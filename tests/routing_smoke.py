"""Exercise real HTTPS checks and rule apply/undo against a private Mihomo instance.

Run: uv run python tests/routing_smoke.py --node 'NODE NAME'
No installed Clash files, mode, or selections are changed.
"""

import argparse
import socket
import ssl
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path

import yaml
from menu_smoke import Terminal, command

from clashctl.benchmark import never_cancel
from clashctl.config import load_settings, read_yaml, source_digest
from clashctl.controller import ClashClient
from clashctl.isolation import IsolatedCore, free_ports
from clashctl.models import Settings, Snapshot, StateConflictError, choose_group
from clashctl.persistence import write_text_file
from clashctl.routing import (
    apply_rules,
    check_hosts,
    commit_rule_files,
    plan_rules,
    strings,
    undo_rules,
    verify_rules,
)
from clashctl.routing_models import RuleAudit, RulePlan


def verify_live_route(settings: Settings, port: int) -> None:
    with socket.create_connection(("127.0.0.1", port), timeout=10) as connection:
        connection.sendall(b"CONNECT www.baidu.com:443 HTTP/1.1\r\nHost: www.baidu.com:443\r\n\r\n")
        response: bytes = connection.recv(4096)
        if b"200" not in response.split(b"\r\n")[0]:
            raise AssertionError(f"HTTPS proxy tunnel failed: {response[:200]!r}")
        with ssl.create_default_context().wrap_socket(connection, server_hostname="www.baidu.com"):
            matches = tuple(
                c for c in ClashClient(settings).connections() if c.host == "www.baidu.com"
            )
            if not matches or any(c.chains[0] != "DIRECT" for c in matches):
                raise AssertionError(f"China website did not route DIRECT: {matches}")
            if not all(c.rule in {"GeoSite", "DomainSuffix", "Domain", "GeoIP"} for c in matches):
                raise AssertionError(f"China website matched an unexpected rule: {matches}")


def verify_terminal(settings: Settings, node: str, root: Path, port: int) -> None:
    with socket.create_connection(("127.0.0.1", port), timeout=10) as connection:
        connection.sendall(b"CONNECT www.baidu.com:443 HTTP/1.1\r\nHost: www.baidu.com:443\r\n\r\n")
        if b"200" not in connection.recv(4096).split(b"\r\n")[0]:
            raise AssertionError("Private HTTPS tunnel failed")
        with (
            ssl.create_default_context().wrap_socket(connection, server_hostname="www.baidu.com"),
            Terminal(command(settings, node, root, 2), root) as terminal,
        ):
            terminal.expect("Your local Clash workspace")
            terminal.command("/watch pause", "Pausing downloads")
            terminal.expect("WATCH PAUSED")
            terminal.command("/sites", "Live Clash connections")
            terminal.expect("www.baidu.com")
            terminal.expect("GeoSite:cn")
            terminal.command("/rules cn", "Ordered routing rules")
            terminal.expect("GeoSite")
            terminal.command("/rules check www.baidu.com", "Rule refresh preview")
            terminal.expect("DIRECT")
            terminal.command("/rank", "OpenAI API")
            terminal.quit()
    print("Terminal rules, check preview, live websites, OpenAI column, clean exit: passed")


def verify_rules_workflow(settings: Settings, snapshot: Snapshot, node: str) -> None:
    group: str = choose_group(snapshot, None)
    with IsolatedCore(settings, snapshot, (node,)) as core:
        if core.client is None:
            raise AssertionError("Private controller did not initialize")
        private: Settings = core.client.settings
        root: Path = private.config_path.parent
        extension: Path = root / "profiles" / "rules.yaml"
        user_rule: str = "DOMAIN,manual-existing.example.com,DIRECT"
        extension_text: str = yaml.safe_dump({"prepend": [user_rule], "append": [], "delete": []})
        write_text_file(extension_text, extension)
        write_text_file(
            yaml.safe_dump(
                {
                    "current": "test-profile",
                    "items": [
                        {"uid": "test-profile", "type": "local", "option": {"rules": "test-rules"}},
                        {"uid": "test-rules", "type": "rules", "file": "rules.yaml"},
                    ],
                }
            ),
            root / "profiles.yaml",
        )
        source = read_yaml(private.config_path)
        port: int = free_ports(1)[0]
        initial_rules: tuple[str, ...] = (
            user_rule,
            *strings(read_yaml(settings.config_path), "rules"),
        )
        initial: str = yaml.safe_dump(
            {**source, "mixed-port": port, "rules": list(initial_rules)},
            allow_unicode=True,
            sort_keys=False,
        )
        write_text_file(initial, private.config_path)
        core.client.reload(initial)
        before: Snapshot = core.client.snapshot()
        directory: Path = root / "reports"
        audits: tuple[RuleAudit, ...] = check_hosts(
            private,
            before,
            group,
            ("www.baidu.com", "www.google.com", "api.openai.com"),
            never_cancel,
        )
        print("HTTPS evidence:", [(a.host, a.verdict) for a in audits])
        plan: RulePlan = plan_rules(
            private, before, source_digest(private.config_path), group, audits, directory
        )
        write_text_file(extension_text + "\n# External edit\n", extension)
        try:
            apply_rules(private, plan, directory, never_cancel)
        except StateConflictError:
            print("Profile drift: rejected")
        else:
            raise AssertionError("An externally edited extension was overwritten")
        write_text_file(extension_text, extension)
        expired: RulePlan = replace(
            plan, created_at=(datetime.now(UTC) - timedelta(minutes=11)).isoformat()
        )
        try:
            apply_rules(private, expired, directory, never_cancel)
        except StateConflictError:
            print("Expired preview: rejected")
        else:
            raise AssertionError("An expired rule preview was applied")
        apply_rules(private, plan, directory, never_cancel)
        verify_rules(core.client, plan.rules)
        if core.client.snapshot().proxies != before.proxies:
            raise AssertionError("Rule refresh changed selections")
        verify_live_route(private, port)
        verify_terminal(private, node, root, port)
        applied: str = extension.read_text()
        refreshed: RulePlan = plan_rules(
            private,
            core.client.snapshot(),
            source_digest(private.config_path),
            group,
            audits,
            directory,
        )
        if refreshed.rules != plan.rules or user_rule not in refreshed.prepend:
            raise AssertionError("A repeated refresh duplicated rules or removed a user override")
        try:
            commit_rule_files(
                private,
                core.client.snapshot(),
                ((extension, applied + "\n# Rollback check\n"),),
                ("MATCH,REJECT",),
            )
        except StateConflictError:
            verify_rules(core.client, plan.rules)
            if extension.read_text() != applied:
                raise AssertionError(
                    "Failed rule commit did not restore extension contents"
                ) from None
            print("Failed verification: files and live rules rolled back")
        else:
            raise AssertionError("A failed rule verification was accepted")
        undo_rules(private, directory)
        verify_rules(core.client, initial_rules)
        if extension.read_text() != extension_text:
            raise AssertionError("Undo did not restore the original user extension")
        if core.client.snapshot().proxies != before.proxies:
            raise AssertionError("Undo changed selections")
        print("Apply, real China routing, repeat refresh, undo, selection preservation: passed")


def main() -> None:
    parser: argparse.ArgumentParser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--node", required=True)
    arguments: argparse.Namespace = parser.parse_args()
    settings: Settings = load_settings(None, None, None, None, 5.0)
    before: Snapshot = ClashClient(settings).snapshot()
    verify_rules_workflow(settings, before, str(arguments.node))
    if ClashClient(settings).snapshot() != before:
        raise AssertionError("Routing tests changed installed Clash state")
    print("PASS: routing workflow, rollback, drift guards, installed Clash unchanged")


if __name__ == "__main__":
    main()
