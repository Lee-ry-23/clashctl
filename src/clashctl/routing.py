"""Evidence-based domain checks and reversible Clash Verge rule-extension transactions."""

import fcntl
import hashlib
import json
import re
import subprocess
import sys
import tempfile
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import urlsplit

import yaml

from clashctl.config import read_yaml, source_digest
from clashctl.controller import ClashClient
from clashctl.isolation import IsolatedCore, credential_values
from clashctl.models import (
    BenchmarkCancelled,
    ClashError,
    ConfigurationError,
    JsonObject,
    Settings,
    Snapshot,
    StateConflictError,
    as_list,
    as_object,
    as_string,
    json_value,
    proxy_by_name,
)
from clashctl.persistence import write_json_file, write_text_file
from clashctl.probes import OPENAI_URL, HttpsProbe, ProbeResult, probe_outcome
from clashctl.routing_models import Connection, RuleAudit, RulePlan, RuntimeRule


def strings(document: JsonObject, key: str) -> tuple[str, ...]:
    return tuple(as_string(v, key) for v in as_list(document.get(key, []), key))


def normalize_host(value: str) -> str:
    host: str = value.strip().lower().rstrip(".")
    if "://" in host:
        try:
            parsed = urlsplit(host)
            port: int | None = parsed.port
        except ValueError as error:
            raise ConfigurationError(f"Invalid website URL: {value!r}: {error}") from error
        if parsed.scheme != "https" or parsed.username or parsed.password or port is not None:
            raise ConfigurationError(
                "Rule checks require a public HTTPS hostname without credentials"
            )
        host = parsed.hostname or ""
    try:
        host = host.encode("idna").decode("ascii")
    except UnicodeError as error:
        raise ConfigurationError(f"Invalid hostname: {value!r}") from error
    if (
        len(host) > 253
        or not re.fullmatch(r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}", host)
        or host.endswith((".local", ".localhost", ".internal", ".invalid", ".test", ".example"))
    ):
        raise ConfigurationError(f"Not a public website hostname: {value!r}")
    return host


def observed_hosts(connections: tuple[Connection, ...]) -> tuple[str, ...]:
    hosts: tuple[str, ...] = ()
    for connection in connections:
        if connection.port not in {"80", "443"}:
            continue
        try:
            host: str = normalize_host(connection.host)
        except ConfigurationError:
            # IP-only, local, and non-web connections remain visible but are not probed.
            continue
        hosts = (*hosts, host)
    return tuple(dict.fromkeys(hosts))


def check_host(host: str, direct: HttpsProbe, proxy: HttpsProbe) -> RuleAudit:
    url: str = OPENAI_URL if host == "api.openai.com" else f"https://{host}/"
    direct_results: tuple[ProbeResult, ...] = tuple(probe_outcome(direct, url, 1) for _ in range(2))
    proxy_results: tuple[ProbeResult, ...] = ()
    verdict: str = "unconfirmed"
    if all(result.reachable for result in direct_results):
        verdict = "DIRECT"
    else:
        proxy_results = tuple(probe_outcome(proxy, url, 1) for _ in range(2))
        if all(
            result.http_status is None or result.http_status in {403, 451}
            for result in direct_results
        ) and all(result.reachable for result in proxy_results):
            verdict = "VPN"
    return RuleAudit(host, verdict, direct_results, proxy_results, datetime.now(UTC).isoformat())


def check_hosts(
    settings: Settings,
    snapshot: Snapshot,
    group: str,
    hosts: tuple[str, ...],
    cancelled: Callable[[], bool],
) -> tuple[RuleAudit, ...]:
    """Compare two independent TLS-verified requests per route on the current network."""
    if not hosts:
        raise ConfigurationError("No observed websites. Use /rules check example.com other.site")
    if len(hosts) > 100:
        raise ConfigurationError("Check at most 100 websites per refresh; split a larger list")
    target: str = selected_node(snapshot, group)
    with IsolatedCore(settings, snapshot, ("DIRECT", target)) as core:
        direct: HttpsProbe = HttpsProbe(core.proxy_url("DIRECT"), 3.0, cancelled)
        proxy: HttpsProbe = HttpsProbe(core.proxy_url(target), 3.0, cancelled)
        with ThreadPoolExecutor(max_workers=4, thread_name_prefix="clashctl-rules") as executor:
            return tuple(executor.map(lambda host: check_host(host, direct, proxy), hosts))


def selected_node(snapshot: Snapshot, group: str) -> str:
    target: str = group
    visited: tuple[str, ...] = ()
    while proxy_by_name(snapshot.proxies, target).members:
        if target in visited:
            raise ConfigurationError(f"Proxy group cycle: {(*visited, target)}")
        visited = (*visited, target)
        selected: str | None = proxy_by_name(snapshot.proxies, target).selected
        if selected is None or selected == target:
            raise ConfigurationError(f"No selected proxy in group {target}")
        target = selected
    if target in {"DIRECT", "REJECT"}:
        raise ConfigurationError(f"Working group {group} selects {target}; choose a VPN node first")
    return target


def active_extension(settings: Settings) -> tuple[str, Path]:
    profiles: JsonObject = read_yaml(settings.config_path.parent / "profiles.yaml")
    uid: str = as_string(profiles.get("current"), "profiles.current")
    items: tuple[JsonObject, ...] = tuple(
        as_object(v, "profile") for v in as_list(profiles.get("items"), "profiles.items")
    )
    active: JsonObject | None = next((v for v in items if v.get("uid") == uid), None)
    if active is None:
        raise ConfigurationError(f"Active Clash Verge profile {uid} is missing")
    rules_uid: str = as_string(
        as_object(active.get("option"), "profile.option").get("rules"), "rules uid"
    )
    extension: JsonObject | None = next((v for v in items if v.get("uid") == rules_uid), None)
    if extension is None or extension.get("type") != "rules":
        raise ConfigurationError(f"Clash Verge rules extension {rules_uid} is missing")
    root: Path = (settings.config_path.parent / "profiles").resolve()
    path: Path = (root / as_string(extension.get("file"), "rules.file")).resolve()
    if path.parent != root or not path.is_file():
        raise ConfigurationError(f"Invalid rules-extension path: {path}")
    return uid, path


def rule_key(raw: str) -> tuple[str, str, str]:
    parts: list[str] = raw.split(",")
    if parts[-1].lower() == "no-resolve":
        parts = parts[:-1]
    if len(parts) < 2:
        raise ConfigurationError(f"Invalid rule: {raw}")
    kind: str = parts[0].replace("-", "").upper()
    return "IPCIDR" if kind == "IPCIDR6" else kind, ",".join(parts[1:-1]).lower(), parts[-1]


def live_rule_key(rule: RuntimeRule) -> tuple[str, str, str]:
    return rule.kind.replace("-", "").upper(), rule.payload.lower(), rule.target


def verify_rules(client: ClashClient, expected: tuple[str, ...]) -> None:
    actual: tuple[tuple[str, str, str], ...] = tuple(live_rule_key(rule) for rule in client.rules())
    planned: tuple[tuple[str, str, str], ...] = tuple(rule_key(raw) for raw in expected)
    if actual != planned:
        difference: int = next(
            (
                index
                for index, pair in enumerate(zip(actual, planned, strict=False))
                if pair[0] != pair[1]
            ),
            min(len(actual), len(planned)),
        )
        raise StateConflictError(
            f"Live rules differ at #{difference + 1}: "
            f"expected={planned[difference : difference + 1]}, "
            f"actual={actual[difference : difference + 1]}; "
            f"counts={len(planned)}/{len(actual)}. Refresh /rules."
        )


def managed_document(path: Path) -> JsonObject:
    if not path.exists():
        return {}
    try:
        return as_object(json_value(json.loads(path.read_text()), "managed rules"), "managed rules")
    except json.JSONDecodeError as error:
        raise ConfigurationError(f"Invalid managed-rule metadata: {path}: {error}") from error


def plan_rules(
    settings: Settings,
    snapshot: Snapshot,
    digest: str,
    group: str,
    audits: tuple[RuleAudit, ...],
    directory: Path,
) -> RulePlan:
    """Prioritize China and verified domains while preserving unconfirmed subscription routes."""
    uid, extension_path = active_extension(settings)
    extension: JsonObject = read_yaml(extension_path)
    source: JsonObject = read_yaml(settings.config_path)
    original: tuple[str, ...] = strings(source, "rules")
    if source_digest(settings.config_path) != digest:
        raise StateConflictError("Configuration changed during domain checks; repeat /rules check")
    if selected_node(ClashClient(settings).snapshot(), group) != selected_node(snapshot, group):
        raise StateConflictError("Selected VPN changed during domain checks; repeat /rules check")
    verify_rules(ClashClient(settings), original)
    managed: JsonObject = managed_document(directory / "rules-managed.json")
    owned: tuple[str, ...] = (
        strings(managed, "prepend") if managed.get("extension_path") == str(extension_path) else ()
    )
    previous_audits: tuple[str, ...] = tuple(
        raw
        for raw in owned
        if raw.startswith("DOMAIN,")
        and raw.split(",")[1] not in {a.host for a in audits if a.verdict in {"DIRECT", "VPN"}}
    )
    rejected: tuple[str, ...] = tuple(
        raw for raw in original if rule_key(raw)[2].startswith("REJECT")
    )
    decisions: tuple[str, ...] = tuple(
        f"DOMAIN,{audit.host},{'DIRECT' if audit.verdict == 'DIRECT' else group}"
        for audit in audits
        if audit.verdict in {"DIRECT", "VPN"}
    )
    policy: tuple[str, ...] = tuple(
        dict.fromkeys(
            (
                *rejected,
                "IP-CIDR,127.0.0.0/8,DIRECT,no-resolve",
                "IP-CIDR,10.0.0.0/8,DIRECT,no-resolve",
                "IP-CIDR,172.16.0.0/12,DIRECT,no-resolve",
                "IP-CIDR,192.168.0.0/16,DIRECT,no-resolve",
                "IP-CIDR6,::1/128,DIRECT,no-resolve",
                "IP-CIDR6,fc00::/7,DIRECT,no-resolve",
                "IP-CIDR6,fe80::/10,DIRECT,no-resolve",
                "GEOSITE,cn,DIRECT",
                "DOMAIN-SUFFIX,cn,DIRECT",
                *decisions,
                *previous_audits,
                "GEOIP,CN,DIRECT",
            )
        )
    )
    removed: tuple[str, ...] = tuple(raw for raw in original if rule_key(raw)[0] == "MATCH")
    if len(removed) != 1:
        raise ConfigurationError("A rule refresh requires exactly one existing MATCH rule")
    prepend: tuple[str, ...] = tuple(
        dict.fromkeys(
            (*policy, *(raw for raw in strings(extension, "prepend") if raw not in owned))
        )
    )
    old_prepend: tuple[str, ...] = strings(extension, "prepend")
    old_append: tuple[str, ...] = strings(extension, "append")
    if any(rule_key(raw)[0] == "MATCH" for raw in old_prepend):
        raise ConfigurationError("Remove the catch-all from the profile's prepend rules first")
    if original[: len(old_prepend)] != old_prepend or (
        old_append and original[-len(old_append) :] != old_append
    ):
        raise StateConflictError(
            "Runtime and profile extension differ; reselect the profile in Clash Verge"
        )
    base: tuple[str, ...] = original[len(old_prepend) : len(original) - len(old_append)]
    deleted: tuple[str, ...] = tuple(
        dict.fromkeys(
            (*strings(extension, "delete"), *removed, *(raw for raw in policy if raw in base))
        )
    )
    appended: tuple[str, ...] = (
        *(raw for raw in old_append if rule_key(raw)[0] != "MATCH"),
        removed[0],
    )
    rules: tuple[str, ...] = (*prepend, *(raw for raw in base if raw not in deleted), *appended)
    plan: RulePlan = RulePlan(
        datetime.now(UTC).isoformat(),
        group,
        selected_node(snapshot, group),
        uid,
        extension_path,
        extension_path.read_text(),
        source_digest(settings.config_path),
        original,
        rules,
        prepend,
        policy,
        deleted,
        audits,
    )
    document: JsonObject = as_object(
        json_value(asdict(plan) | {"extension_path": str(extension_path)}, "plan"), "plan"
    )
    write_json_file(document, directory / "rules-plan.json")
    return plan


def validate_config(settings: Settings, source: JsonObject) -> str:
    """Use Mihomo's own parser before any live rule or extension write."""
    if settings.core_binary is None:
        raise ConfigurationError("Mihomo binary is required to validate rules")
    content: str = yaml.safe_dump(source, allow_unicode=True, sort_keys=False)
    with tempfile.TemporaryDirectory(prefix="clashctl-rule-check-") as temporary:
        root: Path = Path(temporary)
        for filename in ("Country.mmdb", "geoip.dat", "geosite.dat"):
            cached: Path = settings.config_path.parent / filename
            if cached.is_file():
                (root / filename).symlink_to(cached)
        path: Path = root / "config.yaml"
        write_text_file(content, path)
        result: subprocess.CompletedProcess[str] = subprocess.run(
            [str(settings.core_binary), "-t", "-d", str(root), "-f", str(path)],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        if result.returncode != 0:
            detail: str = (result.stdout + result.stderr)[-2000:]
            for secret in credential_values(source):
                detail = detail.replace(secret, "[REDACTED]")
            raise ConfigurationError(f"Mihomo rule validation failed: {detail}")
    return content


def reload_preserving(settings: Settings, content: str, snapshot: Snapshot) -> None:
    client: ClashClient = ClashClient(settings)
    client.reload(content)
    fresh: Snapshot = client.snapshot()
    if (fresh.mode, fresh.tun_enabled, fresh.mixed_port) != (
        snapshot.mode,
        snapshot.tun_enabled,
        snapshot.mixed_port,
    ):
        raise StateConflictError("Rule reload unexpectedly changed mode, TUN, or proxy port")
    for proxy in snapshot.proxies:
        if not proxy.members:
            continue
        actual = proxy_by_name(fresh.proxies, proxy.name)
        if (
            proxy.kind == "Selector"
            and proxy.selected is not None
            and actual.selected != proxy.selected
        ):
            client.select(proxy.name, proxy.selected)
        elif proxy.fixed and actual.fixed != proxy.fixed:
            client.select(proxy.name, proxy.fixed)


def selection_stamp(snapshot: Snapshot) -> tuple[tuple[str, str | None], ...]:
    return tuple(
        (proxy.name, proxy.selected if proxy.kind == "Selector" else proxy.fixed)
        for proxy in snapshot.proxies
        if proxy.members
    )


def commit_rule_files(
    settings: Settings,
    snapshot: Snapshot,
    replacements: tuple[tuple[Path, str], ...],
    expected: tuple[str, ...],
) -> None:
    """Roll back file contents, metadata, and live rules together on any failed commit."""
    originals: tuple[tuple[Path, str | None], ...] = tuple(
        (path, path.read_text() if path.exists() else None) for path, _ in replacements
    )
    original_runtime: str = settings.config_path.read_text()
    original_rules: tuple[str, ...] = strings(read_yaml(settings.config_path), "rules")
    committed: bool = False
    try:
        for path, content in replacements:
            write_text_file(content, path)
        reload_preserving(settings, settings.config_path.read_text(), snapshot)
        verify_rules(ClashClient(settings), expected)
        committed = True
    finally:
        if not committed:
            failure: BaseException | None = sys.exception()
            try:
                for path, original in originals:
                    if original is None:
                        path.unlink(missing_ok=True)
                    else:
                        write_text_file(original, path)
                reload_preserving(settings, original_runtime, snapshot)
                verify_rules(ClashClient(settings), original_rules)
            except (OSError, ClashError) as error:
                raise StateConflictError(
                    f"Rule transaction failed: {failure}; rollback failed: {error}"
                ) from error


def apply_rules(
    settings: Settings, plan: RulePlan, directory: Path, cancelled: Callable[[], bool]
) -> Path:
    """Persist the active profile extension and runtime together, with automatic rollback."""
    directory.mkdir(parents=True, exist_ok=True)
    with (directory / "rules.lock").open("a+") as lock:
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        uid, extension_path = active_extension(settings)
        if uid != plan.profile_uid or extension_path != plan.extension_path:
            raise StateConflictError("Active Clash Verge profile changed; repeat /rules check")
        if (
            source_digest(settings.config_path) != plan.source_digest
            or extension_path.read_text() != plan.extension_text
        ):
            raise StateConflictError("Rules or subscription changed; repeat /rules check")
        snapshot: Snapshot = ClashClient(settings).snapshot()
        if (datetime.now(UTC) - datetime.fromisoformat(plan.created_at)).total_seconds() > 600:
            raise StateConflictError("Rule preview is over 10 minutes old; repeat /rules check")
        if selected_node(snapshot, plan.tested_group) != plan.tested_node:
            raise StateConflictError("Selected VPN changed since checking; repeat /rules check")
        if snapshot.mode != "rule":
            raise ConfigurationError("Use /mode rule before applying routing rules")
        verify_rules(ClashClient(settings), plan.original_rules)
        source: JsonObject = read_yaml(settings.config_path)
        content: str = validate_config(
            settings, {**source, "rules": list(plan.rules), "mode": snapshot.mode}
        )
        extension: JsonObject = read_yaml(extension_path)
        extension_content: str = yaml.safe_dump(
            {
                **extension,
                "prepend": list(plan.prepend),
                "delete": list(plan.delete),
                "append": [
                    *(raw for raw in strings(extension, "append") if rule_key(raw)[0] != "MATCH"),
                    plan.rules[-1],
                ],
            },
            allow_unicode=True,
            sort_keys=False,
        )
        backup: Path = directory / "rule-backups" / datetime.now(UTC).strftime("%Y%m%dT%H%M%S%fZ")
        originals: tuple[tuple[Path, str], ...] = (
            (settings.config_path, settings.config_path.read_text()),
            (extension_path, plan.extension_text),
        )
        for index, (_, text) in enumerate(originals):
            write_text_file(text, backup / f"{index}.yaml")
        manifest: JsonObject = {
            "profile_uid": uid,
            "paths": [str(path) for path, _ in originals],
            "expected": [
                hashlib.sha256(content.encode()).hexdigest(),
                hashlib.sha256(extension_content.encode()).hexdigest(),
            ],
            "previous_managed": managed_document(directory / "rules-managed.json"),
        }
        write_json_file(manifest, backup / "manifest.json")
        if cancelled():
            raise BenchmarkCancelled("Rule refresh cancelled before applying")
        if (
            source_digest(settings.config_path) != plan.source_digest
            or extension_path.read_text() != plan.extension_text
            or active_extension(settings) != (uid, extension_path)
        ):
            raise StateConflictError("Configuration changed during validation; repeat /rules check")
        latest: Snapshot = ClashClient(settings).snapshot()
        if (latest.mode, latest.tun_enabled, latest.mixed_port, selection_stamp(latest)) != (
            snapshot.mode,
            snapshot.tun_enabled,
            snapshot.mixed_port,
            selection_stamp(snapshot),
        ):
            raise StateConflictError(
                "Live mode or selections changed during validation; repeat /rules check"
            )
        commit_rule_files(
            settings,
            snapshot,
            (
                (extension_path, extension_content),
                (settings.config_path, content),
                (
                    directory / "rules-managed.json",
                    json.dumps(
                        {
                            "extension_path": str(extension_path),
                            "prepend": list(plan.managed_prepend),
                        },
                        ensure_ascii=False,
                    ),
                ),
                (directory / "rules-last.json", json.dumps({"backup": str(backup)})),
            ),
            plan.rules,
        )
        return backup


def undo_rules(settings: Settings, directory: Path) -> Path:
    with (directory / "rules.lock").open("a+") as lock:
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        return restore_last_rules(settings, directory)


def restore_last_rules(settings: Settings, directory: Path) -> Path:
    """Restore the last verified transaction, rejecting intervening external edits."""
    pointer: JsonObject = managed_document(directory / "rules-last.json")
    if not pointer.get("backup"):
        raise ConfigurationError("No applied rule refresh to undo")
    backup: Path = Path(as_string(pointer.get("backup"), "last rule backup"))
    if backup.parent != directory / "rule-backups":
        raise ConfigurationError(f"Invalid rule-backup location: {backup}")
    manifest: JsonObject = managed_document(backup / "manifest.json")
    uid, extension = active_extension(settings)
    paths: tuple[Path, ...] = tuple(Path(raw) for raw in strings(manifest, "paths"))
    if uid != manifest.get("profile_uid") or paths != (settings.config_path, extension):
        raise StateConflictError(
            "Active profile changed; refusing to restore another profile's rules"
        )
    if tuple(hashlib.sha256(path.read_bytes()).hexdigest() for path in paths) != strings(
        manifest, "expected"
    ):
        raise StateConflictError(
            "Configuration changed since applying rules; automatic undo refused"
        )
    before: Snapshot = ClashClient(settings).snapshot()
    restored: tuple[str, ...] = tuple((backup / f"{index}.yaml").read_text() for index in range(2))
    original_source: JsonObject = read_yaml(backup / "0.yaml")
    restored_runtime: str = (
        restored[0]
        if original_source.get("mode") == before.mode
        else yaml.safe_dump(
            {**original_source, "mode": before.mode}, allow_unicode=True, sort_keys=False
        )
    )
    commit_rule_files(
        settings,
        before,
        (
            (paths[0], restored_runtime),
            (paths[1], restored[1]),
            (
                directory / "rules-managed.json",
                json.dumps(manifest.get("previous_managed"), ensure_ascii=False),
            ),
            (directory / "rules-last.json", "{}"),
        ),
        strings(original_source, "rules"),
    )
    return backup
