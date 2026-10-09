"""Start a private Mihomo with one fixed, loopback-only inbound per candidate node."""

import os
import re
import secrets
import socket
import subprocess
import tempfile
import time
from pathlib import Path
from types import TracebackType
from typing import IO

import yaml

from clashctl.config import read_yaml
from clashctl.controller import ClashClient
from clashctl.models import (
    ConfigurationError,
    JsonObject,
    JsonValue,
    Proxy,
    Settings,
    Snapshot,
    as_int,
    as_list,
    as_object,
    as_string,
    node_names,
)


def definitions(config_path: Path) -> tuple[JsonObject, ...]:
    """Use local provider caches only; never send a subscription URL to another service."""
    source: JsonObject = read_yaml(config_path)
    inline: tuple[JsonObject, ...] = tuple(
        as_object(item, "proxies entry") for item in as_list(source.get("proxies", []), "proxies")
    )
    providers: JsonObject = as_object(source.get("proxy-providers", {}), "proxy-providers")
    cached: tuple[JsonObject, ...] = ()
    for name, value in providers.items():
        provider: JsonObject = as_object(value, f"provider {name}")
        if provider.get("type") == "inline":
            payload: list[JsonValue] = as_list(provider.get("payload"), f"provider {name}.payload")
        else:
            path: Path = Path(as_string(provider.get("path"), f"provider {name}.path"))
            resolved: Path = path if path.is_absolute() else config_path.parent / path
            if not resolved.is_file():
                raise ConfigurationError(
                    f"Provider {name} cache is missing: {resolved}. Update it in Clash first."
                )
            payload = as_list(read_yaml(resolved).get("proxies"), f"provider {name}.proxies")
        cached = (*cached, *(as_object(item, f"provider {name} node") for item in payload))
    by_name: dict[str, JsonObject] = {}
    for item in (*inline, *cached):
        node_name: str = as_string(item.get("name"), "node.name")
        if node_name in by_name and by_name[node_name] != item:
            raise ConfigurationError(f"Conflicting local definitions for node {node_name}")
        by_name[node_name] = item
    return tuple(by_name.values())


def is_subscription_label(definition: JsonObject) -> bool:
    """Recognize metadata disguised as local SOCKS entries, without excluding real local proxies."""
    if definition.get("type") != "socks5":
        return False
    server: str = as_string(definition.get("server"), "SOCKS server")
    if server not in {"127.0.0.1", "::1", "localhost"}:
        return False
    name: str = as_string(definition.get("name"), "SOCKS name").strip()
    return name.casefold().startswith(("website:", "telegram:", "balance:")) or bool(
        re.fullmatch(r"\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(?:\s*\(UTC[+-]\d+\))?", name)
    )


def candidate_names(config_path: Path, proxies: tuple[Proxy, ...], group: str) -> tuple[str, ...]:
    """Validate live/source agreement and exclude disabled proxies and subscription labels."""
    local: dict[str, JsonObject] = {
        as_string(item.get("name"), "node.name"): item for item in definitions(config_path)
    }
    expanded: tuple[str, ...] = node_names(proxies, group)
    missing: tuple[str, ...] = tuple(name for name in expanded if name not in local)
    if missing:
        raise ConfigurationError(
            f"Live nodes missing from runtime source: {missing}. Refresh it first."
        )
    return tuple(
        name
        for name in expanded
        if as_int(local[name].get("port"), f"{name}.port") > 0
        and not is_subscription_label(local[name])
    )


def free_ports(count: int) -> tuple[int, ...]:
    reservations: list[socket.socket] = []
    try:
        for _ in range(count):
            reservation: socket.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            reservations.append(reservation)
            reservation.bind(("127.0.0.1", 0))
        return tuple(int(reservation.getsockname()[1]) for reservation in reservations)
    finally:
        for reservation in reservations:
            reservation.close()


def private_config(
    source: JsonObject,
    local_nodes: tuple[JsonObject, ...],
    snapshot: Snapshot,
    ports: dict[str, int],
    controller_port: int,
    secret: str,
) -> JsonObject:
    """Remove public listeners, TUN, providers, persistent selection, and original routing."""
    dns: JsonObject = as_object(source.get("dns", {}), "dns")
    if dns.get("respect-rules") is True:
        raise ConfigurationError(
            "Isolated testing of DNS respect-rules=true is not supported in this version. "
            "A separate DNS routing configuration is needed; live settings were not changed."
        )
    preserved: JsonObject = {
        key: value
        for key, value in source.items()
        if key in {"ipv6", "hosts", "tcp-concurrent", "global-client-fingerprint", "unified-delay"}
    }
    private_dns: JsonObject = {key: value for key, value in dns.items() if key != "listen"}
    groups: list[JsonValue] = [
        {"name": proxy.name, "type": "select", "proxies": list(proxy.members)}
        for proxy in snapshot.proxies
        if proxy.members and proxy.name != "GLOBAL"
    ]
    listeners: list[JsonValue] = [
        {
            "name": f"clashctl-{index}",
            "type": "mixed",
            "listen": "127.0.0.1",
            "port": port,
            "proxy": name,
        }
        for index, (name, port) in enumerate(ports.items())
    ]
    return {
        **preserved,
        "dns": private_dns,
        "mode": "rule",
        "allow-lan": False,
        "bind-address": "127.0.0.1",
        "mixed-port": 0,
        "port": 0,
        "socks-port": 0,
        "external-controller": f"127.0.0.1:{controller_port}",
        "secret": secret,
        "log-level": "warning",
        "find-process-mode": "off",
        "profile": {"store-selected": False, "store-fake-ip": False},
        "tun": {"enable": False},
        "proxies": list(local_nodes),
        "proxy-groups": groups,
        "listeners": listeners,
        "rules": ["MATCH,REJECT"],
    }


def credential_values(value: JsonValue) -> tuple[str, ...]:
    if isinstance(value, dict):
        return tuple(
            item
            for key, child in value.items()
            for item in (
                (child,)
                if key in {"secret", "password", "uuid", "token", "private-key"}
                and isinstance(child, str)
                and child
                else credential_values(child)
            )
        )
    if isinstance(value, list):
        return tuple(item for child in value for item in credential_values(child))
    return ()


class IsolatedCore:
    """Own temporary files and a child process; never write to the installed Clash directory."""

    def __init__(self, settings: Settings, snapshot: Snapshot, nodes: tuple[str, ...]) -> None:
        self.settings: Settings = settings
        self.snapshot: Snapshot = snapshot
        self.nodes: tuple[str, ...] = nodes
        self.ports: dict[str, int] = {}
        self.client: ClashClient | None = None
        self.process: subprocess.Popen[bytes] | None = None
        self.temp: tempfile.TemporaryDirectory[str] | None = None
        self.log_file: IO[bytes] | None = None
        self.log_path: Path | None = None
        self.redactions: tuple[str, ...] = ()

    def __enter__(self) -> "IsolatedCore":
        if self.settings.core_binary is None:
            raise ConfigurationError("Mihomo binary not found; supply --core /path/to/mihomo")
        if self.snapshot.tun_enabled:
            raise ConfigurationError(
                "TUN is enabled and could intercept the private core's outbound traffic. "
                "Disable TUN before benchmarking. Status and manual switching still work."
            )
        complete: bool = False
        try:
            self.temp = tempfile.TemporaryDirectory(prefix="clashctl-")
            directory: Path = Path(self.temp.name)
            allocated: tuple[int, ...] = free_ports(len(self.nodes) + 1)
            self.ports = dict(zip(self.nodes, allocated[1:], strict=True))
            secret: str = secrets.token_hex(24)
            source: JsonObject = read_yaml(self.settings.config_path)
            config: JsonObject = private_config(
                source,
                definitions(self.settings.config_path),
                self.snapshot,
                self.ports,
                allocated[0],
                secret,
            )
            self.redactions = credential_values(config)
            config_path: Path = directory / "config.yaml"
            descriptor: int = os.open(config_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(descriptor, "w", encoding="utf-8") as output:
                yaml.safe_dump(config, output, allow_unicode=True, sort_keys=False)
            # Existing GeoData is read only; avoid downloading fresh data during DNS setup.
            for filename in ("country.mmdb", "geoip.dat", "geosite.dat"):
                cached: Path = self.settings.config_path.parent / filename
                if cached.is_file():
                    (directory / filename).symlink_to(cached)
            self.log_path = directory / "core.log"
            self.log_file = self.log_path.open("wb")
            self.process = subprocess.Popen(
                [str(self.settings.core_binary), "-d", str(directory), "-f", str(config_path)],
                stdout=self.log_file,
                stderr=subprocess.STDOUT,
                start_new_session=True,
            )
            deadline: float = time.monotonic() + 15.0
            while time.monotonic() < deadline:
                if self.process.poll() is not None:
                    raise ConfigurationError(self.startup_error())
                try:
                    with socket.create_connection(("127.0.0.1", allocated[0]), timeout=0.2):
                        break
                except (ConnectionRefusedError, TimeoutError):
                    time.sleep(0.05)
            else:
                raise ConfigurationError(f"Private Mihomo did not start: {self.startup_error()}")
            private_settings: Settings = Settings(
                config_path,
                f"http://127.0.0.1:{allocated[0]}",
                secret,
                self.settings.core_binary,
                3.0,
            )
            self.client = ClashClient(private_settings)
            actual: tuple[str, ...] = tuple(proxy.name for proxy in self.client.proxies())
            if any(name not in actual for name in self.nodes):
                raise ConfigurationError("Private core does not contain all requested nodes")
            for proxy in self.snapshot.proxies:
                if proxy.members and proxy.name != "GLOBAL" and proxy.selected in proxy.members:
                    self.client.select(proxy.name, str(proxy.selected))
            complete = True
            return self
        finally:
            if not complete:
                self.close()

    def startup_error(self) -> str:
        details: str = "No diagnostic output"
        if self.log_path is not None and self.log_path.is_file():
            details = self.log_path.read_text(encoding="utf-8", errors="replace")[-3000:]
            for secret in self.redactions:
                details = details.replace(secret, "[REDACTED]")
        code: int | None = None if self.process is None else self.process.poll()
        return f"Private Mihomo startup failed (exit={code}): {details}"

    def proxy_url(self, node: str) -> str:
        return f"http://127.0.0.1:{self.ports[node]}"

    def close(self) -> None:
        if self.process is not None and self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=5.0)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=5.0)
        if self.log_file is not None:
            self.log_file.close()
        if self.temp is not None:
            self.temp.cleanup()

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        self.close()
