"""Immutable live routing, connection, and rule-refresh records."""

from dataclasses import dataclass
from pathlib import Path

from clashctl.models import ConfigurationError, JsonValue, as_int, as_list, as_object, as_string
from clashctl.probes import ProbeResult


@dataclass(frozen=True)
class RuntimeRule:
    position: int
    kind: str
    payload: str
    target: str


@dataclass(frozen=True)
class Connection:
    identifier: str
    host: str
    port: str
    process: str
    network: str
    rule: str
    rule_payload: str
    chains: tuple[str, ...]
    downloaded: int
    uploaded: int


@dataclass(frozen=True)
class RuleAudit:
    host: str
    verdict: str
    direct: tuple[ProbeResult, ...]
    proxy: tuple[ProbeResult, ...]
    checked_at: str


@dataclass(frozen=True)
class RulePlan:
    created_at: str
    tested_group: str
    tested_node: str
    profile_uid: str
    extension_path: Path
    extension_text: str
    source_digest: str
    original_rules: tuple[str, ...]
    rules: tuple[str, ...]
    prepend: tuple[str, ...]
    managed_prepend: tuple[str, ...]
    delete: tuple[str, ...]
    audits: tuple[RuleAudit, ...]


@dataclass(frozen=True)
class RoutingState:
    rules: tuple[RuntimeRule, ...]
    connections: tuple[Connection, ...]
    observed: tuple[str, ...]
    checked_at: str | None
    error: str | None
    plan: RulePlan | None


def empty_routing() -> RoutingState:
    return RoutingState((), (), (), None, None, None)


def parse_rule(value: JsonValue, position: int) -> RuntimeRule:
    item = as_object(value, "rule")
    return RuntimeRule(
        position,
        as_string(item.get("type"), "rule.type"),
        as_string(item.get("payload"), "rule.payload"),
        as_string(item.get("proxy"), "rule.proxy"),
    )


def parse_connection(value: JsonValue) -> Connection:
    item = as_object(value, "connection")
    metadata = as_object(item.get("metadata"), "connection.metadata")
    host: str = as_string(metadata.get("host", ""), "metadata.host")
    sniff: str = as_string(metadata.get("sniffHost", ""), "metadata.sniffHost")
    destination: str = as_string(metadata.get("destinationIP", ""), "metadata.destinationIP")
    port: JsonValue = metadata.get("destinationPort", "")
    if not isinstance(port, (str, int)) or isinstance(port, bool):
        raise ConfigurationError(f"Invalid destination port: {port!r}")
    return Connection(
        as_string(item.get("id"), "connection.id"),
        host or sniff or destination,
        str(port),
        as_string(metadata.get("process", ""), "metadata.process"),
        as_string(metadata.get("network", ""), "metadata.network"),
        as_string(item.get("rule", ""), "connection.rule"),
        as_string(item.get("rulePayload", ""), "connection.rulePayload"),
        tuple(as_string(v, "chain") for v in as_list(item.get("chains", []), "chains")),
        as_int(item.get("download", 0), "connection.download"),
        as_int(item.get("upload", 0), "connection.upload"),
    )
