"""Immutable records and strict parsers for local configuration and API responses."""

from dataclasses import dataclass, field
from pathlib import Path

type JsonValue = str | int | float | bool | None | list[JsonValue] | dict[str, JsonValue]
type JsonObject = dict[str, JsonValue]


class ClashError(Exception):
    """An actionable configuration, controller, or benchmark error."""


class ConfigurationError(ClashError):
    """Configuration is missing, ambiguous, or incompatible."""


class ControllerError(ClashError):
    """A controller request failed after its bounded retries."""


class MeasurementError(ClashError):
    """A node could not complete a valid download measurement."""


class BenchmarkCancelled(ClashError):
    """An explicit stop or pause interrupted a private download benchmark."""


class CacheError(ClashError):
    """A persisted measurement cache is invalid or unavailable."""


class StateConflictError(ClashError):
    """Live state changed during a benchmark or selection transaction."""


@dataclass(frozen=True)
class Settings:
    config_path: Path
    controller: str
    secret: str = field(repr=False)
    core_binary: Path | None
    timeout: float


@dataclass(frozen=True)
class Proxy:
    name: str
    kind: str
    members: tuple[str, ...]
    selected: str | None
    fixed: str | None


@dataclass(frozen=True)
class Snapshot:
    mode: str
    version: str
    mixed_port: int
    tun_enabled: bool
    proxies: tuple[Proxy, ...]
    rule_targets: tuple[str, ...]
    rule_count: int


@dataclass(frozen=True)
class BenchmarkOptions:
    group: str
    nodes: tuple[str, ...]
    rounds: int
    size_bytes: int
    url: str
    timeout: float
    attempts: int
    report_path: Path


@dataclass(frozen=True)
class Sample:
    node: str
    round_number: int
    attempts: int
    bytes_received: int
    elapsed_seconds: float
    first_byte_ms: float | None
    mbps: float
    error: str | None


@dataclass(frozen=True)
class OpenAIResult:
    checked_at: str
    status: str
    response_ms: float | None
    http_status: int | None
    error: str | None


@dataclass(frozen=True)
class NodeResult:
    node: str
    successful_rounds: int
    total_rounds: int
    median_mbps: float
    conservative_mbps: float
    variation_percent: float
    median_first_byte_ms: float | None
    score: float
    eligible: bool
    samples: tuple[Sample, ...]
    openai: OpenAIResult | None


@dataclass(frozen=True)
class GroupSelection:
    name: str
    selected: str | None
    fixed: str | None


@dataclass(frozen=True)
class BenchmarkReport:
    started_at: str
    completed_at: str | None
    complete: bool
    source_digest: str
    group: str
    initial_selection: str | None
    initial_groups: tuple[GroupSelection, ...]
    live_mode: str
    url: str
    size_bytes: int
    rounds: int
    requested_nodes: tuple[str, ...]
    results: tuple[NodeResult, ...]
    winner: str | None


def json_value(value: object, context: str) -> JsonValue:
    """Validate unknown decoded input instead of propagating untyped dictionaries."""
    if value is None or isinstance(value, (str, bool, int, float)):
        return value
    if isinstance(value, (list, tuple)):
        return [json_value(item, context) for item in value]
    if isinstance(value, dict):
        if not all(isinstance(key, str) for key in value):
            raise ConfigurationError(f"{context}: object keys must be strings")
        return {str(key): json_value(item, context) for key, item in value.items()}
    raise ConfigurationError(f"{context}: unsupported value type {type(value).__name__}")


def as_object(value: JsonValue, context: str) -> JsonObject:
    if not isinstance(value, dict):
        raise ConfigurationError(f"{context}: expected an object")
    return value


def as_list(value: JsonValue, context: str) -> list[JsonValue]:
    if not isinstance(value, list):
        raise ConfigurationError(f"{context}: expected an array")
    return value


def as_string(value: JsonValue, context: str) -> str:
    if not isinstance(value, str):
        raise ConfigurationError(f"{context}: expected a string")
    return value


def as_int(value: JsonValue, context: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ConfigurationError(f"{context}: expected an integer")
    return value


def optional_string(value: JsonValue, context: str) -> str | None:
    return None if value is None else as_string(value, context)


def parse_proxy(name: str, value: JsonValue) -> Proxy:
    item: JsonObject = as_object(value, f"proxy {name}")
    members: tuple[str, ...] = tuple(
        as_string(member, f"proxy {name}.all")
        for member in as_list(item.get("all", []), f"proxy {name}.all")
    )
    return Proxy(
        name=name,
        kind=as_string(item.get("type"), f"proxy {name}.type"),
        members=members,
        selected=optional_string(item.get("now"), f"proxy {name}.now"),
        fixed=optional_string(item.get("fixed"), f"proxy {name}.fixed"),
    )


def proxy_by_name(proxies: tuple[Proxy, ...], name: str) -> Proxy:
    for proxy in proxies:
        if proxy.name == name:
            return proxy
    raise ConfigurationError(f"Unknown node or group: {name}")


def is_node(proxy: Proxy) -> bool:
    return not proxy.members and proxy.kind.lower() not in {
        "direct",
        "reject",
        "rejectdrop",
        "compatible",
        "pass",
        "dns",
        "selector",
        "urltest",
        "fallback",
        "loadbalance",
        "relay",
    }


def node_names(proxies: tuple[Proxy, ...], group: str) -> tuple[str, ...]:
    """Expand nested groups, preserve ordering, and reject cycles or missing members."""

    def walk(name: str, ancestors: tuple[str, ...]) -> tuple[str, ...]:
        if name in ancestors:
            raise ConfigurationError(f"Proxy group cycle: {' -> '.join((*ancestors, name))}")
        proxy: Proxy = proxy_by_name(proxies, name)
        if is_node(proxy):
            return (name,)
        return tuple(leaf for member in proxy.members for leaf in walk(member, (*ancestors, name)))

    return tuple(dict.fromkeys(walk(group, ())))


def choose_group(snapshot: Snapshot, requested: str | None) -> str:
    """Infer only an unambiguous active leaf group; never guess between service groups."""
    if requested is not None:
        group: Proxy = proxy_by_name(snapshot.proxies, requested)
        if not group.members:
            raise ConfigurationError(f"{requested} is not a proxy group")
        return requested
    if snapshot.mode == "global":
        return "GLOBAL"
    if snapshot.mode == "direct":
        raise ConfigurationError("Direct mode: specify --group, or use 'mode rule' first")
    reachable: tuple[str, ...] = tuple(
        name
        for name in snapshot.rule_targets
        if any(proxy.name == name and proxy.members for proxy in snapshot.proxies)
    )

    def leaf_groups(name: str, ancestors: tuple[str, ...]) -> tuple[str, ...]:
        if name in ancestors:
            raise ConfigurationError(f"Proxy group cycle at {name}")
        proxy: Proxy = proxy_by_name(snapshot.proxies, name)
        if any(is_node(proxy_by_name(snapshot.proxies, member)) for member in proxy.members):
            return (name,)
        return tuple(
            child
            for member in proxy.members
            for child in leaf_groups(member, (*ancestors, name))
            if proxy_by_name(snapshot.proxies, member).members
        )

    candidates: tuple[str, ...] = tuple(
        dict.fromkeys(child for name in reachable for child in leaf_groups(name, ()))
    )
    if len(candidates) != 1:
        raise ConfigurationError(
            f"Cannot infer one target group from rules: {list(candidates)}. Specify --group."
        )
    return candidates[0]


def selection_path(
    proxies: tuple[Proxy, ...], group: str, node: str
) -> tuple[tuple[str, str], ...]:
    """Find a selectable path to a node without traversing load-balancing groups."""
    queue: tuple[tuple[str, tuple[tuple[str, str], ...]], ...] = ((group, ()),)
    seen: frozenset[str] = frozenset()
    while queue:
        name, path = queue[0]
        queue = queue[1:]
        if name in seen:
            continue
        seen = seen | {name}
        proxy: Proxy = proxy_by_name(proxies, name)
        if proxy.kind not in {"Selector", "URLTest", "Fallback"}:
            continue
        if node in proxy.members:
            return (*path, (name, node))
        queue = (*queue, *((member, (*path, (name, member))) for member in proxy.members))
    raise ConfigurationError(f"No selectable path from {group} to {node}")
