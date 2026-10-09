"""Pure command parsing, stable ASCII references, and cache-selection rules."""

import hashlib
import shlex
from dataclasses import dataclass
from datetime import datetime
from typing import Literal

from clashctl.cache import CachedReport, age_seconds
from clashctl.models import (
    BenchmarkReport,
    ConfigurationError,
    MeasurementError,
    StateConflictError,
)
from clashctl.monitor import LiveContext, MonitorOptions, WatchStatus, cache_matches, group_nodes
from clashctl.routing_models import RoutingState
from clashctl.service_checks import OpenAICache


@dataclass(frozen=True)
class CommandHint:
    name: str
    usage: str
    description: str


@dataclass(frozen=True)
class ShellCommand:
    name: str
    arguments: tuple[str, ...]


@dataclass(frozen=True)
class ShellState:
    context: LiveContext | None
    group: str | None
    cache: CachedReport | None
    watch: WatchStatus
    view: Literal[
        "help", "status", "groups", "nodes", "rank", "watch", "logs", "rules", "rulecheck", "sites"
    ]
    keyword: str
    notice: str
    level: Literal["info", "success", "error"]
    logs: tuple[str, ...]
    routing: RoutingState
    scan: BenchmarkReport | None
    services: OpenAICache | None
    service_message: str


def command_hints() -> tuple[CommandHint, ...]:
    return (
        CommandHint("rank", "/rank [keyword]", "View cached speeds instantly; no new download"),
        CommandHint("nodes", "/nodes [keyword]", "Browse nodes with stable ASCII IDs"),
        CommandHint("connect", "/connect <id or name>", "Select a node in the working group"),
        CommandHint("best", "/best", "Connect the best fresh, complete cached result"),
        CommandHint("bench", "/bench", "Request a background refresh now"),
        CommandHint(
            "openai", "/openai [node ID | stop]", "Quick API checks, no download benchmark"
        ),
        CommandHint("watch", "/watch <action> [minutes]", "Status, pause, resume, or interval"),
        CommandHint(
            "sites", "/sites [keyword]", "Current websites and their matched routing rules"
        ),
        CommandHint(
            "rules",
            "/rules [action or keyword]",
            "All routing rules; /rules sites shows active websites",
        ),
        CommandHint("status", "/status", "Refresh live Clash mode and selections"),
        CommandHint("groups", "/groups", "List selectable groups and their IDs"),
        CommandHint("group", "/group <id or name>", "Choose a working proxy group"),
        CommandHint("mode", "/mode <mode>", "Set rule, global, or direct mode"),
        CommandHint("help", "/help", "Show commands and keyboard shortcuts"),
        CommandHint("logs", "/logs", "Show recent background warnings and errors"),
        CommandHint("copy", "/copy", "Copy current results, including off-screen rows"),
        CommandHint("freeze", "/freeze", "Pause or resume display updates; same as F2"),
        CommandHint("clear", "/clear", "Clear the current result panel"),
        CommandHint("quit", "/quit", "Stop the worker and restore the terminal"),
    )


def parse_command(text: str) -> ShellCommand:
    try:
        words: list[str] = shlex.split(text)
    except ValueError as error:
        raise ConfigurationError(f"Invalid command quoting: {error}") from error
    if not words:
        raise ConfigurationError("Enter a command, such as /rank. Tab shows completions.")
    name: str = words[0].lstrip("/").casefold()
    if name not in {hint.name for hint in command_hints()}:
        raise ConfigurationError(f"Unknown command {words[0]!r}. Use /help or press Tab.")
    return ShellCommand(name, tuple(words[1:]))


def node_id(name: str) -> str:
    return "n" + hashlib.sha256(name.encode()).hexdigest()[:8]


def group_id(name: str) -> str:
    return "g" + hashlib.sha256(name.encode()).hexdigest()[:8]


def resolve_reference(reference: str, choices: tuple[tuple[str, str], ...]) -> str:
    key: str = reference.casefold()
    exact: tuple[str, ...] = tuple(
        name for identifier, name in choices if key in {identifier.casefold(), name.casefold()}
    )
    if len(exact) == 1:
        return exact[0]
    matches: tuple[str, ...] = tuple(name for _, name in choices if key in name.casefold())
    if len(matches) == 1:
        return matches[0]
    if not matches:
        raise ConfigurationError(f"No node or group matches {reference!r}. View /nodes or /groups.")
    raise ConfigurationError(f"Ambiguous reference {reference!r}: {matches}. Use an ID or Tab.")


def cached_best(
    cache: CachedReport | None,
    context: LiveContext,
    group: str,
    options: MonitorOptions,
    now: datetime,
) -> str:
    if cache is None:
        raise MeasurementError("No complete background scan yet. Check /watch status.")
    if not cache.report.complete or not cache_matches(cache, context, options):
        raise StateConflictError("Cache no longer matches this configuration. Refresh with /bench.")
    members: tuple[str, ...] = group_nodes(context, group)
    measured: dict[str, str] = dict(cache.measured_at)
    eligible: tuple[str, ...] = tuple(
        result.node
        for result in cache.report.results
        if result.node in members
        and result.eligible
        and age_seconds(measured[result.node], now) <= options.interval_seconds
    )
    if not eligible:
        raise MeasurementError(
            "No fresh successful cached result for this group. Refresh with /bench."
        )
    return eligible[0]
