"""Replaceable English terminal panels; rendering never performs controller or disk I/O."""

from dataclasses import dataclass, replace
from datetime import UTC, datetime
from io import StringIO

from rich import box
from rich.console import Console
from rich.table import Table
from rich.text import Text

from clashctl.cache import age_seconds, parse_time
from clashctl.models import NodeResult, OpenAIResult, proxy_by_name
from clashctl.monitor import (
    MonitorOptions,
    WatchStatus,
    cache_matches,
    group_nodes,
    matching_nodes,
    report_matches,
)
from clashctl.probes import openai_label
from clashctl.routing_display import connection_key, render_rulecheck, render_rules, render_sites
from clashctl.routing_models import empty_routing
from clashctl.shell_commands import ShellState, command_hints, group_id, node_id
from clashctl.terminal_display import display_name, node_label


@dataclass(frozen=True)
class PanelRevision:
    state: ShellState
    options: MonitorOptions
    width: int
    age_period: int


def panel_render_state(state: ShellState) -> ShellState:
    """Compare only inputs used by the visible result panel, excluding toolbar changes."""
    revision: ShellState = replace(
        state,
        context=None,
        group=None,
        cache=None,
        watch=WatchStatus("idle", 0, 0, "", None),
        notice="",
        level="info",
        logs=(),
        routing=empty_routing(),
        scan=None,
        services=None,
        service_message="",
    )
    if state.view in {"nodes", "rank"}:
        return replace(
            revision,
            context=state.context,
            group=state.group,
            cache=state.cache,
            scan=state.scan,
            services=state.services,
            service_message=state.service_message,
        )
    if state.view in {"status", "groups"}:
        return replace(revision, context=state.context, group=state.group)
    if state.view == "watch":
        return replace(revision, context=state.context, watch=state.watch)
    if state.view == "rules":
        return replace(revision, routing=replace(revision.routing, rules=state.routing.rules))
    if state.view == "sites":
        return replace(
            revision,
            routing=replace(
                revision.routing,
                connections=tuple(
                    sorted(
                        (
                            replace(connection, identifier="", downloaded=0, uploaded=0)
                            for connection in state.routing.connections
                        ),
                        key=connection_key,
                    )
                ),
                error=state.routing.error,
            ),
        )
    if state.view == "rulecheck":
        return replace(revision, routing=replace(revision.routing, plan=state.routing.plan))
    if state.view == "logs":
        return replace(revision, logs=state.logs)
    return revision


def format_age(seconds: float) -> str:
    if seconds < 60:
        return f"{int(seconds)}s"
    if seconds < 3600:
        return f"{int(seconds / 60)}m"
    return f"{seconds / 3600:.1f}h"


def visible_nodes(state: ShellState) -> tuple[str, ...]:
    if state.context is None:
        return ()
    members: tuple[str, ...] = (
        state.context.nodes if state.group is None else group_nodes(state.context, state.group)
    )
    return tuple(name for name in members if state.keyword.casefold() in name.casefold())


def render_help(console: Console) -> None:
    console.print("[bold]Your local Clash workspace[/bold]")
    console.print(
        "[blue]/sites[/blue] → current websites + matched rules · "
        "[blue]/rules view[/blue] → all rules"
    )
    console.print(
        "Type a command. Press [blue]Tab[/blue] to complete commands, node IDs, and groups."
    )
    table: Table = Table("Command", "Action", box=box.SIMPLE, expand=True)
    for hint in command_hints():
        table.add_row(Text(hint.usage, style="blue"), hint.description)
    console.print(table)
    console.print("[dim]Examples: /nodes JP  →  /connect <ID>    |    /rank  →  /best[/dim]")
    console.print(
        "[dim]Use IDs or completion to avoid typing emoji or non-English node names.[/dim]"
    )
    console.print(
        "[dim]Wheel / PgUp/PgDn scroll results · Drag and release to copy selected text.[/dim]"
    )
    console.print(
        "[dim]Esc clears selection · ↑↓ command history · F2 pauses display updates.[/dim]"
    )
    console.print(
        "[dim]/copy copies the current results, including rows outside the viewport.[/dim]"
    )


def render_status(console: Console, state: ShellState) -> None:
    if state.context is None:
        console.print("Waiting for the controller. Use /status to retry; /logs shows the error.")
        return
    snapshot = state.context.snapshot
    console.print(f"[bold]Mihomo {snapshot.version}[/bold]")
    console.print(f"Mode: {snapshot.mode}    TUN: {snapshot.tun_enabled}")
    console.print(f"Proxy port: {snapshot.mixed_port}    Rules: {snapshot.rule_count}")
    console.print(f"Usable nodes: {len(state.context.nodes)}\n")
    render_groups(console, state)


def render_groups(console: Console, state: ShellState) -> None:
    if state.context is None:
        console.print("No live groups yet. Use /status to connect to Clash.")
        return
    table: Table = Table(box=box.SIMPLE, expand=True)
    table.add_column("ID", width=9, no_wrap=True)
    table.add_column("Group", ratio=2, no_wrap=True, overflow="ellipsis")
    table.add_column("Current member", ratio=3, no_wrap=True, overflow="ellipsis")
    table.add_column("Nodes", width=5, no_wrap=True)
    for group in state.context.groups:
        selected: str = proxy_by_name(state.context.snapshot.proxies, group.name).selected or "—"
        table.add_row(
            group_id(group.name),
            Text(display_name(group.name)),
            Text(node_label(selected)),
            str(len(group.nodes)),
            style="blue" if group.name == state.group else "",
        )
    console.print(table)
    console.print(
        "[dim]/group <id or name> chooses the group affected by /connect and /best.[/dim]"
    )


def render_nodes(
    console: Console, state: ShellState, options: MonitorOptions, now: datetime
) -> None:
    members: tuple[str, ...] = visible_nodes(state)
    monitored: frozenset[str] = frozenset(
        () if state.context is None else matching_nodes(state.context, options)
    )
    results: dict[str, NodeResult] = (
        {}
        if state.cache is None
        else {result.node: result for result in state.cache.report.results}
    )
    times: dict[str, str] = {} if state.cache is None else dict(state.cache.measured_at)
    matched: bool = (
        state.cache is not None
        and state.context is not None
        and cache_matches(state.cache, state.context, options)
    )
    current: frozenset[str] = frozenset(results) if matched else frozenset()
    if (
        state.scan is not None
        and state.context is not None
        and report_matches(state.scan, state.context, options)
    ):
        finished: dict[str, NodeResult] = {
            result.node: result
            for result in state.scan.results
            if len(result.samples) == state.scan.rounds and result.openai is not None
        }
        results = {**results, **finished}
        times = {
            **times,
            **{
                name: result.openai.checked_at
                for name, result in finished.items()
                if result.openai is not None
            },
        }
        current = current | frozenset(finished)
    services: dict[str, tuple[OpenAIResult, bool]] = node_services(state, results, current)
    if state.view == "rank":
        members = tuple(name for name in members if name in monitored)
        members = tuple(
            sorted(
                members,
                key=lambda name: (
                    name not in results or not results[name].eligible,
                    -results[name].score if name in results else 0.0,
                    name,
                ),
            )
        )
    console.print(
        Text(
            f"Group: {display_name(state.group or 'all nodes')}    Showing: {len(members)}",
            style="bold",
        )
    )
    if state.cache is None:
        console.print(
            "[dark_orange]First scan is running. "
            "Results appear as each node finishes.[/dark_orange]"
        )
    elif not matched:
        console.print(
            "[dark_orange]Cache configuration changed. "
            "/best waits for a matching refresh.[/dark_orange]"
        )
    else:
        console.print(
            "[dim]Cached downloads · median Mbps · conservative score · age per node[/dim]"
        )
    if state.service_message:
        console.print(Text(display_name(state.service_message), style="blue"))
    console.print(
        "[dim]Each node: all download rounds + OpenAI, then next node. "
        "/openai runs API checks only.[/dim]"
    )
    table: Table = Table(
        "ID",
        "Node",
        "Mbps",
        "Score",
        "OpenAI API",
        "Age",
        "State",
        box=box.SIMPLE,
        expand=True,
        collapse_padding=True,
        pad_edge=False,
    )
    table.columns[1].no_wrap = True
    table.columns[1].overflow = "ellipsis"
    for name in members:
        result: NodeResult | None = results.get(name)
        age: float | None = None if name not in times else age_seconds(times[name], now)
        label: str = "pending"
        if name not in monitored:
            label = "unmonitored"
        if result is not None:
            label = "failed" if not result.eligible else "fresh"
            if name not in current or (age is not None and age > options.interval_seconds):
                label = "stale"
        entry: tuple[OpenAIResult, bool] | None = services.get(name)
        service: str = "untested" if entry is None else openai_label(entry[0])
        if entry is not None and (
            not entry[1] or age_seconds(entry[0].checked_at, now) > options.interval_seconds
        ):
            service = "stale"
        table.add_row(
            node_id(name),
            Text(node_label(name)),
            "—" if result is None else f"{result.median_mbps:.2f}",
            "—" if result is None else f"{result.score:.2f}",
            service,
            "—" if age is None else format_age(age),
            label,
            style="dim" if label in {"pending", "stale", "unmonitored"} else "",
        )
    console.print(table)
    console.print(
        "[dim]Score = P25 × first-attempt success rate. "
        "/best uses fresh results from the last complete scan.[/dim]"
    )
    console.print("[dim]Ranking is specific to this download target and sample size.[/dim]")
    console.print(
        "[dim]OpenAI: fast ≤2s · API only · no key · ChatGPT/account access untested.[/dim]"
    )


def node_services(
    state: ShellState, results: dict[str, NodeResult], current: frozenset[str]
) -> dict[str, tuple[OpenAIResult, bool]]:
    services: dict[str, tuple[OpenAIResult, bool]] = {
        name: (result.openai, name in current)
        for name, result in results.items()
        if result.openai is not None
    }
    if state.services is not None:
        valid: bool = (
            state.context is not None and state.services.source_digest == state.context.digest
        )
        for name, result in state.services.results:
            previous: tuple[OpenAIResult, bool] | None = services.get(name)
            if (
                previous is None
                or (valid and not previous[1])
                or (
                    valid == previous[1]
                    and parse_time(result.checked_at) > parse_time(previous[0].checked_at)
                )
            ):
                services = {**services, name: (result, valid)}
    return services


def render_watch(console: Console, state: ShellState, options: MonitorOptions) -> None:
    count: int = len(matching_nodes(state.context, options)) if state.context is not None else 0
    payload: float = count * options.rounds * options.size_bytes / 1024 / 1024
    console.print(f"[bold]Background monitor: {state.watch.phase}[/bold]\n")
    console.print(Text(display_name(state.watch.message)))
    console.print(f"Samples: {state.watch.completed}/{state.watch.total}")
    console.print(f"Interval: {options.interval_seconds / 60:g} minutes")
    console.print(
        f"Download: {options.rounds} rounds × {options.size_bytes / 1024 / 1024:g} MiB per node"
    )
    console.print(
        f"Traffic: about {payload:g} MiB/scan; up to {payload * options.attempts:g} MiB on retries"
    )
    if options.include is not None:
        console.print(Text(f"Monitor filter: {options.include}"))
    console.print(Text(f"Target: {options.url}"))
    console.print(Text(f"Cache: {options.directory / 'background-cache.json'}"))
    if state.watch.next_at is not None:
        console.print(f"Next scan: {state.watch.next_at}")
    console.print("\n[dim]Scans never switch your node. Closing the shell stops the worker.[/dim]")
    console.print("[dim]/watch pause    /watch resume    /watch interval 60    /bench[/dim]")


def render_panel(state: ShellState, options: MonitorOptions, width: int) -> str:
    output: StringIO = StringIO()
    console: Console = Console(
        file=output,
        force_terminal=True,
        color_system="truecolor",
        width=max(30, width),
    )
    if state.view == "help":
        render_help(console)
    elif state.view == "status":
        render_status(console, state)
    elif state.view == "groups":
        render_groups(console, state)
    elif state.view in {"nodes", "rank"}:
        render_nodes(console, state, options, datetime.now(UTC))
    elif state.view == "watch":
        render_watch(console, state, options)
    elif state.view == "sites":
        render_sites(console, state.routing, state.keyword)
    elif state.view == "rules":
        render_rules(console, state.routing, state.keyword)
    elif state.view == "rulecheck":
        render_rulecheck(console, state.routing)
    else:
        console.print("[bold]Recent activity[/bold]\n")
        for message in state.logs:
            console.print(Text(display_name(message)))
        if not state.logs:
            console.print("No warnings or errors in this session.")
    return output.getvalue()
