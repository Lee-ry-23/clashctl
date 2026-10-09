"""Terminal panels for live routing and evidence-backed rule previews."""

import csv
from collections import Counter
from io import StringIO
from itertools import groupby

from rich import box
from rich.console import Console
from rich.table import Table
from rich.text import Text

from clashctl.probes import ProbeResult
from clashctl.routing_models import Connection, RoutingState, RuntimeRule
from clashctl.terminal_display import display_name, node_label


def connection_key(connection: Connection) -> tuple[str, str, str, str, str, tuple[str, ...]]:
    return (
        connection.host,
        connection.port,
        connection.process,
        connection.rule,
        connection.rule_payload,
        connection.chains,
    )


def render_sites(console: Console, routing: RoutingState, keyword: str) -> None:
    console.print("[bold]Live Clash connections[/bold]")
    console.print("[dim]Refresh every 5s while visible · latest update time shown below[/dim]")
    if routing.error is not None:
        console.print(Text("Refresh failed; last snapshot is stale: " + routing.error, style="red"))
    connections: tuple[Connection, ...] = matching_connections(routing, keyword)
    show_apps: bool = console.width >= 110 and any(c.process for c in connections)
    table: Table = Table(box=box.SIMPLE, expand=True, padding=(0, 1))
    table.add_column("Website / address", ratio=4, no_wrap=True, overflow="ellipsis")
    table.add_column("Route", ratio=3, no_wrap=True, overflow="ellipsis")
    table.add_column("Matched rule", ratio=3, no_wrap=True, overflow="ellipsis")
    if show_apps:
        table.add_column("App", ratio=1, no_wrap=True, overflow="ellipsis")
    table.add_column("#", width=3, justify="right", no_wrap=True)
    for key, grouped in groupby(connections, key=connection_key):
        members: tuple[Connection, ...] = tuple(grouped)
        host, port, process, rule, payload, chains = key
        destination: str = f"{host}:{port}" if port != "443" else host
        route: str = route_summary(chains)
        row: list[Text] = [
            Text(display_name(destination)),
            Text(display_name(route), style="green" if route == "DIRECT" else "blue"),
            Text(display_name(rule + (":" + payload if payload else ""))),
        ]
        if show_apps:
            row.append(Text(display_name(process) or "-"))
        row.append(Text(str(len(members))))
        table.add_row(*row)
    console.print(table)
    if not connections:
        console.print("No matching open connections. Open a website and keep this view visible.")
    console.print("[dim]/sites <keyword> filters · /copy copies full addresses and routes[/dim]")
    console.print(
        "[dim]Only Clash-visible traffic. Existing connections keep their original route.[/dim]"
    )


def matching_connections(routing: RoutingState, keyword: str) -> tuple[Connection, ...]:
    return tuple(
        sorted(
            (
                connection
                for connection in routing.connections
                if keyword.casefold() in (connection.host + " " + connection.process).casefold()
            ),
            key=connection_key,
        )
    )


def route_summary(chains: tuple[str, ...]) -> str:
    if not chains:
        return "pending"
    outbound: str = chains[0]
    if outbound.upper() in {"DIRECT", "REJECT", "REJECT-DROP", "REJECTDROP"}:
        return outbound.upper()
    return "VPN " + node_label(outbound)


def sites_copy_text(routing: RoutingState, keyword: str) -> str:
    """Export complete raw names and chains, independently of screen truncation."""
    output: StringIO = StringIO()
    writer = csv.writer(output, delimiter="\t", lineterminator="\n")
    writer.writerow(("Website / address", "App", "Route", "Matched rule", "Connections"))
    connections: tuple[Connection, ...] = matching_connections(routing, keyword)
    for key, grouped in groupby(connections, key=connection_key):
        members: tuple[Connection, ...] = tuple(grouped)
        host, port, process, rule, payload, chains = key
        writer.writerow(
            (
                f"{host}:{port}",
                process,
                " -> ".join(reversed(chains)),
                rule + (":" + payload if payload else ""),
                len(members),
            )
        )
    return output.getvalue()


def render_rules(console: Console, routing: RoutingState, keyword: str) -> None:
    console.print("[bold]Ordered routing rules · first match wins[/bold]")
    counts: Counter[str] = Counter(rule.target for rule in routing.rules)
    console.print(
        Text(
            display_name(
                f"{len(routing.rules)} rules · "
                + " · ".join(f"{k}: {v}" for k, v in counts.items())
            )
        )
    )
    if keyword:
        console.print(Text(f"Filter: {keyword} · /rules view clears this filter", style="dim"))
    matches: tuple[RuntimeRule, ...] = matching_rules(routing, keyword)
    table: Table = Table(box=box.SIMPLE, expand=True)
    table.add_column("#", width=5, no_wrap=True)
    table.add_column("Type", ratio=2, no_wrap=True, overflow="ellipsis")
    table.add_column("Match", ratio=5, no_wrap=True, overflow="ellipsis")
    table.add_column("Policy", ratio=2, no_wrap=True, overflow="ellipsis")
    for rule in matches[:200]:
        table.add_row(
            str(rule.position),
            rule.kind,
            Text(display_name(rule.payload)),
            Text(display_name(rule.target)),
        )
    console.print(table)
    console.print(
        f"Showing {min(len(matches), 200)}/{len(matches)} matches. /rules <keyword> filters."
    )
    console.print(
        "[dim]/rules check [hosts] · /rules apply · /rules refresh [hosts] · /rules undo[/dim]"
    )
    console.print(
        "[dim]/sites or /rules sites shows active websites and their matched rules.[/dim]"
    )
    console.print("[dim]/copy copies all matching rules with full policy names.[/dim]")


def matching_rules(routing: RoutingState, keyword: str) -> tuple[RuntimeRule, ...]:
    return tuple(
        rule
        for rule in routing.rules
        if keyword.casefold() in f"{rule.kind} {rule.payload} {rule.target}".casefold()
    )


def rules_copy_text(routing: RoutingState, keyword: str) -> str:
    """Copy all matching rules without the display row limit or truncated labels."""
    output: StringIO = StringIO()
    writer = csv.writer(output, delimiter="\t", lineterminator="\n")
    writer.writerow(("#", "Type", "Match", "Policy"))
    for rule in matching_rules(routing, keyword):
        writer.writerow((rule.position, rule.kind, rule.payload, rule.target))
    return output.getvalue()


def probe_summary(results: tuple[ProbeResult, ...]) -> str:
    if not results:
        return "not needed"
    return " / ".join(
        "timeout/error"
        if result.http_status is None
        else f"{result.http_status} {result.response_ms / 1000:.1f}s"
        if result.response_ms is not None
        else str(result.http_status)
        for result in results
    )


def render_rulecheck(console: Console, routing: RoutingState) -> None:
    if routing.plan is None:
        console.print("No rule preview. Run /rules check [hostnames].")
        return
    plan = routing.plan
    console.print("[bold]Rule refresh preview[/bold]")
    console.print(Text(f"Created: {plan.created_at}"))
    console.print(
        "China domains/IPs → DIRECT · confirmed reachable → DIRECT · confirmed proxy-only → VPN"
    )
    console.print(
        "[dim]Unconfirmed domains keep existing routes. "
        "Known proxy rules remain for untested sites.[/dim]"
    )
    table: Table = Table(
        "Website", "Direct (2 trials)", "VPN (2 trials)", "Decision", box=box.SIMPLE, expand=True
    )
    for audit in plan.audits:
        table.add_row(
            Text(audit.host), probe_summary(audit.direct), probe_summary(audit.proxy), audit.verdict
        )
    console.print(table)
    console.print(f"Rules: {len(plan.original_rules)} → {len(plan.rules)} · {plan.rules[-1]}")
    console.print(Text("Extension: " + str(plan.extension_path)))
    console.print(
        "[dim]/rules apply activates this preview with a backup. "
        "/rules undo restores the last change.[/dim]"
    )
    console.print(
        "[dim]Checks describe this network at this time; "
        "they do not classify the entire Internet.[/dim]"
    )
