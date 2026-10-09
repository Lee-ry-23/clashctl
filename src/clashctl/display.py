"""Shared terminal rendering for command and interactive workflows."""

import click
from rich.console import Console
from rich.table import Table
from rich.text import Text

from clashctl.models import (
    BenchmarkReport,
    NodeResult,
    Sample,
    Settings,
    Snapshot,
    node_names,
    proxy_by_name,
)
from clashctl.probes import openai_label
from clashctl.terminal_display import node_label


def print_status(settings: Settings, snapshot: Snapshot) -> None:
    console: Console = Console()
    console.print(f"[bold]Mihomo {snapshot.version}[/bold]", markup=True)
    console.print(f"API: {settings.controller}", markup=False)
    console.print(f"Mode: {snapshot.mode} | TUN: {snapshot.tun_enabled}", markup=False)
    console.print(f"Proxy port: {snapshot.mixed_port} | Rules: {snapshot.rule_count}", markup=False)
    console.print(f"Runtime source: {settings.config_path}", markup=False)
    print_groups(snapshot)


def print_groups(snapshot: Snapshot) -> None:
    table: Table = Table("Group", "Type", "Current member", "Entries", "Fixed")
    for proxy in snapshot.proxies:
        if proxy.members:
            table.add_row(
                Text(proxy.name),
                proxy.kind,
                Text(node_label(proxy.selected or "—")),
                str(len(node_names(snapshot.proxies, proxy.name))),
                proxy.fixed or "—",
            )
    Console().print(table)


def print_nodes(snapshot: Snapshot, group: str, candidates: tuple[str, ...]) -> None:
    table: Table = Table("#", "Node", "Protocol", "Current")
    current: str | None = proxy_by_name(snapshot.proxies, group).selected
    for index, name in enumerate(candidates, 1):
        proxy = proxy_by_name(snapshot.proxies, name)
        table.add_row(
            str(index), Text(node_label(name)), proxy.kind, "✓" if name == current else ""
        )
    Console().print(f"Group: {group} | Nodes: {len(candidates)}", markup=False)
    Console().print(table)


def print_sample(sample: Sample, completed: int, total: int) -> None:
    prefix: str = f"[{completed}/{total}] round {sample.round_number} | {node_label(sample.node)}"
    if sample.error is None:
        click.echo(f"{prefix} | {sample.mbps:.2f} Mbps | attempt {sample.attempts}")
    else:
        click.echo(f"{prefix} | FAILED: {sample.error}", err=True)


def print_node_finished(report: BenchmarkReport) -> None:
    completed: dict[str, NodeResult] = {
        result.node: result
        for result in report.results
        if len(result.samples) == report.rounds and result.openai is not None
    }
    node: str = next(name for name in reversed(report.requested_nodes) if name in completed)
    result: NodeResult = completed[node]
    click.echo(
        f"Done: {node_label(node)} | {result.median_mbps:.2f} Mbps"
        f" | OpenAI {openai_label(result.openai)}"
    )


def print_results(report: BenchmarkReport) -> None:
    table: Table = Table(
        "Rank", "Node", "Median Mbps", "P25 Mbps", "CV %", "Rounds", "Score", "OpenAI API"
    )
    for index, result in enumerate(report.results, 1):
        table.add_row(
            str(index),
            Text(node_label(result.node)),
            f"{result.median_mbps:.2f}",
            f"{result.conservative_mbps:.2f}",
            f"{result.variation_percent:.1f}",
            f"{result.successful_rounds}/{result.total_rounds}",
            f"{result.score:.2f}",
            openai_label(result.openai),
            style="green" if result.node == report.winner else "",
        )
    Console().print(table)
    click.echo(f"Winner for this test target: {node_label(report.winner or 'none')}")
    click.echo("Score = P25 throughput × first-attempt success fraction; all rounds must succeed.")
    click.echo(
        "OpenAI: fast ≤2s for unauthenticated API response; account/ChatGPT access untested."
    )
