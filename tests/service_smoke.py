"""Real node-first benchmarks, independent API checks, cache updates, and PTY commands.

Run: uv run python tests/service_smoke.py --node NODE --node OTHER_NODE
Uses temporary private cores and reports, with small 1 MiB download samples.
"""

import argparse
import re
import tempfile
import threading
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path

from menu_smoke import Terminal, command

from clashctl.benchmark import apply_winner, never_cancel, run_benchmark
from clashctl.cache import read_cache
from clashctl.config import load_settings
from clashctl.controller import ClashClient
from clashctl.isolation import IsolatedCore
from clashctl.models import (
    BenchmarkCancelled,
    BenchmarkOptions,
    BenchmarkReport,
    MeasurementError,
    Sample,
    Settings,
    Snapshot,
)
from clashctl.monitor import LiveContext, MonitorOptions, WatchStatus, default_options, load_context
from clashctl.routing_models import empty_routing
from clashctl.service_checks import (
    OpenAICache,
    ProbeEvent,
    merge_openai_results,
    read_openai_cache,
    run_openai_checks,
)
from clashctl.shell_commands import ShellState, cached_best, node_id
from clashctl.shell_display import render_panel
from clashctl.terminal_display import plain_text


def verify_node_order(
    settings: Settings, snapshot: Snapshot, nodes: tuple[str, ...], directory: Path
) -> None:
    samples: list[tuple[str, int]] = []
    finished: list[BenchmarkReport] = []

    def progress(sample: Sample, completed: int, total: int) -> None:
        samples.append((sample.node, sample.round_number))

    def node_finished(report: BenchmarkReport) -> None:
        finished.append(report)

    options: BenchmarkOptions = BenchmarkOptions(
        "GLOBAL",
        nodes,
        2,
        1024 * 1024,
        "https://speed.cloudflare.com/__down?bytes={bytes}",
        10.0,
        2,
        directory / "active.json",
    )
    report: BenchmarkReport = run_benchmark(
        settings, snapshot, options, progress, node_finished, never_cancel
    )
    if samples != [(name, round_number) for name in nodes for round_number in (1, 2)]:
        raise AssertionError(f"Benchmark did not finish each node before advancing: {samples}")
    if len(finished) != len(nodes) or not report.complete:
        raise AssertionError("Per-node publications or final completion were lost")
    first: BenchmarkReport = finished[0]
    if first.complete:
        raise AssertionError("First node publication incorrectly completed the whole scan")
    results = {result.node: result for result in first.results}
    if len(results[nodes[0]].samples) != 2 or results[nodes[0]].openai is None:
        raise AssertionError("First node did not include all rounds and its OpenAI probe")
    if results[nodes[1]].samples or results[nodes[1]].openai is not None:
        raise AssertionError("Second node started before the first result was published")
    try:
        apply_winner(settings, first)
    except MeasurementError:
        pass
    else:
        raise AssertionError("An incomplete scan could be applied")
    context: LiveContext = load_context(settings)
    monitor_options: MonitorOptions = replace(
        default_options(),
        directory=directory,
        include="^(?:" + "|".join(re.escape(node) for node in nodes) + ")$",
    )
    state: ShellState = ShellState(
        context,
        None,
        None,
        WatchStatus("scanning", 2, 4, "test", None),
        "rank",
        "",
        "",
        "info",
        (),
        empty_routing(),
        first,
        None,
        "",
    )
    panel: str = plain_text(render_panel(state, monitor_options, 124))
    node_row: str = next(line for line in panel.splitlines() if node_id(nodes[0]) in line)
    if "untested" in node_row or "untested" not in panel:
        raise AssertionError("The live panel lost the completed node or pending node state")
    try:
        cached_best(None, context, "GLOBAL", monitor_options, datetime.now(UTC))
    except MeasurementError:
        pass
    else:
        raise AssertionError("Per-node display data bypassed the complete-cache requirement")
    print("Node-first order, early publication, partial-scan switching guard: passed", flush=True)


def verify_cancelled_probe(settings: Settings, snapshot: Snapshot, nodes: tuple[str, ...]) -> None:
    stop: threading.Event = threading.Event()
    events: list[ProbeEvent] = []

    def progress(event: ProbeEvent) -> None:
        events.append(event)
        stop.set()

    try:
        run_openai_checks(settings, snapshot, nodes, 4.0, progress, stop.is_set)
    except BenchmarkCancelled:
        pass
    else:
        raise AssertionError("Independent OpenAI checks ignored cancellation")
    if len(events) != 1 or events[0].node != nodes[0]:
        raise AssertionError("Cancellation lost the finished API result or probed another node")
    print("Independent API probe and cancellation after one node: passed", flush=True)


def verify_commands(settings: Settings, node: str, directory: Path) -> None:
    reports: Path = directory / "reports"
    download_cache: Path = reports / "background-cache.json"
    service_cache: Path = reports / "openai-cache.json"
    with Terminal(command(settings, node, directory, 2), directory) as terminal:
        terminal.expect("Your local Clash workspace")
        terminal.until(lambda: download_cache.exists(), 90.0)
        terminal.expect("WATCH IDLE")
        terminal.command("/watch pause", "Pausing downloads")
        terminal.expect("WATCH PAUSED")
        download_before: bytes = download_cache.read_bytes()
        original: OpenAICache | None = read_openai_cache(service_cache)
        if original is None:
            raise AssertionError("Per-node benchmark API results were not persisted")
        terminal.send("/ope\t")
        terminal.expect("› /openai")
        terminal.send(" " + node_id(node) + "\r")
        terminal.expect("OpenAI checks started.")
        terminal.expect("OpenAI complete 1/1")
        updated: OpenAICache | None = read_openai_cache(service_cache)
        if updated is None or updated == original:
            raise AssertionError("Independent /openai did not update the service cache")
        if download_cache.read_bytes() != download_before:
            raise AssertionError("Independent /openai rewrote download rankings")
        if b"\x1b[?1000h" not in terminal.transcript:
            raise AssertionError("The real shell did not enable application mouse scrolling")
        older: OpenAICache = merge_openai_results(updated, updated.source_digest, original.results)
        if older != updated:
            raise AssertionError("Older benchmark data overwrote a newer independent API check")
        terminal.command("/logs", "Recent activity")
        terminal.command("/nodes", "OpenAI complete 1/1")
        terminal.quit()
    before_restart: bytes = service_cache.read_bytes()
    with Terminal(command(settings, node, directory, 2), directory) as terminal:
        terminal.expect("WATCH IDLE")
        terminal.command("/nodes", "OpenAI API")
        node_row: str = next(row for row in terminal.screen.display if node_id(node) in row)
        if "untested" in node_row:
            raise AssertionError("Restart lost the persisted API observation")
        if service_cache.read_bytes() != before_restart:
            raise AssertionError("Restart replaced the fresh API cache")
        terminal.command("/watch pause", "Pausing downloads")
        terminal.expect("WATCH PAUSED")
        terminal.command("/openai", "OpenAI checks started.")
        terminal.command("/help", "Your local Clash workspace")
        terminal.send("/openai stop\r")
        terminal.until(
            lambda: (
                "Stopping OpenAI checks" in terminal.text()
                or "No independent OpenAI check" in terminal.text()
            ),
            5.0,
        )
        terminal.quit()
    if read_cache(download_cache) is None:
        raise AssertionError("Stopping API checks discarded the complete download cache")
    print(
        "PTY /openai, completion, pause independence, persisted restart, stop, quit: passed",
        flush=True,
    )


def main() -> None:
    parser: argparse.ArgumentParser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--node", action="append", required=True)
    arguments: argparse.Namespace = parser.parse_args()
    nodes: tuple[str, ...] = tuple(arguments.node)
    if len(nodes) != 2 or len(set(nodes)) != 2:
        raise AssertionError("Supply exactly two different nodes")
    settings: Settings = load_settings(None, None, None, None, 5.0)
    client: ClashClient = ClashClient(settings)
    before: Snapshot = client.snapshot()
    with IsolatedCore(settings, before, nodes) as core:
        if core.client is None:
            raise AssertionError("Private controller did not initialize")
        private: Settings = core.client.settings
        with tempfile.TemporaryDirectory(prefix="clashctl-service-test-") as temporary:
            directory: Path = Path(temporary)
            verify_node_order(private, core.client.snapshot(), nodes, directory)
            verify_cancelled_probe(private, core.client.snapshot(), nodes)
            verify_commands(private, nodes[0], directory)
    if client.snapshot() != before:
        raise AssertionError("Service checks changed live mode, topology, or selections")
    print("PASS: real node-first downloads, independent OpenAI, incremental cache, PTY, live state")


if __name__ == "__main__":
    main()
