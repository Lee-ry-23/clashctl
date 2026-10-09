"""Measure real PTY idle CPU, memory and scroll latency with live read-only Clash data.

Run: uv run python tests/performance_smoke.py
The fixture runs the production refresh loops without starting any benchmark worker.
An optional --source directory selects a saved source tree for before/after comparisons.
"""

import argparse
import asyncio
import json
import resource
import statistics
import sys
import tempfile
import time
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta
from pathlib import Path

from menu_smoke import Terminal
from terminal_smoke import mouse_packet, resize, wait_for_paint

from clashctl.cache import read_cache
from clashctl.config import load_settings
from clashctl.controller import ClashClient
from clashctl.models import ConfigurationError, JsonObject, Settings, as_int, as_object, json_value
from clashctl.monitor import LiveContext, MonitorOptions, WatchStatus, default_options, load_context
from clashctl.routing_models import RoutingState
from clashctl.service_checks import read_openai_cache
from clashctl.shell import TerminalShell


@dataclass(frozen=True)
class Counters:
    cpu: float
    wall: float
    peak_mib: float
    paints: int
    scroll_limit: int


@dataclass(frozen=True)
class Measurement:
    view: str
    cpu_percent: float
    peak_mib: float
    idle_paints: int
    scroll_ms: float
    hover_paints: int


async def resource_updates(shell: TerminalShell, path: Path) -> None:
    """Publish transient counters atomically without fsync work in the measured process."""
    temporary: Path = path.with_suffix(".tmp")
    while not shell.closing:
        temporary.write_text(
            json.dumps(
                {
                    "cpu": time.process_time(),
                    "wall": time.monotonic(),
                    "peak_mib": resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024 / 1024,
                    "paints": shell.app.render_counter,
                    "scroll_limit": shell.scroll_limit(),
                }
            ),
            encoding="utf-8",
        )
        temporary.replace(path)
        await asyncio.sleep(1.0)


async def run_fixture() -> None:
    project: Path = Path(__file__).resolve().parent.parent
    settings: Settings = load_settings(None, None, None, None, 5.0)
    options: MonitorOptions = default_options()
    shell: TerminalShell = TerminalShell(settings, options)
    context: LiveContext = await asyncio.to_thread(load_context, settings)
    client: ClashClient = ClashClient(settings)
    routing: RoutingState = RoutingState(
        await asyncio.to_thread(client.rules),
        await asyncio.to_thread(client.connections),
        (),
        datetime.now(UTC).isoformat(),
        None,
        None,
    )
    shell.state = replace(
        shell.state,
        context=context,
        view="nodes",
        cache=read_cache(project / "reports/background-cache.json"),
        services=read_openai_cache(project / "reports/openai-cache.json"),
        routing=routing,
        watch=WatchStatus(
            "idle",
            0,
            0,
            "Cached measurements ready",
            (datetime.now(UTC) + timedelta(hours=1)).isoformat(),
        ),
    )
    shell.redraw()
    tasks: tuple[asyncio.Task[None], ...] = (
        asyncio.create_task(shell.refresh()),
        asyncio.create_task(shell.connections_loop()),
        asyncio.create_task(resource_updates(shell, Path("resources.json"))),
    )
    for task in tasks:
        task.add_done_callback(shell.task_finished)
    try:
        await shell.app.run_async(set_exception_handler=False)
    finally:
        shell.closing = True
        for task in tasks:
            task.cancel()
        for task in tasks:
            try:
                await task
            except asyncio.CancelledError:
                pass
        if shell.foreground is not None:
            await shell.foreground


def number(value: object) -> float:
    if not isinstance(value, (float, int)) or isinstance(value, bool):
        raise ConfigurationError(f"Invalid numeric resource counter: {value!r}")
    return float(value)


def counters(path: Path) -> Counters:
    data: JsonObject = as_object(
        json_value(json.loads(path.read_text()), "resource counters"), "counters"
    )
    return Counters(
        number(data["cpu"]),
        number(data["wall"]),
        number(data["peak_mib"]),
        as_int(data["paints"], "paints"),
        as_int(data["scroll_limit"], "scroll_limit"),
    )


def fresh_counters(terminal: Terminal, path: Path) -> Counters:
    """Await a new counter sample so earlier scroll paints cannot count as hover paints."""
    requested: float = time.monotonic()
    terminal.until(lambda: counters(path).wall >= requested, 3.0)
    return counters(path)


def scroll_latency(terminal: Terminal) -> float:
    target: str = terminal.screen.display[13][2:80]
    started: float = time.monotonic()
    terminal.send(mouse_packet(65, (20, 10), "M") * 3)
    terminal.until(lambda: terminal.screen.display[4][2:80] == target, 5.0)
    return (time.monotonic() - started) * 1000


def measure_view(terminal: Terminal, view: str, title: str, path: Path) -> Measurement:
    terminal.command("/" + view, title)
    wait_for_paint(terminal, 2.0)
    before: Counters = counters(path)
    wait_for_paint(terminal, 10.0)
    after: Counters = counters(path)
    samples: list[float] = []
    if after.scroll_limit >= 9:
        for _ in range(6):
            samples.append(scroll_latency(terminal))
            terminal.send("\x1b[1;5H")
            wait_for_paint(terminal, 0.1)
    wait_for_paint(terminal, 0.6)
    hover_before: Counters = fresh_counters(terminal, path)
    terminal.send(mouse_packet(35, (20, 10), "M") * 100)
    wait_for_paint(terminal, 1.2)
    hover_after: Counters = fresh_counters(terminal, path)
    return Measurement(
        view,
        100 * (after.cpu - before.cpu) / (after.wall - before.wall),
        after.peak_mib,
        after.paints - before.paints,
        statistics.median(samples) if samples else 0.0,
        hover_after.paints - hover_before.paints,
    )


def verify_rules_navigation(terminal: Terminal) -> None:
    """Verify visible completions and both rule views against the real read-only controller."""
    terminal.command("/help", "Your local Clash workspace")
    resize(terminal, 80, 24)
    terminal.expect("/sites → current websites")
    terminal.expect("/rules view → all rules")
    terminal.send("/rules ")
    terminal.expect("suggestions · Tab")
    terminal.expect("All routing rules")
    terminal.expect("Active websites and matched rules")
    if "suggestions" in terminal.screen.display[-2]:
        raise AssertionError("Completions covered the input frame instead of appearing above it")
    terminal.send("v\t")
    terminal.expect("› /rules view")
    terminal.send("\r")
    terminal.expect("Viewing ")
    terminal.expect("Ordered routing rules")
    terminal.command("/rules view __clashctl_no_such_rule__", "Filtering rules by ")
    terminal.expect("Filter: __clashctl_no_such_rule__")
    terminal.expect("Showing 0/0 matches")
    terminal.command("/rules view", "Viewing ")
    if "Filter: __clashctl_no_such_rule__" in terminal.text():
        raise AssertionError("/rules view retained the previous keyword filter")
    terminal.command("/rules sites", "Live Clash traffic.")
    terminal.expect("Live Clash connections")
    terminal.expect("Website / address")
    terminal.expect("Matched rule")
    terminal.command("/help", "Your local Clash workspace")
    terminal.send("/si")
    terminal.expect("suggestions · Tab")
    terminal.expect("Current websites and their matched routing rules")
    terminal.send("\t\r")
    terminal.expect("Live Clash traffic.")
    terminal.expect("Live Clash connections")
    resize(terminal, 124, 42)
    terminal.command("/nodes", "Cached view.")
    terminal.expect("Showing:")


def measure_shell(source: Path | None) -> tuple[Measurement, ...]:
    command: list[str] = ["/usr/bin/env", "NO_COLOR=", "PROMPT_TOOLKIT_COLOR_DEPTH=DEPTH_24_BIT"]
    if source is not None:
        command.append("PYTHONPATH=" + str(source))
    command.extend([sys.executable, str(Path(__file__).resolve()), "--fixture"])
    with tempfile.TemporaryDirectory(prefix="clashctl-performance-") as temporary:
        directory: Path = Path(temporary)
        with Terminal(command, directory) as terminal:
            terminal.expect("Showing:")
            terminal.expect("Ctrl+D quit")
            terminal.until(lambda: (directory / "resources.json").exists(), 5.0)
            if source is None:
                verify_rules_navigation(terminal)
            measurements: tuple[Measurement, ...] = tuple(
                measure_view(terminal, view, title, directory / "resources.json")
                for view, title in (
                    ("nodes", "Showing:"),
                    ("rules", "Ordered routing rules"),
                    ("sites", "Live Clash connections"),
                    ("help", "Your local Clash workspace"),
                )
            )
            terminal.quit()
            return measurements


def verify_limits(measurements: tuple[Measurement, ...]) -> None:
    for measurement in measurements:
        if measurement.cpu_percent >= 1.0:
            raise AssertionError(f"Idle CPU target missed: {measurement}")
        if measurement.scroll_ms >= 100.0:
            raise AssertionError(f"Scrolling took too long: {measurement}")
        if measurement.view != "sites" and measurement.hover_paints > 1:
            raise AssertionError(f"Hover events triggered excessive redraws: {measurement}")


def main() -> None:
    parser: argparse.ArgumentParser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fixture", action="store_true")
    parser.add_argument("--source", type=Path)
    arguments: argparse.Namespace = parser.parse_args()
    if arguments.fixture:
        asyncio.run(run_fixture())
        return
    measurements: tuple[Measurement, ...] = measure_shell(arguments.source)
    for measurement in measurements:
        print(
            f"{measurement.view}: CPU={measurement.cpu_percent:.2f}%, "
            f"peak={measurement.peak_mib:.1f} MiB, idle paints={measurement.idle_paints}, "
            f"scroll median={measurement.scroll_ms:.1f}ms, hover paints={measurement.hover_paints}"
        )
    if arguments.source is None:
        verify_limits(measurements)
        print("PASS: visible completion, all rules, filtered rules, and active website routes")
        print("PASS: all views idle below 1% CPU and scrolling responds below 100ms")


if __name__ == "__main__":
    main()
