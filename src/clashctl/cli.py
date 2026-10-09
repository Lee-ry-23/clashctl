"""Command help contains the user-facing workflow and benchmark definitions."""

import json
import logging
import re
import signal
import sys
from collections.abc import Callable
from dataclasses import asdict, replace
from pathlib import Path
from types import FrameType
from typing import NoReturn, TextIO
from urllib.parse import quote

import click

from clashctl.benchmark import apply_winner, measurement_url, never_cancel, run_benchmark
from clashctl.config import load_settings
from clashctl.controller import ClashClient
from clashctl.display import (
    print_groups,
    print_node_finished,
    print_nodes,
    print_results,
    print_sample,
    print_status,
)
from clashctl.isolation import candidate_names
from clashctl.models import (
    BenchmarkOptions,
    BenchmarkReport,
    ClashError,
    ConfigurationError,
    MeasurementError,
    Settings,
    Snapshot,
    choose_group,
    proxy_by_name,
    selection_path,
)
from clashctl.monitor import MonitorOptions, default_options
from clashctl.shell import run_shell


class JsonLogFormatter(logging.Formatter):
    """Render structured connector warnings with their actionable context."""

    def format(self, record: logging.LogRecord) -> str:
        fields: dict[str, object] = {
            key: record.__dict__[key]
            for key in ("method", "path", "url", "attempt", "node", "round", "error")
            if key in record.__dict__
        }
        return json.dumps(
            {"level": record.levelname, "event": record.getMessage(), **fields}, ensure_ascii=False
        )


def configure_logging() -> None:
    handler: logging.StreamHandler[TextIO] = logging.StreamHandler(sys.stderr)
    handler.setFormatter(JsonLogFormatter())
    logging.basicConfig(level=logging.WARNING, handlers=[handler])


@click.group(invoke_without_command=True, context_settings={"help_option_names": ["-h", "--help"]})
@click.option(
    "--config", type=click.Path(path_type=Path), help="Clash runtime YAML; auto-detected on macOS."
)
@click.option("--controller", help="HTTP control API address; read from runtime YAML by default.")
@click.option("--secret-env", help="Name of an environment variable containing the API secret.")
@click.option(
    "--core", type=click.Path(path_type=Path), help="Mihomo executable; auto-detected on macOS."
)
@click.option("--api-timeout", type=click.FloatRange(min=0.1), default=5.0, show_default=True)
@click.pass_context
def cli(
    context: click.Context,
    config: Path | None,
    controller: str | None,
    secret_env: str | None,
    core: Path | None,
    api_timeout: float,
) -> None:
    """Open the interactive Clash shell, or run a command directly.

    Run: uv sync; uv run clashctl

    Direct commands remain available: clashctl status; clashctl best

    macOS auto-discovery reads the runtime YAML and its API secret locally.
    Other installations need --config and --core. Secrets are never printed.
    """
    configure_logging()
    context.obj = load_settings(config, controller, secret_env, core, api_timeout)
    if context.invoked_subcommand is None:
        run_shell(context.obj, default_options())


@cli.command("menu")
@click.pass_obj
def interactive_menu(settings: Settings) -> None:
    """Open the command shell; retained as an alias for earlier installations."""
    run_shell(settings, default_options())


@cli.command("shell")
@click.option(
    "--interval-minutes", type=click.FloatRange(0.1, 1440), default=60.0, show_default=True
)
@click.option("--rounds", type=click.IntRange(2, 20), default=2, show_default=True)
@click.option("--size-mib", type=click.IntRange(1, 128), default=1, show_default=True)
@click.option("--timeout", type=click.FloatRange(1, 120), default=10.0, show_default=True)
@click.option("--include", help="Limit scheduled downloads to a node-name regular expression.")
@click.option("--cache-dir", type=click.Path(path_type=Path), default="reports", show_default=True)
@click.option(
    "--url", default="https://speed.cloudflare.com/__down?bytes={bytes}", show_default=True
)
@click.pass_obj
def shell_command(
    settings: Settings,
    interval_minutes: float,
    rounds: int,
    size_mib: int,
    timeout: float,
    include: str | None,
    cache_dir: Path,
    url: str,
) -> None:
    """Full-screen English commands, Tab completion, cached rankings, and hourly downloads.

    All real nodes are monitored through private fixed-node listeners by default.
    Scans never change live selections. /best explicitly applies fresh cached results.
    /watch pause/resume controls downloads; closing the shell stops the worker.
    A fresh on-disk cache is reused on restart instead of starting another full scan.
    """
    compile_pattern(include)
    measurement_url(url, size_mib * 1024 * 1024, "validation")
    options: MonitorOptions = replace(
        default_options(),
        interval_seconds=interval_minutes * 60,
        rounds=rounds,
        size_bytes=size_mib * 1024 * 1024,
        timeout=timeout,
        include=include,
        directory=cache_dir.resolve(),
        url=url,
    )
    run_shell(settings, options)


@cli.command()
@click.pass_obj
def status(settings: Settings) -> None:
    """Read live mode, ports, core version, rule count, and every group selection."""
    snapshot: Snapshot = ClashClient(settings).snapshot()
    print_status(settings, snapshot)


@cli.command()
@click.pass_obj
def groups(settings: Settings) -> None:
    """List groups, nested selections, and automatic-group pins."""
    print_groups(ClashClient(settings).snapshot())


@cli.command()
@click.option("--group", help="Group to expand; infer from the current mode when unambiguous.")
@click.pass_obj
def nodes(settings: Settings, group: str | None) -> None:
    """List actual candidate nodes and protocols, excluding subscription display labels."""
    snapshot: Snapshot = ClashClient(settings).snapshot()
    target: str = choose_group(snapshot, group)
    candidates: tuple[str, ...] = candidate_names(settings.config_path, snapshot.proxies, target)
    print_nodes(snapshot, target, candidates)


@cli.command("inspect")
@click.pass_obj
def inspect_state(settings: Settings) -> None:
    """Export a credential-free live snapshot as JSON for scripts."""
    click.echo(json.dumps(asdict(ClashClient(settings).snapshot()), ensure_ascii=False, indent=2))


@cli.command()
@click.argument("value", type=click.Choice(["rule", "global", "direct"]))
@click.pass_obj
def mode(settings: Settings, value: str) -> None:
    """Change the live mode. Example: clashctl mode rule."""
    ClashClient(settings).set_mode(value)
    click.echo(f"Mode verified: {value}")


@cli.command()
@click.argument("node")
@click.option("--group", help="Target group; infer only when unambiguous.")
@click.pass_obj
def switch(settings: Settings, node: str, group: str | None) -> None:
    """Select a node, verify the selection, and retain the current mode.

    Existing connections keep their current routes. New connections use the new selection.
    Selecting within URLTest/Fallback pins it; use 'unpin GROUP' to restore automatic choice.
    """
    client: ClashClient = ClashClient(settings)
    snapshot: Snapshot = client.snapshot()
    target: str = choose_group(snapshot, group)
    path: tuple[tuple[str, str], ...] = client.select_node(target, node)
    for group_name, member in path:
        click.echo(f"Verified: {group_name} → {member}")
    click.echo(f"Mode retained: {snapshot.mode}. Existing connections were not closed.")


@cli.command()
@click.argument("group")
@click.pass_obj
def unpin(settings: Settings, group: str) -> None:
    """Remove the fixed choice from an automatic URLTest/Fallback group."""
    client: ClashClient = ClashClient(settings)
    proxy = proxy_by_name(client.proxies(), group)
    if proxy.kind not in {"URLTest", "Fallback"}:
        raise ConfigurationError(f"{group} is not a URLTest/Fallback group")
    client.request("DELETE", f"/proxies/{quote(group, safe='')}", {}, None)
    after = proxy_by_name(client.proxies(), group)
    if after.fixed:
        raise ConfigurationError(f"Could not verify that {group} was unpinned")
    click.echo(f"Automatic selection restored: {group}")


def benchmark_options[**P, R](function: Callable[P, R]) -> Callable[P, R]:
    decorators: tuple[Callable[[Callable[P, R]], Callable[P, R]], ...] = (
        click.option("--group", help="Group to test; auto-infer from the live mode."),
        click.option("--include", help="Node-name regular expression to include."),
        click.option("--exclude", help="Node-name regular expression to exclude."),
        click.option("--rounds", type=click.IntRange(min=1, max=20), default=3, show_default=True),
        click.option(
            "--size-mib", type=click.IntRange(min=1, max=128), default=4, show_default=True
        ),
        click.option(
            "--timeout", type=click.FloatRange(min=1, max=120), default=30.0, show_default=True
        ),
        click.option("--attempts", type=click.IntRange(min=1, max=3), default=2, show_default=True),
        click.option(
            "--url",
            default="https://speed.cloudflare.com/__down?bytes={bytes}",
            show_default=True,
            help="HTTPS download target; {bytes} is replaced by the sample size.",
        ),
        click.option("--output", type=click.Path(path_type=Path), default="reports/latest.json"),
    )
    decorated: Callable[P, R] = function
    for decorator in reversed(decorators):
        decorated = decorator(decorated)
    return decorated


def compile_pattern(expression: str | None) -> re.Pattern[str] | None:
    if expression is None:
        return None
    try:
        return re.compile(expression)
    except re.error as error:
        raise ConfigurationError(f"Invalid node-name regex {expression}: {error}") from error


def execute_benchmark(
    settings: Settings,
    group: str | None,
    include: str | None,
    exclude: str | None,
    rounds: int,
    size_mib: int,
    timeout: float,
    attempts: int,
    url: str,
    output: Path,
) -> BenchmarkReport:
    snapshot: Snapshot = ClashClient(settings).snapshot()
    target: str = choose_group(snapshot, group)
    include_pattern: re.Pattern[str] | None = compile_pattern(include)
    exclude_pattern: re.Pattern[str] | None = compile_pattern(exclude)
    expanded: tuple[str, ...] = candidate_names(settings.config_path, snapshot.proxies, target)
    candidates: tuple[str, ...] = tuple(
        name
        for name in expanded
        if (include_pattern is None or include_pattern.search(name))
        and (exclude_pattern is None or not exclude_pattern.search(name))
    )
    if not candidates:
        raise ConfigurationError("No candidate nodes match the requested group and filters")
    for node in candidates:
        selection_path(snapshot.proxies, target, node)
    measurement_url(url, size_mib * 1024 * 1024, "validation")
    click.echo(f"Group: {target} | live mode: {snapshot.mode} | nodes: {len(candidates)}")
    click.echo(
        f"Payload: {len(candidates) * rounds * size_mib} MiB if all first attempts succeed; "
        f"up to about {len(candidates) * rounds * size_mib * attempts} MiB with retries."
    )
    click.echo(
        "Using private fixed-node listeners. "
        "Live mode and selections stay unchanged during testing."
    )
    options: BenchmarkOptions = BenchmarkOptions(
        target, candidates, rounds, size_mib * 1024 * 1024, url, timeout, attempts, output.resolve()
    )
    report: BenchmarkReport = run_benchmark(
        settings, snapshot, options, print_sample, print_node_finished, never_cancel
    )
    print_results(report)
    click.echo(f"Report: {output.resolve()}")
    if report.winner is None:
        raise MeasurementError("No node passed every round; report saved and live state unchanged")
    return report


@cli.command()
@benchmark_options
@click.pass_obj
def bench(
    settings: Settings,
    group: str | None,
    include: str | None,
    exclude: str | None,
    rounds: int,
    size_mib: int,
    timeout: float,
    attempts: int,
    url: str,
    output: Path,
) -> None:
    """Benchmark and rank nodes, saving partial results after each sample. Do not switch.

    Example: clashctl bench --include 'JP|HK|SG' --size-mib 8

    Throughput includes connection, handshake, and transfer time. Nodes download sequentially.
    Each node finishes all rounds and its OpenAI probe before the next node starts.
    CV describes throughput dispersion, not packet loss.
    Use a larger --size-mib for sustained downloads and --url for your relevant destination.
    Ctrl-C stops the private core; completed samples remain in the report.
    TUN must be off so it cannot intercept the private core's outgoing traffic.
    """
    execute_benchmark(
        settings, group, include, exclude, rounds, size_mib, timeout, attempts, url, output
    )


@cli.command()
@benchmark_options
@click.pass_obj
def best(
    settings: Settings,
    group: str | None,
    include: str | None,
    exclude: str | None,
    rounds: int,
    size_mib: int,
    timeout: float,
    attempts: int,
    url: str,
    output: Path,
) -> None:
    """Benchmark, pick a repeatable winner, then switch the target group and verify it.

    Requires at least two rounds. Current mode and existing connections are retained.
    If subscription, mode, or group selection changes during testing, switching is refused.
    The winner is specific to this test destination, sample size, and time of day.
    """
    if rounds < 2:
        raise ConfigurationError(
            "'best' requires at least 2 rounds; use 'bench' for a quick smoke run"
        )
    report: BenchmarkReport = execute_benchmark(
        settings, group, include, exclude, rounds, size_mib, timeout, attempts, url, output
    )
    for group_name, member in apply_winner(settings, report):
        click.echo(f"Applied and verified: {group_name} → {member}")
    click.echo(f"Mode retained: {report.live_mode}. New connections use the selected node.")


def terminate(signum: int, frame: FrameType | None) -> NoReturn:
    """Exit on SIGTERM while unwinding temporary resources and selection transactions."""
    raise SystemExit(128 + signum)


def main() -> None:
    signal.signal(signal.SIGTERM, terminate)
    try:
        cli()
    except ClashError as error:
        click.echo(f"Error: {error}", err=True)
        raise SystemExit(1) from error


if __name__ == "__main__":
    main()
