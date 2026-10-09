"""Owned background scans with cooperative cancellation, bounded traffic, and durable results."""

import fcntl
import logging
import re
import threading
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from queue import SimpleQueue
from types import TracebackType
from typing import IO, Literal

from clashctl.benchmark import run_benchmark
from clashctl.cache import CachedReport, age_seconds, parse_time, read_cache, write_cache
from clashctl.config import source_digest
from clashctl.controller import ClashClient
from clashctl.isolation import candidate_names
from clashctl.models import (
    BenchmarkCancelled,
    BenchmarkOptions,
    BenchmarkReport,
    ClashError,
    ConfigurationError,
    Sample,
    Settings,
    Snapshot,
    selection_path,
)
from clashctl.service_checks import ProbeEvent, ProbeStatusEvent


@dataclass(frozen=True)
class MonitorOptions:
    interval_seconds: float
    rounds: int
    size_bytes: int
    timeout: float
    attempts: int
    url: str
    include: str | None
    directory: Path


@dataclass(frozen=True)
class GroupChoice:
    name: str
    nodes: tuple[str, ...]


@dataclass(frozen=True)
class LiveContext:
    snapshot: Snapshot
    nodes: tuple[str, ...]
    groups: tuple[GroupChoice, ...]
    digest: str


@dataclass(frozen=True)
class WatchStatus:
    phase: Literal["starting", "scanning", "idle", "paused", "error", "stopping"]
    completed: int
    total: int
    message: str
    next_at: str | None


@dataclass(frozen=True)
class ContextEvent:
    context: LiveContext


@dataclass(frozen=True)
class CacheEvent:
    cache: CachedReport


@dataclass(frozen=True)
class ScanEvent:
    report: BenchmarkReport


@dataclass(frozen=True)
class StatusEvent:
    status: WatchStatus


@dataclass(frozen=True)
class NoticeEvent:
    message: str


type MonitorEvent = (
    ContextEvent
    | CacheEvent
    | ScanEvent
    | StatusEvent
    | NoticeEvent
    | ProbeEvent
    | ProbeStatusEvent
)


def default_options() -> MonitorOptions:
    return MonitorOptions(
        3600.0,
        2,
        1024 * 1024,
        10.0,
        2,
        "https://speed.cloudflare.com/__down?bytes={bytes}",
        None,
        Path("reports").resolve(),
    )


def load_context(settings: Settings) -> LiveContext:
    snapshot: Snapshot = ClashClient(settings).snapshot()
    nodes: tuple[str, ...] = candidate_names(settings.config_path, snapshot.proxies, "GLOBAL")
    groups: tuple[GroupChoice, ...] = tuple(
        GroupChoice(proxy.name, available)
        for proxy in snapshot.proxies
        if proxy.members and proxy.kind in {"Selector", "URLTest", "Fallback"}
        for available in (candidate_names(settings.config_path, snapshot.proxies, proxy.name),)
        if available
    )
    return LiveContext(snapshot, nodes, groups, source_digest(settings.config_path))


def matching_nodes(context: LiveContext, options: MonitorOptions) -> tuple[str, ...]:
    pattern: re.Pattern[str] | None = (
        None if options.include is None else re.compile(options.include)
    )
    return tuple(node for node in context.nodes if pattern is None or pattern.search(node))


def monitored_nodes(context: LiveContext, options: MonitorOptions) -> tuple[str, ...]:
    nodes: tuple[str, ...] = matching_nodes(context, options)
    if not nodes:
        raise ConfigurationError(f"No monitor nodes match include={options.include!r}")
    return nodes


def cache_matches(cache: CachedReport, context: LiveContext, options: MonitorOptions) -> bool:
    return report_matches(cache.report, context, options)


def report_matches(report: BenchmarkReport, context: LiveContext, options: MonitorOptions) -> bool:
    return (
        report.source_digest == context.digest
        and report.url == options.url
        and report.rounds == options.rounds
        and report.size_bytes == options.size_bytes
        and set(report.requested_nodes) == set(matching_nodes(context, options))
    )


def group_nodes(context: LiveContext, name: str) -> tuple[str, ...]:
    for group in context.groups:
        if group.name == name:
            return group.nodes
    raise ConfigurationError(f"Unknown working group: {name}. Use /groups to refresh your choice.")


class MonitorLease:
    """Allow one active scheduler per cache directory across terminal sessions."""

    def __init__(self, directory: Path) -> None:
        self.directory: Path = directory
        self.file: IO[str] | None = None

    def __enter__(self) -> "MonitorLease":
        self.directory.mkdir(parents=True, exist_ok=True)
        self.file = (self.directory / "background.lock").open("a+", encoding="utf-8")
        try:
            fcntl.flock(self.file.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            self.file.close()
            raise ConfigurationError(
                f"Another clashctl shell owns {self.directory}. Close that session first."
            ) from error
        return self

    def close(self) -> None:
        if self.file is not None:
            self.file.close()

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        self.close()


class EventLogHandler(logging.Handler):
    """Route connector warnings into the terminal event feed instead of corrupting the screen."""

    def __init__(self, events: SimpleQueue[MonitorEvent]) -> None:
        super().__init__()
        self.events: SimpleQueue[MonitorEvent] = events

    def emit(self, record: logging.LogRecord) -> None:
        context: str = " ".join(
            f"{key}={record.__dict__[key]}"
            for key in ("node", "round", "attempt", "method", "path", "error")
            if key in record.__dict__
        )
        self.events.put(NoticeEvent(f"{record.levelname} {record.getMessage()} {context}"))


class BackgroundMonitor:
    """Own a single cancellable worker thread and its isolated real Mihomo scan process."""

    def __init__(
        self, settings: Settings, options: MonitorOptions, events: SimpleQueue[MonitorEvent]
    ) -> None:
        self.settings: Settings = settings
        self.options: MonitorOptions = options
        self.events: SimpleQueue[MonitorEvent] = events
        self.cancel: threading.Event = threading.Event()
        self.stop: threading.Event = threading.Event()
        self.wake: threading.Event = threading.Event()
        self.lock: threading.Lock = threading.Lock()
        self.paused: bool = False
        self.requested: bool = False
        self.running: bool = False
        self.thread: threading.Thread | None = None
        self.measured_at: tuple[tuple[str, str], ...] = ()
        self.status: WatchStatus = WatchStatus("starting", 0, 0, "Loading local measurements", None)

    def start(self) -> None:
        self.thread = threading.Thread(target=self.run, name="clashctl-monitor", daemon=False)
        self.thread.start()

    def publish(self, status: WatchStatus) -> None:
        self.status = status
        self.events.put(StatusEvent(status))

    def scan_now(self) -> None:
        with self.lock:
            if self.paused:
                raise ConfigurationError("Background scans are paused. Use /watch resume first.")
            if self.running:
                raise ConfigurationError(
                    "A background scan is already running. View /watch status."
                )
            self.requested = True
            self.wake.set()

    def pause(self) -> None:
        with self.lock:
            self.paused = True
            self.cancel.set()
            self.wake.set()

    def refresh_configuration(self) -> None:
        """Cancel a scan with an obsolete digest and queue a refresh, respecting pause."""
        with self.lock:
            self.cancel.set()
            self.requested = True
            self.wake.set()

    def resume(self) -> None:
        with self.lock:
            self.paused = False
            self.requested = True
            self.wake.set()

    def set_interval(self, seconds: float) -> None:
        if not 6.0 <= seconds <= 86400.0:
            raise ConfigurationError("Interval must be between 0.1 and 1440 minutes")
        with self.lock:
            self.options = replace(self.options, interval_seconds=seconds)
            self.wake.set()

    def request_stop(self) -> None:
        with self.lock:
            self.stop.set()
            self.cancel.set()
            self.wake.set()

    def close(self) -> None:
        self.request_stop()
        if self.thread is not None:
            self.thread.join()

    def progress(self, sample: Sample, completed: int, total: int) -> None:
        if sample.round_number == self.options.rounds:
            self.measured_at = (*self.measured_at, (sample.node, datetime.now(UTC).isoformat()))
        outcome: str = "failed" if sample.error else f"{sample.mbps:.1f} Mbps"
        self.publish(WatchStatus("scanning", completed, total, f"{sample.node} · {outcome}", None))

    def scan(self, options: MonitorOptions) -> CachedReport:
        context: LiveContext = load_context(self.settings)
        self.events.put(ContextEvent(context))
        nodes: tuple[str, ...] = monitored_nodes(context, options)
        for node in nodes:
            selection_path(context.snapshot.proxies, "GLOBAL", node)
        self.measured_at = ()
        self.publish(WatchStatus("scanning", 0, len(nodes) * options.rounds, "Starting scan", None))
        parameters: BenchmarkOptions = BenchmarkOptions(
            "GLOBAL",
            nodes,
            options.rounds,
            options.size_bytes,
            options.url,
            options.timeout,
            options.attempts,
            options.directory / "background-active.json",
        )
        report: BenchmarkReport = run_benchmark(
            self.settings,
            context.snapshot,
            parameters,
            self.progress,
            self.node_finished,
            self.cancel.is_set,
        )
        cache: CachedReport = CachedReport(report, self.measured_at)
        write_cache(cache, options.directory / "background-cache.json")
        return cache

    def node_finished(self, report: BenchmarkReport) -> None:
        self.events.put(ScanEvent(report))

    def run(self) -> None:
        last_started: datetime | None = None
        failure: str | None = None
        try:
            cached: CachedReport | None = read_cache(
                self.options.directory / "background-cache.json"
            )
            if cached is not None:
                self.events.put(CacheEvent(cached))
                context: LiveContext = load_context(self.settings)
                self.events.put(ContextEvent(context))
                if cache_matches(cached, context, self.options):
                    age_seconds(cached.report.started_at, datetime.now(UTC))
                    last_started = parse_time(cached.report.started_at)
        except (ClashError, OSError) as error:
            failure = str(error)
            self.events.put(NoticeEvent(str(error)))
        while not self.stop.is_set():
            with self.lock:
                options: MonitorOptions = self.options
                paused: bool = self.paused
                requested: bool = self.requested
            remaining: float = (
                0.0
                if last_started is None
                else max(
                    0.0,
                    options.interval_seconds - (datetime.now(UTC) - last_started).total_seconds(),
                )
            )
            if paused or (remaining > 0 and not requested):
                next_at: str | None = (
                    None
                    if paused
                    else (datetime.now(UTC) + timedelta(seconds=remaining)).isoformat()
                )
                self.publish(
                    WatchStatus(
                        "paused" if paused else "idle" if failure is None else "error",
                        self.status.completed,
                        self.status.total,
                        "Background scans paused"
                        if paused
                        else "Cached measurements ready"
                        if failure is None
                        else failure,
                        next_at,
                    )
                )
                # Recheck wall time after laptop sleep instead of extending a stale scan deadline.
                self.wake.wait(timeout=None if paused else min(remaining, 30.0))
                self.wake.clear()
                continue
            with self.lock:
                if self.stop.is_set() or self.paused:
                    continue
                self.running = True
                self.requested = False
                self.cancel.clear()
            last_started = datetime.now(UTC)
            try:
                cache: CachedReport = self.scan(options)
                self.events.put(CacheEvent(cache))
                failure = None
            except BenchmarkCancelled as error:
                self.events.put(NoticeEvent(str(error)))
            except (ClashError, OSError) as error:
                failure = str(error)
                self.publish(WatchStatus("error", 0, 0, str(error), None))
                self.events.put(NoticeEvent(f"Scan failed: {error}. Use /bench to retry."))
            finally:
                with self.lock:
                    self.running = False
        self.publish(WatchStatus("stopping", 0, 0, "Background worker stopped", None))
