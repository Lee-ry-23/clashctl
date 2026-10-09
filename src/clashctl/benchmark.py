"""Sequential, repeated downloads with transparent ranking and durable partial reports."""

import json
import logging
import math
import statistics
import time
import uuid
from collections.abc import Callable
from dataclasses import asdict
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

import httpx

from clashctl.config import source_digest
from clashctl.controller import ClashClient
from clashctl.isolation import IsolatedCore
from clashctl.models import (
    BenchmarkCancelled,
    BenchmarkOptions,
    BenchmarkReport,
    ConfigurationError,
    GroupSelection,
    MeasurementError,
    NodeResult,
    OpenAIResult,
    Sample,
    Settings,
    Snapshot,
    StateConflictError,
    as_object,
    json_value,
    proxy_by_name,
    selection_path,
)
from clashctl.persistence import write_json_file
from clashctl.probes import HttpsProbe, check_openai


def never_cancel() -> bool:
    """One-shot commands use normal signal interruption rather than a worker stop token."""
    return False


def check_cancelled(cancelled: Callable[[], bool]) -> None:
    if cancelled():
        raise BenchmarkCancelled("Benchmark stopped; completed samples remain in the active report")


def measurement_url(template: str, size_bytes: int, nonce: str) -> str:
    url: str = template.replace("{bytes}", str(size_bytes))
    parts = urlsplit(url)
    if parts.scheme != "https" or not parts.hostname:
        raise ConfigurationError("Benchmark URL must be an HTTPS URL")
    if parts.username or parts.password:
        raise ConfigurationError("Benchmark URL must not contain credentials")
    if "{" in url or "}" in url:
        raise ConfigurationError("Only the {bytes} placeholder is supported in --url")
    query: str = urlencode([*parse_qsl(parts.query, keep_blank_values=True), ("clashctl", nonce)])
    return urlunsplit((parts.scheme, parts.netloc, parts.path, query, ""))


class DownloadClient:
    """Measure raw network bytes through one explicit fixed-node HTTP proxy."""

    def __init__(self, proxy_url: str, timeout: float, cancelled: Callable[[], bool]) -> None:
        self.proxy_url: str = proxy_url
        self.timeout: float = timeout
        self.cancelled: Callable[[], bool] = cancelled

    def download(self, url: str, size_bytes: int) -> tuple[int, float, float]:
        check_cancelled(self.cancelled)
        headers: dict[str, str] = {
            "Accept-Encoding": "identity",
            "Cache-Control": "no-cache, no-store",
            "Range": f"bytes=0-{size_bytes - 1}",
            "User-Agent": "clashctl/0.1",
        }
        read_timeout: float = min(self.timeout, 5.0)
        received: int = 0
        started: float = time.perf_counter()
        try:
            with httpx.Client(
                proxy=self.proxy_url,
                trust_env=False,
                follow_redirects=False,
                timeout=httpx.Timeout(read_timeout, connect=min(self.timeout, 5.0)),
            ) as client:
                with client.stream("GET", url, headers=headers) as response:
                    if response.status_code not in {200, 206}:
                        body: bytes = next(response.iter_raw(chunk_size=512), b"")
                        raise MeasurementError(
                            f"GET {url}: HTTP {response.status_code}, "
                            f"response={body.decode('utf-8', errors='replace')[:300]}"
                        )
                    encoding: str = response.headers.get("content-encoding", "identity")
                    if encoding.lower() != "identity":
                        raise MeasurementError(f"GET {url}: compressed response {encoding}")
                    first_byte: float | None = None
                    for chunk in response.iter_raw():
                        check_cancelled(self.cancelled)
                        now: float = time.perf_counter()
                        if now - started > self.timeout:
                            raise MeasurementError(
                                f"GET {url}: total timeout {self.timeout}s after {received} bytes"
                            )
                        if first_byte is None:
                            first_byte = (now - started) * 1000.0
                        received += min(len(chunk), size_bytes - received)
                        if received >= size_bytes:
                            elapsed: float = now - started
                            return received, elapsed, first_byte
                    raise MeasurementError(
                        f"GET {url}: incomplete body, received {received}/{size_bytes} bytes"
                    )
        except httpx.TransportError as error:
            raise MeasurementError(
                f"GET {url} via {self.proxy_url}: {type(error).__name__}: {error}; "
                f"received={received}/{size_bytes} bytes"
            ) from error


def measure_sample(
    client: DownloadClient, node: str, round_number: int, options: BenchmarkOptions
) -> Sample:
    """Retry failed network calls, then surface the last error as a failed sample."""
    for attempt in range(1, options.attempts + 1):
        check_cancelled(client.cancelled)
        url: str = measurement_url(options.url, options.size_bytes, uuid.uuid4().hex)
        try:
            received, elapsed, first_byte = client.download(url, options.size_bytes)
        except MeasurementError as error:
            if attempt == options.attempts:
                raise error
            logging.getLogger(__name__).warning(
                "download_retry",
                extra={
                    "node": node,
                    "round": round_number,
                    "attempt": attempt,
                    "error": str(error),
                },
            )
            time.sleep(0.2)
        else:
            return Sample(
                node,
                round_number,
                attempt,
                received,
                elapsed,
                first_byte,
                received * 8.0 / elapsed / 1_000_000.0,
                None,
            )
    raise MeasurementError(f"No measurement attempts for {node}")


def percentile(values: tuple[float, ...], fraction: float) -> float:
    ordered: tuple[float, ...] = tuple(sorted(values))
    position: float = (len(ordered) - 1) * fraction
    lower: int = math.floor(position)
    upper: int = math.ceil(position)
    return ordered[lower] + (ordered[upper] - ordered[lower]) * (position - lower)


def summarize(
    node: str, samples: tuple[Sample, ...], rounds: int, openai: OpenAIResult | None
) -> NodeResult:
    """Score = lower quartile of round throughput × first-attempt success fraction.

    Failed and unfinished rounds contribute zero throughput. Automatic selection requires
    every round to finish, so one lucky download cannot win over repeatable measurements.
    First-byte time includes connection setup and the first received network block; it is
    an application response measurement, not ICMP RTT. Dispersion is population CV.
    """
    successful: tuple[Sample, ...] = tuple(sample for sample in samples if sample.error is None)
    rates: tuple[float, ...] = tuple(sample.mbps for sample in samples) + (0.0,) * (
        rounds - len(samples)
    )
    response_times: tuple[float, ...] = tuple(
        sample.first_byte_ms for sample in successful if sample.first_byte_ms is not None
    )
    average: float = statistics.mean(rates)
    conservative: float = percentile(rates, 0.25)
    clean_successes: int = sum(sample.error is None and sample.attempts == 1 for sample in samples)
    return NodeResult(
        node=node,
        successful_rounds=len(successful),
        total_rounds=rounds,
        median_mbps=statistics.median(rates),
        conservative_mbps=conservative,
        variation_percent=statistics.pstdev(rates) / average * 100.0 if average > 0.0 else 0.0,
        median_first_byte_ms=statistics.median(response_times) if response_times else None,
        score=conservative * clean_successes / rounds,
        eligible=len(successful) == rounds and clean_successes > 0,
        samples=samples,
        openai=openai,
    )


def rank_results(results: tuple[NodeResult, ...]) -> tuple[NodeResult, ...]:
    return tuple(
        sorted(
            results,
            key=lambda item: (
                not item.eligible,
                -item.score,
                -item.median_mbps,
                math.inf if item.median_first_byte_ms is None else item.median_first_byte_ms,
                item.node,
            ),
        )
    )


def write_report(report: BenchmarkReport, path: Path) -> None:
    """Replace reports atomically; no API keys, node credentials, or subscription URLs."""
    write_json_file(as_object(json_value(asdict(report), "report"), "report"), path)


def report_from_samples(
    snapshot: Snapshot,
    options: BenchmarkOptions,
    started_at: str,
    digest: str,
    samples: tuple[Sample, ...],
    services: dict[str, OpenAIResult],
) -> BenchmarkReport:
    results: tuple[NodeResult, ...] = rank_results(
        tuple(
            summarize(
                node,
                tuple(sample for sample in samples if sample.node == node),
                options.rounds,
                services.get(node),
            )
            for node in options.nodes
        )
    )
    winner: str | None = next((result.node for result in results if result.eligible), None)
    complete: bool = len(samples) == len(options.nodes) * options.rounds
    return BenchmarkReport(
        started_at,
        datetime.now(UTC).isoformat() if complete else None,
        complete,
        digest,
        options.group,
        proxy_by_name(snapshot.proxies, options.group).selected,
        tuple(
            GroupSelection(proxy.name, proxy.selected, proxy.fixed)
            for proxy in snapshot.proxies
            if proxy.members
        ),
        snapshot.mode,
        options.url,
        options.size_bytes,
        options.rounds,
        options.nodes,
        results,
        winner,
    )


def run_benchmark(
    settings: Settings,
    snapshot: Snapshot,
    options: BenchmarkOptions,
    progress: Callable[[Sample, int, int], None],
    node_finished: Callable[[BenchmarkReport], None],
    cancelled: Callable[[], bool],
) -> BenchmarkReport:
    """Finish every download round and the OpenAI probe for one node before the next."""
    check_cancelled(cancelled)
    digest: str = source_digest(settings.config_path)
    started_at: str = datetime.now(UTC).isoformat()
    samples: tuple[Sample, ...] = ()
    services: dict[str, OpenAIResult] = {}
    total: int = len(options.nodes) * options.rounds
    # Write before startup so an interrupted run has an explicit, ineligible partial report.
    write_report(
        report_from_samples(snapshot, options, started_at, digest, samples, services),
        options.report_path,
    )
    with IsolatedCore(settings, snapshot, options.nodes) as core:
        for node in options.nodes:
            for round_number in range(1, options.rounds + 1):
                check_cancelled(cancelled)
                client: DownloadClient = DownloadClient(
                    core.proxy_url(node), options.timeout, cancelled
                )
                started: float = time.perf_counter()
                try:
                    sample: Sample = measure_sample(client, node, round_number, options)
                except MeasurementError as error:
                    sample = Sample(
                        node,
                        round_number,
                        options.attempts,
                        0,
                        time.perf_counter() - started,
                        None,
                        0.0,
                        str(error),
                    )
                    logging.getLogger(__name__).warning(
                        "node_sample_failed",
                        extra={"node": node, "round": round_number, "error": str(error)},
                    )
                samples = (*samples, sample)
                if round_number == options.rounds:
                    services = {
                        **services,
                        node: check_openai(
                            HttpsProbe(core.proxy_url(node), min(options.timeout, 4.0), cancelled)
                        ),
                    }
                write_report(
                    report_from_samples(snapshot, options, started_at, digest, samples, services),
                    options.report_path,
                )
                progress(sample, len(samples), total)
            if source_digest(settings.config_path) != digest:
                raise StateConflictError("The subscription changed during testing. Rerun /bench.")
            node_finished(
                report_from_samples(snapshot, options, started_at, digest, samples, services)
            )
    check_cancelled(cancelled)
    if source_digest(settings.config_path) != digest:
        raise StateConflictError("The subscription changed during testing. Report saved; rerun it.")
    return report_from_samples(snapshot, options, started_at, digest, samples, services)


def apply_winner(settings: Settings, report: BenchmarkReport) -> tuple[tuple[str, str], ...]:
    """Only switch after a completed benchmark, and protect concurrent user changes."""
    if not report.complete:
        raise MeasurementError("Benchmark is incomplete; no live selection changed")
    if report.winner is None:
        raise MeasurementError(
            "No node passed every round. Report saved; no live selection changed."
        )
    if source_digest(settings.config_path) != report.source_digest:
        raise StateConflictError("Subscription changed since testing; rerun before switching")
    client: ClashClient = ClashClient(settings)
    fresh: Snapshot = client.snapshot()
    group = proxy_by_name(fresh.proxies, report.group)
    if fresh.mode != report.live_mode or group.selected != report.initial_selection:
        raise StateConflictError(
            "Live mode or group selection changed during testing. Report saved; no winner applied."
        )
    path: tuple[tuple[str, str], ...] = selection_path(fresh.proxies, report.group, report.winner)
    for group_name, _ in path:
        original: GroupSelection | None = next(
            (item for item in report.initial_groups if item.name == group_name), None
        )
        if original is None:
            raise StateConflictError(f"New group {group_name} appeared during testing; rerun it")
        current = proxy_by_name(fresh.proxies, group_name)
        if (current.selected, current.fixed) != (original.selected, original.fixed):
            raise StateConflictError(
                f"Nested group {group_name} changed during testing; no winner applied"
            )
    result: tuple[tuple[str, str], ...] = client.select_node(report.group, report.winner)
    if result != path:
        raise StateConflictError("Group topology changed while switching; inspect group selections")
    applied_path: Path = Path("reports") / "last-switch.json"
    applied_path.parent.mkdir(parents=True, exist_ok=True)
    applied_path.write_text(
        json.dumps(
            {
                "at": datetime.now(UTC).isoformat(),
                "mode": fresh.mode,
                "group": report.group,
                "previous": report.initial_selection,
                "node": report.winner,
                "selection_path": result,
            },
            ensure_ascii=False,
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    return result
