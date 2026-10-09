"""Validated durable measurements; interrupted scans never replace the complete cache."""

import json
import math
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path

from clashctl.benchmark import rank_results, summarize
from clashctl.models import (
    BenchmarkReport,
    CacheError,
    ConfigurationError,
    GroupSelection,
    JsonObject,
    JsonValue,
    NodeResult,
    OpenAIResult,
    Sample,
    as_int,
    as_list,
    as_object,
    as_string,
    json_value,
    optional_string,
)
from clashctl.persistence import write_json_file


@dataclass(frozen=True)
class CachedReport:
    report: BenchmarkReport
    measured_at: tuple[tuple[str, str], ...]


def parse_time(value: str) -> datetime:
    try:
        timestamp: datetime = datetime.fromisoformat(value)
    except ValueError as error:
        raise CacheError(f"Invalid cache timestamp: {value!r}") from error
    if timestamp.tzinfo is None:
        raise CacheError(f"Cache timestamp requires a timezone: {value!r}")
    return timestamp.astimezone(UTC)


def age_seconds(timestamp: str, now: datetime) -> float:
    age: float = (now - parse_time(timestamp)).total_seconds()
    if age < -60.0:
        raise CacheError(
            "Cache is dated in the future; check the system clock or rebuild with /bench"
        )
    return max(0.0, age)


def number(value: JsonValue, context: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (float, int)):
        raise CacheError(f"{context}: expected a number")
    if not math.isfinite(value) or value < 0:
        raise CacheError(f"{context}: expected a finite nonnegative number")
    return float(value)


def parse_sample(value: JsonValue) -> Sample:
    item: JsonObject = as_object(value, "cached sample")
    first_byte: JsonValue = item.get("first_byte_ms")
    return Sample(
        as_string(item.get("node"), "sample.node"),
        as_int(item.get("round_number"), "sample.round_number"),
        as_int(item.get("attempts"), "sample.attempts"),
        as_int(item.get("bytes_received"), "sample.bytes_received"),
        number(item.get("elapsed_seconds"), "sample.elapsed_seconds"),
        None if first_byte is None else number(first_byte, "sample.first_byte_ms"),
        number(item.get("mbps"), "sample.mbps"),
        optional_string(item.get("error"), "sample.error"),
    )


def parse_result(value: JsonValue, rounds: int, size_bytes: int) -> NodeResult:
    item: JsonObject = as_object(value, "cached result")
    node: str = as_string(item.get("node"), "result.node")
    samples: tuple[Sample, ...] = tuple(
        parse_sample(sample) for sample in as_list(item.get("samples"), "result.samples")
    )
    if len(samples) != rounds or {sample.round_number for sample in samples} != set(
        range(1, rounds + 1)
    ):
        raise CacheError(f"Incomplete or duplicate cached rounds for {node}")
    for sample in samples:
        if sample.node != node or sample.attempts < 1:
            raise CacheError(f"Invalid sample identity or attempt count for {node}")
        if sample.error is None and (
            sample.bytes_received != size_bytes or sample.elapsed_seconds <= 0 or sample.mbps <= 0
        ):
            raise CacheError(f"Invalid successful download sample for {node}")
    service: OpenAIResult | None = (
        None if item.get("openai") is None else parse_openai_result(item["openai"], node)
    )
    return summarize(node, samples, rounds, service)


def parse_openai_result(value: JsonValue, node: str) -> OpenAIResult:
    entry: JsonObject = as_object(value, f"OpenAI result for {node}")
    checked_at: str = as_string(entry.get("checked_at"), "openai.checked_at")
    age_seconds(checked_at, datetime.now(UTC))
    status: str = as_string(entry.get("status"), "openai.status")
    if status not in {"fast", "slow", "restricted", "failed", "unconfirmed"}:
        raise CacheError(f"Invalid OpenAI status for {node}: {status}")
    response_ms: float | None = (
        None if entry.get("response_ms") is None else number(entry["response_ms"], "openai.ms")
    )
    http_status: int | None = (
        None
        if entry.get("http_status") is None
        else as_int(entry["http_status"], "openai.http_status")
    )
    if status in {"fast", "slow"} and (http_status != 401 or response_ms is None):
        raise CacheError(f"Unproven OpenAI connectivity for {node}")
    return OpenAIResult(
        checked_at, status, response_ms, http_status, optional_string(entry.get("error"), "error")
    )


def parse_report(value: JsonValue) -> BenchmarkReport:
    item: JsonObject = as_object(value, "cached report")
    if item.get("complete") is not True:
        raise CacheError("Only complete scans may be loaded as a persistent ranking")
    rounds: int = as_int(item.get("rounds"), "report.rounds")
    size: int = as_int(item.get("size_bytes"), "report.size_bytes")
    if rounds < 2 or size < 1:
        raise CacheError("Cached rankings require at least two rounds and a positive sample size")
    nodes: tuple[str, ...] = tuple(
        as_string(node, "report.node")
        for node in as_list(item.get("requested_nodes"), "report.requested_nodes")
    )
    results: tuple[NodeResult, ...] = rank_results(
        tuple(
            parse_result(result, rounds, size)
            for result in as_list(item.get("results"), "report.results")
        )
    )
    if not nodes or len(set(nodes)) != len(nodes) or {r.node for r in results} != set(nodes):
        raise CacheError("Cached results do not match the requested node set")
    if len(results) != len(nodes):
        raise CacheError("Duplicate results in the cached ranking")
    groups: tuple[GroupSelection, ...] = tuple(
        GroupSelection(
            as_string(group.get("name"), "group.name"),
            optional_string(group.get("selected"), "group.selected"),
            optional_string(group.get("fixed"), "group.fixed"),
        )
        for entry in as_list(item.get("initial_groups"), "report.initial_groups")
        for group in (as_object(entry, "initial group"),)
    )
    started: str = as_string(item.get("started_at"), "report.started_at")
    completed: str = as_string(item.get("completed_at"), "report.completed_at")
    if parse_time(completed) < parse_time(started):
        raise CacheError("Cache completion precedes its start time")
    return BenchmarkReport(
        started,
        completed,
        True,
        as_string(item.get("source_digest"), "report.source_digest"),
        as_string(item.get("group"), "report.group"),
        optional_string(item.get("initial_selection"), "report.initial_selection"),
        groups,
        as_string(item.get("live_mode"), "report.live_mode"),
        as_string(item.get("url"), "report.url"),
        size,
        rounds,
        nodes,
        results,
        next((result.node for result in results if result.eligible), None),
    )


def read_cache(path: Path) -> CachedReport | None:
    if not path.exists():
        return None
    try:
        decoded: object = json.loads(path.read_text(encoding="utf-8"))
        document: JsonObject = as_object(json_value(decoded, "cache"), "cache")
        if document.get("schema") != 1:
            raise CacheError(f"Unsupported cache schema at {path}; rebuild with /bench")
        report: BenchmarkReport = parse_report(document.get("report"))
        age_seconds(str(report.completed_at), datetime.now(UTC))
        times: JsonObject = as_object(document.get("measured_at"), "cache.measured_at")
        measured: tuple[tuple[str, str], ...] = tuple(
            (node, as_string(times.get(node), f"measurement time for {node}"))
            for node in report.requested_nodes
        )
        for _, timestamp in measured:
            if (
                not parse_time(report.started_at)
                <= parse_time(timestamp)
                <= parse_time(str(report.completed_at))
            ):
                raise CacheError("A node measurement time falls outside its complete scan")
        return CachedReport(report, measured)
    except (OSError, UnicodeError, json.JSONDecodeError, ConfigurationError) as error:
        raise CacheError(
            f"Cannot read measurement cache {path}: {error}. Rebuild with /bench."
        ) from error


def write_cache(cache: CachedReport, path: Path) -> None:
    if not cache.report.complete:
        raise CacheError("Refusing to overwrite the complete cache with an interrupted scan")
    document: JsonObject = {
        "schema": 1,
        "report": json_value(asdict(cache.report), "report"),
        "measured_at": {node: timestamp for node, timestamp in cache.measured_at},
    }
    try:
        write_json_file(document, path)
    except OSError as error:
        raise CacheError(f"Cannot save measurement cache {path}: {error}") from error
