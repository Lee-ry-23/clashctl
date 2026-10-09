"""Independent per-node OpenAI probes and durable results, without download samples."""

import json
from collections.abc import Callable
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Literal

from clashctl.benchmark import check_cancelled
from clashctl.cache import parse_openai_result, parse_time
from clashctl.config import source_digest
from clashctl.isolation import IsolatedCore
from clashctl.models import (
    CacheError,
    ConfigurationError,
    OpenAIResult,
    Settings,
    Snapshot,
    StateConflictError,
    as_object,
    as_string,
    json_value,
)
from clashctl.persistence import write_json_file
from clashctl.probes import HttpsProbe, check_openai


@dataclass(frozen=True)
class OpenAICache:
    source_digest: str
    results: tuple[tuple[str, OpenAIResult], ...]


@dataclass(frozen=True)
class ProbeEvent:
    source_digest: str
    node: str
    result: OpenAIResult
    completed: int
    total: int


@dataclass(frozen=True)
class ProbeStatusEvent:
    message: str
    level: Literal["info", "error"]


def merge_openai_results(
    cache: OpenAICache | None, digest: str, results: tuple[tuple[str, OpenAIResult], ...]
) -> OpenAICache:
    """Keep the newest observation and discard entries from a different configuration."""
    merged: dict[str, OpenAIResult] = (
        {} if cache is None or cache.source_digest != digest else dict(cache.results)
    )
    for node, result in results:
        previous: OpenAIResult | None = merged.get(node)
        if previous is None or parse_time(result.checked_at) > parse_time(previous.checked_at):
            merged = {**merged, node: result}
    return OpenAICache(digest, tuple(sorted(merged.items())))


def read_openai_cache(path: Path) -> OpenAICache | None:
    if not path.exists():
        return None
    try:
        document = as_object(
            json_value(json.loads(path.read_text(encoding="utf-8")), "OpenAI cache"), "OpenAI cache"
        )
        if document.get("schema") != 1:
            raise CacheError(f"Unsupported OpenAI cache schema at {path}")
        entries = as_object(document.get("results"), "OpenAI cache results")
        return OpenAICache(
            as_string(document.get("source_digest"), "OpenAI cache source digest"),
            tuple((node, parse_openai_result(value, node)) for node, value in entries.items()),
        )
    except (OSError, UnicodeError, json.JSONDecodeError, ConfigurationError) as error:
        raise CacheError(f"Cannot read OpenAI cache {path}: {error}") from error


def write_openai_cache(cache: OpenAICache, path: Path) -> None:
    try:
        write_json_file(
            {
                "schema": 1,
                "source_digest": cache.source_digest,
                "results": {
                    node: json_value(asdict(result), "OpenAI result")
                    for node, result in cache.results
                },
            },
            path,
        )
    except OSError as error:
        raise CacheError(f"Cannot save OpenAI cache {path}: {error}") from error


def run_openai_checks(
    settings: Settings,
    snapshot: Snapshot,
    nodes: tuple[str, ...],
    timeout: float,
    progress: Callable[[ProbeEvent], None],
    cancelled: Callable[[], bool],
) -> None:
    """Probe fixed private listeners and publish each result after checking source integrity."""
    if not nodes:
        raise ConfigurationError("No nodes selected for the OpenAI check")
    check_cancelled(cancelled)
    digest: str = source_digest(settings.config_path)
    with IsolatedCore(settings, snapshot, nodes) as core:
        for completed, node in enumerate(nodes, start=1):
            check_cancelled(cancelled)
            result: OpenAIResult = check_openai(
                HttpsProbe(core.proxy_url(node), timeout, cancelled)
            )
            check_cancelled(cancelled)
            if source_digest(settings.config_path) != digest:
                raise StateConflictError(
                    "Configuration changed during OpenAI checks. Run /openai again."
                )
            progress(ProbeEvent(digest, node, result, completed, len(nodes)))
