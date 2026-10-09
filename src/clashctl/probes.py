"""Bounded, credential-free HTTPS checks through explicit private proxy listeners."""

import logging
import time
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from urllib.parse import urlsplit

import httpx

from clashctl.models import BenchmarkCancelled, MeasurementError, OpenAIResult

OPENAI_URL: str = "https://api.openai.com/v1/models"
OPENAI_FAST_MS: float = 2000.0


@dataclass(frozen=True)
class ProbeResult:
    http_status: int | None
    response_ms: float | None
    reachable: bool
    error: str | None


class HttpsProbe:
    """Read response headers and a bounded body without cookies or account credentials."""

    def __init__(self, proxy_url: str, timeout: float, cancelled: Callable[[], bool]) -> None:
        self.proxy_url: str = proxy_url
        self.timeout: float = timeout
        self.cancelled: Callable[[], bool] = cancelled

    def request(self, url: str) -> ProbeResult:
        if self.cancelled():
            raise BenchmarkCancelled("HTTPS checks cancelled")
        started: float = time.perf_counter()
        try:
            with httpx.Client(
                proxy=self.proxy_url,
                trust_env=False,
                follow_redirects=False,
                timeout=self.timeout,
            ) as client:
                with client.stream("GET", url, headers={"User-Agent": "clashctl/0.1"}) as response:
                    elapsed: float = (time.perf_counter() - started) * 1000
                    body: bytes = b""
                    for chunk in response.iter_bytes(chunk_size=512):
                        if self.cancelled():
                            raise BenchmarkCancelled("HTTPS checks cancelled")
                        body += chunk[: 4096 - len(body)]
                        if len(body) >= 4096 or time.perf_counter() - started >= self.timeout:
                            break
                    status: int = response.status_code
                    detail: str = body.decode("utf-8", errors="replace")[:300]
                    if status >= 500:
                        raise MeasurementError(f"GET {url}: HTTP {status}, response={detail}")
                    location: str = response.headers.get("location", "")
                    redirect_host: str | None = urlsplit(location).hostname
                    reachable: bool = (
                        200 <= status < 300
                        or (300 <= status < 400 and redirect_host in {None, urlsplit(url).hostname})
                        or (url == OPENAI_URL and status == 401)
                    ) and response.headers.get("cf-mitigated") != "challenge"
                    return ProbeResult(
                        status,
                        elapsed,
                        reachable,
                        None if reachable else f"HTTP {status}, response={detail}",
                    )
        except httpx.TransportError as error:
            raise MeasurementError(
                f"GET {url} via {self.proxy_url}, timeout={self.timeout}s: "
                f"{type(error).__name__}: {error}"
            ) from error

    def measure(self, url: str, attempts: int) -> ProbeResult:
        for attempt in range(1, attempts + 1):
            try:
                return self.request(url)
            except MeasurementError as error:
                if attempt == attempts:
                    raise
                logging.getLogger(__name__).warning(
                    "https_probe_retry",
                    extra={"url": url, "attempt": attempt, "error": str(error)},
                )
        raise MeasurementError(f"No HTTPS probe attempts for {url}")


def probe_outcome(client: HttpsProbe, url: str, attempts: int) -> ProbeResult:
    """Keep the final explicit network error as evidence in a failed measurement."""
    try:
        return client.measure(url, attempts)
    except MeasurementError as error:
        logging.getLogger(__name__).warning(
            "https_probe_failed", extra={"url": url, "error": str(error)}
        )
        return ProbeResult(None, None, False, str(error))


def check_openai(client: HttpsProbe) -> OpenAIResult:
    """401 proves API reachability without a key; it does not prove authenticated usage."""
    result: ProbeResult = probe_outcome(client, OPENAI_URL, 2)
    status: str = "failed"
    if result.http_status == 401 and result.response_ms is not None:
        status = "fast" if result.response_ms <= OPENAI_FAST_MS else "slow"
    elif result.http_status in {403, 451}:
        status = "restricted"
    elif result.http_status is not None:
        status = "unconfirmed"
    return OpenAIResult(
        datetime.now(UTC).isoformat(), status, result.response_ms, result.http_status, result.error
    )


def openai_label(result: OpenAIResult | None) -> str:
    if result is None:
        return "untested"
    elapsed: str = "" if result.response_ms is None else f" {result.response_ms / 1000:.1f}s"
    return result.status + elapsed
