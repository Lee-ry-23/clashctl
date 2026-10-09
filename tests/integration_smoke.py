"""Real-core smoke checks; no mocks and no writes to the live controller.

Run from the project directory with an available real node:
    uv run python tests/integration_smoke.py --node 'NODE NAME'

The checks cover fixed-node routing despite GLOBAL=DIRECT, truncated response rejection,
private process/file cleanup, Ctrl-C partial reports, and unchanged live selections.
They use a small amount of Cloudflare traffic and require TUN to be off.
"""

import argparse
import json
import os
import re
import selectors
import signal
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import httpx

from clashctl.benchmark import DownloadClient, never_cancel
from clashctl.config import load_settings
from clashctl.controller import ClashClient
from clashctl.isolation import IsolatedCore
from clashctl.models import (
    ConfigurationError,
    JsonObject,
    MeasurementError,
    Settings,
    Snapshot,
    as_list,
    as_object,
    as_string,
    json_value,
)


def verify_private_routing(settings: Settings, snapshot: Snapshot, node: str) -> None:
    with IsolatedCore(settings, snapshot, (node,)) as core:
        if core.client is None or core.temp is None or core.process is None:
            raise AssertionError("Private core did not initialize")
        directory: Path = Path(core.temp.name)
        core.client.set_mode("global")
        core.client.select("GLOBAL", "DIRECT")
        with httpx.Client(proxy=core.proxy_url(node), trust_env=False, timeout=10.0) as client:
            with client.stream(
                "GET", "https://speed.cloudflare.com/__down?bytes=8388608"
            ) as response:
                response.raise_for_status()
                iterator = response.iter_raw()
                if not next(iterator):
                    raise AssertionError("Download returned no data")
                state: JsonObject = as_object(
                    core.client.request("GET", "/connections", {}, None), "connections"
                )
                chains: tuple[tuple[str, ...], ...] = tuple(
                    tuple(
                        as_string(item, "chain")
                        for item in as_list(
                            as_object(connection, "connection").get("chains"), "chains"
                        )
                    )
                    for connection in as_list(state.get("connections"), "connections")
                )
                if not chains or not all(node in chain for chain in chains):
                    raise AssertionError(f"Expected fixed node {node}, observed {chains}")
        core.client.set_mode("rule")
        try:
            DownloadClient(core.proxy_url(node), 10.0, never_cancel).download(
                "https://speed.cloudflare.com/__down?bytes=1024", 2048
            )
        except MeasurementError as error:
            if "incomplete body" not in str(error):
                raise AssertionError(f"Unexpected truncated-response error: {error}") from error
        else:
            raise AssertionError("A truncated response was accepted as a complete sample")
    if core.process.poll() is None or directory.exists():
        raise AssertionError("Private process or temporary credentials survived cleanup")


def verify_interrupt(node: str) -> None:
    with tempfile.TemporaryDirectory(prefix="clashctl-test-") as directory:
        report_path: Path = Path(directory) / "partial.json"
        command: list[str] = [
            sys.executable,
            "-m",
            "clashctl.cli",
            "bench",
            "--include",
            re.escape(node),
            "--rounds",
            "20",
            "--size-mib",
            "1",
            "--timeout",
            "10",
            "--output",
            str(report_path),
        ]
        process: subprocess.Popen[bytes] = subprocess.Popen(
            command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, bufsize=0
        )
        try:
            if process.stdout is None:
                raise AssertionError("Missing child output stream")
            deadline: float = time.monotonic() + 45.0
            sample_seen: bool = False
            output: bytes = b""
            with selectors.DefaultSelector() as selector:
                selector.register(process.stdout, selectors.EVENT_READ)
                while time.monotonic() < deadline and process.poll() is None:
                    if selector.select(timeout=1.0):
                        output += os.read(process.stdout.fileno(), 4096)
                        if b"round 1 |" in output:
                            sample_seen = True
                            break
            if not sample_seen:
                raise AssertionError("No completed sample before interrupt test deadline")
            os.kill(process.pid, signal.SIGINT)
            process.communicate(timeout=10.0)
            if process.returncode == 0:
                raise AssertionError("Interrupted benchmark reported success")
            decoded: object = json.loads(report_path.read_text(encoding="utf-8"))
            report: JsonObject = as_object(json_value(decoded, "report"), "report")
            if report.get("complete") is not False or report.get("completed_at") is not None:
                raise AssertionError("Partial report is incorrectly marked complete")
            results = as_list(report.get("results"), "results")
            if not results or not as_list(
                as_object(results[0], "result").get("samples"), "samples"
            ):
                raise AssertionError("Completed sample was lost on interrupt")
        finally:
            if process.poll() is None:
                process.terminate()
                process.communicate(timeout=10.0)


def main() -> None:
    parser: argparse.ArgumentParser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--node", required=True)
    arguments: argparse.Namespace = parser.parse_args()
    node: str = arguments.node
    settings: Settings = load_settings(None, None, None, None, 5.0)
    client: ClashClient = ClashClient(settings)
    before: Snapshot = client.snapshot()
    if before.tun_enabled:
        raise ConfigurationError("Disable TUN before running integration smoke checks")
    verify_private_routing(settings, before, node)
    verify_interrupt(node)
    after: Snapshot = client.snapshot()
    if after != before:
        raise AssertionError("Live mode, topology, or group selections changed during smoke checks")
    print(
        "PASS: forced routing, incomplete-body rejection, cleanup, Ctrl-C, live-state preservation"
    )


if __name__ == "__main__":
    main()
