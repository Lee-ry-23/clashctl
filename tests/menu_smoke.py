"""Real PTY shell checks against private Mihomo; live selections are preserved.

Run: uv run python tests/menu_smoke.py --node 'NODE NAME'

Checks completion, panel replacement, cached selection, timer refresh, persisted restart,
pause cancellation, SIGTERM cleanup, and terminal restoration. Only one node is downloaded.
"""

import argparse
import codecs
import errno
import fcntl
import os
import pty
import re
import select
import signal
import struct
import subprocess
import sys
import tempfile
import termios
import time
from collections.abc import Callable
from pathlib import Path
from types import TracebackType

import pyte

from clashctl.cache import CachedReport, read_cache
from clashctl.config import load_settings
from clashctl.controller import ClashClient
from clashctl.isolation import IsolatedCore, candidate_names
from clashctl.models import ConfigurationError, Settings, Snapshot, choose_group, proxy_by_name
from clashctl.shell_commands import node_id


class Terminal:
    """Own a child PTY and decode the painted screen rather than matching raw ANSI text."""

    def __init__(self, command: list[str], directory: Path) -> None:
        self.master: int
        slave: int
        self.master, slave = pty.openpty()
        fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", 42, 124, 0, 0))
        environment: dict[str, str] = {
            **os.environ,
            "TERM": "xterm-256color",
            "PROMPT_TOOLKIT_NO_CPR": "1",
        }
        self.process: subprocess.Popen[bytes] = subprocess.Popen(
            command,
            cwd=directory,
            stdin=slave,
            stdout=slave,
            stderr=slave,
            env=environment,
            start_new_session=True,
        )
        os.close(slave)
        self.screen: pyte.Screen = pyte.Screen(124, 42)
        self.stream: pyte.Stream = pyte.Stream(self.screen)
        self.decoder: codecs.IncrementalDecoder = codecs.getincrementaldecoder("utf-8")("replace")
        self.transcript: bytes = b""

    def read(self, seconds: float) -> None:
        if not select.select([self.master], [], [], seconds)[0]:
            return
        while True:
            try:
                data: bytes = os.read(self.master, 65536)
            except OSError as error:
                if error.errno == errno.EIO and self.process.poll() is not None:
                    return
                raise
            if not data:
                return
            self.transcript += data
            self.stream.feed(self.decoder.decode(data))
            # Drain a paint before inspecting rows that may temporarily contain wide-char stubs.
            if not select.select([self.master], [], [], 0.01)[0]:
                return

    def text(self) -> str:
        return "\n".join(self.screen.display)

    def send(self, text: str) -> None:
        os.write(self.master, text.encode())

    def until(self, condition: Callable[[], bool], seconds: float) -> None:
        deadline: float = time.monotonic() + seconds
        while time.monotonic() < deadline:
            self.read(0.1)
            exited: bool = self.process.poll() is not None
            if condition():
                return
            if exited:
                raise AssertionError(f"Shell exited unexpectedly: {self.text()}")
        raise AssertionError(f"Terminal condition timed out: {self.text()}")

    def expect(self, text: str) -> None:
        self.until(lambda: text in self.text(), 25.0)

    def command(self, text: str, expected: str) -> None:
        self.send(text + "\r")
        self.expect(expected)

    def quit(self) -> None:
        self.send("/quit\r")
        self.until(lambda: self.process.poll() is not None, 20.0)
        self.read(0.1)
        if self.process.returncode != 0:
            raise AssertionError(f"Shell quit failed: {self.text()}")
        if b"\x1b[?1049l" not in self.transcript:
            raise AssertionError("Shell did not restore the original terminal buffer")
        if b"Traceback" in self.transcript:
            raise AssertionError(f"Uncaught shell failure: {self.text()}")

    def __enter__(self) -> "Terminal":
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        try:
            if self.process.poll() is None:
                self.process.terminate()
                deadline: float = time.monotonic() + 20.0
                while self.process.poll() is None and time.monotonic() < deadline:
                    self.read(0.1)
                if self.process.poll() is None:
                    self.process.kill()
                    self.process.wait(timeout=5.0)
                    raise AssertionError(f"Shell failed to terminate: {self.text()}")
        finally:
            os.close(self.master)


def command(settings: Settings, node: str, directory: Path, rounds: int) -> list[str]:
    if settings.core_binary is None:
        raise ConfigurationError("Shell checks require an installed real Mihomo executable")
    return [
        sys.executable,
        "-m",
        "clashctl.cli",
        "--config",
        str(settings.config_path),
        "--core",
        str(settings.core_binary),
        "shell",
        "--include",
        "^" + re.escape(node) + "$",
        "--cache-dir",
        str(directory / "reports"),
        "--rounds",
        str(rounds),
    ]


def verify_navigation(settings: Settings, group: str, node: str, directory: Path) -> None:
    snapshot: Snapshot = ClashClient(settings).snapshot()
    alternate: str = next(
        name
        for name in candidate_names(settings.config_path, snapshot.proxies, group)
        if name != node
    )
    path: Path = directory / "reports/background-cache.json"
    with Terminal(command(settings, node, directory, 2), directory) as terminal:
        terminal.expect("Your local Clash workspace")
        terminal.command("/unknown", "Unknown command")
        terminal.send("/sta\t")
        terminal.expect("› /status")
        terminal.send("\r")
        terminal.expect("Live controller state refreshed.")
        terminal.command("/group " + group, "Working group:")
        terminal.until(lambda: path.exists() and read_cache(path) is not None, 75.0)
        first: CachedReport | None = read_cache(path)
        if first is None or first.report.winner != node:
            raise AssertionError("The real node did not produce an eligible cached result")
        if first.report.results[0].openai is None:
            raise AssertionError("The completed benchmark omitted its OpenAI measurement")
        terminal.command("/rank", "Cached downloads")
        terminal.expect("OpenAI API")
        terminal.expect(node_id(node))
        terminal.expect("WATCH IDLE")
        if "Your local Clash workspace" in terminal.text():
            raise AssertionError("Old help accumulated instead of being replaced")
        preview: Path = Path(__file__).resolve().parent.parent / ".cache/shell-preview.txt"
        preview.parent.mkdir(parents=True, exist_ok=True)
        preview.write_text(terminal.text(), encoding="utf-8")
        terminal.command("/rules", "Ordered routing rules")
        terminal.command("/sites", "Live Clash connections")
        if "Ordered routing rules" in terminal.text():
            raise AssertionError("The old rules panel accumulated in the connections view")
        terminal.command("/connect " + node_id(alternate), "Verified:")
        if proxy_by_name(ClashClient(settings).proxies(), group).selected != alternate:
            raise AssertionError("Manual selection did not reach the private real controller")
        terminal.command("/best", "Verified:")
        terminal.until(
            lambda: proxy_by_name(ClashClient(settings).proxies(), group).selected == node, 15.0
        )
        terminal.command("/mode direct", "Verified mode: direct")
        terminal.command("/mode rule", "Verified mode: rule")
        terminal.command("/group " + group, "Working group:")
        terminal.command("/watch interval 0.1", "Scan interval set to 0.1")
        terminal.until(
            lambda: (
                (updated := read_cache(path)) is not None
                and updated.report.started_at != first.report.started_at
            ),
            75.0,
        )
        terminal.command("/watch pause", "Pausing downloads")
        terminal.expect("WATCH PAUSED")
        terminal.command("/watch status", "Traffic: about 2 MiB/scan")
        terminal.quit()


def verify_restart(settings: Settings, group: str, node: str, directory: Path) -> None:
    active: Path = directory / "reports/background-active.json"
    before: int = active.stat().st_mtime_ns
    with Terminal(command(settings, node, directory, 2), directory) as terminal:
        terminal.expect("WATCH IDLE")
        terminal.command("/rank", "Cached downloads")
        terminal.expect(node_id(node))
        terminal.read(0.5)
        if active.stat().st_mtime_ns != before:
            raise AssertionError("Restart ignored a fresh persisted cache and started another scan")
        terminal.command("/help", "Your local Clash workspace")
        if "Cached downloads" in terminal.text():
            raise AssertionError("The previous ranking did not disappear")
        terminal.command("/watch pause", "Pausing downloads")
        terminal.expect("WATCH PAUSED")
        original: bytes = settings.config_path.read_bytes()
        try:
            settings.config_path.write_bytes(original + b"\n# Integration source-revision check\n")
            terminal.command("/group " + group, "Working group:")
            terminal.command("/best", "Cache no longer matches this configuration")
        finally:
            settings.config_path.write_bytes(original)
        terminal.command("/group " + group, "Working group:")
        terminal.command("/watch interval 0.1", "Scan interval set to 0.1")
        started: float = time.monotonic()
        terminal.until(lambda: time.monotonic() - started >= 7.0, 10.0)
        terminal.command("/best", "No fresh successful cached result")
        terminal.command("/rank", "stale")
        terminal.quit()


def verify_pause_and_termination(settings: Settings, node: str, directory: Path) -> None:
    path: Path = directory / "reports/background-cache.json"
    cached: bytes = path.read_bytes()
    with Terminal(command(settings, node, directory, 20), directory) as terminal:
        terminal.expect("WATCH SCANNING")
        terminal.command("/bench", "already running")
        terminal.command("/watch pause", "Pausing downloads")
        terminal.expect("WATCH PAUSED")
        if path.read_bytes() != cached:
            raise AssertionError("Paused scan overwrote the previous complete cache")
        terminal.command("/watch resume", "Background scans resumed")
        terminal.expect("WATCH SCANNING")
        terminal.process.send_signal(signal.SIGTERM)
        terminal.until(lambda: terminal.process.poll() is not None, 20.0)
        terminal.read(0.1)
        if terminal.process.returncode != 143:
            raise AssertionError(f"SIGTERM did not exit cleanly: {terminal.text()}")
        if path.read_bytes() != cached:
            raise AssertionError("Terminated scan replaced a complete cache")
        if b"\x1b[?1049l" not in terminal.transcript:
            raise AssertionError("SIGTERM failed to restore the terminal")


def main() -> None:
    parser: argparse.ArgumentParser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--node", required=True)
    arguments: argparse.Namespace = parser.parse_args()
    node: str = arguments.node
    settings: Settings = load_settings(None, None, None, None, 5.0)
    client: ClashClient = ClashClient(settings)
    before: Snapshot = client.snapshot()
    group: str = choose_group(before, None)
    with IsolatedCore(settings, before, (node,)) as core:
        if core.client is None:
            raise AssertionError("Private controller did not initialize")
        with tempfile.TemporaryDirectory(prefix="clashctl-shell-test-") as temporary:
            directory: Path = Path(temporary)
            verify_navigation(core.client.settings, group, node, directory)
            verify_restart(core.client.settings, group, node, directory)
            verify_pause_and_termination(core.client.settings, node, directory)
    if client.snapshot() != before:
        raise AssertionError("Shell checks changed live Clash selections or mode")
    print("PASS: completion, clean panels, cached best, timer, restart, pause, SIGTERM, live state")


if __name__ == "__main__":
    main()
