"""Offline PTY checks for layout, scrolling, selection, and the real macOS clipboard.

Run: uv run python tests/terminal_smoke.py
No controller is contacted and no background downloads are started.
"""

import argparse
import asyncio
import fcntl
import signal
import struct
import subprocess
import sys
import tempfile
import termios
import time
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path

import pyte
from menu_smoke import Terminal
from prompt_toolkit.utils import get_cwidth
from rich.cells import cell_len

from clashctl.models import Proxy, Settings, Snapshot
from clashctl.monitor import GroupChoice, LiveContext, default_options
from clashctl.routing_display import rules_copy_text, sites_copy_text
from clashctl.routing_models import Connection, RoutingState, RuntimeRule
from clashctl.shell import TerminalShell
from clashctl.terminal_display import node_label

NODE: str = "🇺🇸 [v6]DEMO1 (0.3x)"
PLAIN_NODE: str = "🇺🇸 DEMO2 (0.6x)"
GROUP: str = "🧱 Demo Proxy"
CLIPBOARD_SNAPSHOT: str = """
ObjC.import('AppKit');
function run() {
    const items = $.NSPasteboard.generalPasteboard.pasteboardItems;
    const result = [];
    for (let i = 0; i < items.count; i++) {
        const item = items.objectAtIndex(i), values = {};
        for (let j = 0; j < item.types.count; j++) {
            const type = item.types.objectAtIndex(j);
            const encoded = item.dataForType(type).base64EncodedStringWithOptions(0);
            values[ObjC.unwrap(type)] = ObjC.unwrap(encoded);
        }
        result.push(values);
    }
    return JSON.stringify(result);
}
"""
CLIPBOARD_RESTORE: str = """
ObjC.import('AppKit');
function run() {
    const data = $.NSFileHandle.fileHandleWithStandardInput.readDataToEndOfFile;
    const source = ObjC.unwrap($.NSString.alloc.initWithDataEncoding(data, $.NSUTF8StringEncoding));
    const items = JSON.parse(source).map(values => {
        const item = $.NSPasteboardItem.alloc.init;
        for (const type of Object.keys(values)) {
            const bytes = $.NSData.alloc.initWithBase64EncodedStringOptions(values[type], 0);
            item.setDataForType(bytes, type);
        }
        return item;
    });
    const board = $.NSPasteboard.generalPasteboard;
    board.clearContents;
    if (items.length && !board.writeObjects($(items))) throw Error('Cannot restore clipboard');
}
"""


def fixture_routing() -> RoutingState:
    connections: tuple[Connection, ...] = tuple(
        Connection(
            str(index),
            f"site-{index:03}.example.com",
            "443",
            "",
            "tcp",
            "DomainSuffix" if index % 2 else "GeoIP",
            "example.com" if index % 2 else "cn",
            (NODE, GROUP, "🚀 Acceleration") if index % 2 else ("DIRECT",),
            0,
            0,
        )
        for index in range(80)
    )
    rules: tuple[RuntimeRule, ...] = tuple(
        RuntimeRule(index, "DomainSuffix", f"site-{index:03}.example.com", GROUP)
        for index in range(260)
    )
    return RoutingState(rules, connections, (), datetime.now(UTC).isoformat(), None, None)


async def paint_updates(shell: TerminalShell) -> None:
    while not shell.closing:
        await asyncio.sleep(0.5)
        shell.state = replace(
            shell.state,
            routing=replace(shell.state.routing, checked_at=datetime.now(UTC).isoformat()),
        )
        shell.redraw()


async def run_fixture() -> None:
    settings: Settings = Settings(Path("/unused"), "http://127.0.0.1:1", "", None, 1.0)
    shell: TerminalShell = TerminalShell(settings, default_options())
    snapshot: Snapshot = Snapshot(
        "rule",
        "test",
        7897,
        False,
        (Proxy(GROUP, "Selector", (NODE, PLAIN_NODE), NODE, None),),
        (GROUP,),
        260,
    )
    context: LiveContext = LiveContext(
        snapshot, (NODE, PLAIN_NODE), (GroupChoice(GROUP, (NODE, PLAIN_NODE)),), "test"
    )
    shell.state = replace(
        shell.state, context=context, group=GROUP, view="sites", routing=fixture_routing()
    )
    shell.redraw()
    updates: asyncio.Task[None] = asyncio.create_task(paint_updates(shell))
    try:
        await shell.app.run_async(set_exception_handler=False)
    finally:
        updates.cancel()
        try:
            await updates
        except asyncio.CancelledError:
            pass
        if shell.clipboard_task is not None:
            await shell.clipboard_task


def clipboard_snapshot() -> str:
    return subprocess.run(
        ["/usr/bin/osascript", "-l", "JavaScript", "-e", CLIPBOARD_SNAPSHOT],
        capture_output=True,
        text=True,
        check=True,
        timeout=10,
    ).stdout


def restore_clipboard(snapshot: str) -> None:
    subprocess.run(
        ["/usr/bin/osascript", "-l", "JavaScript", "-e", CLIPBOARD_RESTORE],
        input=snapshot,
        capture_output=True,
        text=True,
        check=True,
        timeout=10,
    )


def resize(terminal: Terminal, columns: int, rows: int) -> None:
    fcntl.ioctl(terminal.master, termios.TIOCSWINSZ, struct.pack("HHHH", rows, columns, 0, 0))
    terminal.screen = pyte.Screen(columns, rows)
    terminal.stream = pyte.Stream(terminal.screen)
    terminal.process.send_signal(signal.SIGWINCH)


def wait_for_paint(terminal: Terminal, seconds: float) -> None:
    started: float = time.monotonic()
    terminal.until(lambda: time.monotonic() - started >= seconds, seconds + 3.0)


def clipboard_text() -> str:
    return subprocess.run(
        ["/usr/bin/pbpaste"], capture_output=True, text=True, check=True, timeout=5
    ).stdout


def screen_point(terminal: Terminal, text: str) -> tuple[int, int]:
    for row, line in enumerate(terminal.screen.display):
        if line.startswith("│") and text in line:
            return get_cwidth(line[: line.index(text)]) + 1, row + 1
    raise AssertionError(f"Text not visible for mouse selection: {text!r}: {terminal.text()}")


def mouse_packet(code: int, point: tuple[int, int], ending: str) -> str:
    column, row = point
    return f"\x1b[<{code};{column};{row}{ending}"


def verify_selection(terminal: Terminal, text: str) -> None:
    start: tuple[int, int] = screen_point(terminal, text)
    end: tuple[int, int] = (start[0] + get_cwidth(text), start[1])
    terminal.send(
        mouse_packet(0, start, "M") + mouse_packet(32, end, "M") + mouse_packet(0, end, "m")
    )
    terminal.expect(f"Copied selected text ({len(text)} characters)")
    if clipboard_text() != text:
        raise AssertionError("Mouse selection copied the wrong characters or terminal padding")
    if terminal.screen.buffer[start[1] - 1][start[0] - 1].bg == "default":
        colors: list[tuple[int, str, str]] = [
            (column, char.data, char.bg)
            for column, char in terminal.screen.buffer[start[1] - 1].items()
            if char.bg != "default"
        ]
        raise AssertionError(f"Mouse selection was not highlighted at {start}: {colors}")
    wait_for_paint(terminal, 0.3)
    offset: int = len(terminal.transcript)
    wait_for_paint(terminal, 1.2)
    if terminal.transcript[offset:]:
        raise AssertionError("Automatic updates disturbed the selected snapshot")
    terminal.send(mouse_packet(65, (20, 10), "M") * 3)
    wait_for_paint(terminal, 0.3)
    terminal.send(mouse_packet(64, (20, 10), "M") * 3)
    terminal.expect(text)
    terminal.send("\x03")
    terminal.expect(f"Copied selected text ({len(text)} characters)")
    wait_for_paint(terminal, 0.3)
    if clipboard_text() != text:
        raise AssertionError("Ctrl+C did not copy the mouse selection")
    terminal.send("\x1b")
    terminal.expect("Selection cleared.")
    if any(
        char.bg != "default" for line in terminal.screen.buffer.values() for char in line.values()
    ):
        raise AssertionError("Esc left selection highlighting behind")


def assert_layout(terminal: Terminal) -> None:
    text: str = terminal.text()
    if NODE in text or "🧱" in text or "🚀" in text or "unknown" in text:
        raise AssertionError("Unstable emoji widths or empty app labels leaked into the panel")
    rows: list[str] = [row for row in terminal.screen.display if "site-" in row]
    if not rows or any("DIRECT" not in row and "VPN" not in row for row in rows):
        raise AssertionError(f"Website rows wrapped or lost their route: {text}")
    for row in rows:
        if row.count("site-") != 1 or ("GeoIP:cn" not in row and "DomainSuffix" not in row):
            raise AssertionError(f"Website columns are not aligned: {row}")
    if any(
        char.bg != "default" for line in terminal.screen.buffer.values() for char in line.values()
    ):
        raise AssertionError("The shell stopped following the terminal background")


def verify_terminal(directory: Path) -> None:
    command: list[str] = [
        "/usr/bin/env",
        "NO_COLOR=",
        "PROMPT_TOOLKIT_COLOR_DEPTH=DEPTH_24_BIT",
        sys.executable,
        str(Path(__file__).resolve()),
        "--fixture",
    ]
    with Terminal(command, directory) as terminal:
        terminal.expect("Live Clash connections")
        terminal.expect("site-000.example.com")
        terminal.expect("Ctrl+D quit")
        assert_layout(terminal)
        if b"\x1b[?1000h" not in terminal.transcript or b"\x1b[?1006h" not in terminal.transcript:
            raise AssertionError("Mouse capture was not enabled for application scrolling")
        terminal.send(mouse_packet(65, (20, 10), "M") * 3)
        terminal.until(lambda: "site-000.example.com" not in terminal.text(), 5.0)
        terminal.expect("site-004.example.com")
        wait_for_paint(terminal, 1.2)
        if "site-000.example.com" in terminal.text():
            raise AssertionError("Automatic redraw reset the scroll position")
        terminal.send("\x1b[6~")
        terminal.until(lambda: "site-004.example.com" not in terminal.text(), 5.0)
        terminal.send("\x1b[1;5F")
        terminal.expect("site-079.example.com")
        terminal.send("\x1b[1;5H")
        terminal.expect("site-000.example.com")
        terminal.send("\x1b[6~\x1b[5~")
        terminal.expect("site-000.example.com")
        terminal.send("draft")
        terminal.expect("› draft")
        terminal.send(mouse_packet(65, screen_point(terminal, "› draft"), "M") * 3)
        terminal.until(lambda: "site-000.example.com" not in terminal.text(), 5.0)
        if "› draft" not in terminal.text():
            raise AssertionError("Wheel events over the input changed command text")
        terminal.send("\x03\x1b[1;5H")
        terminal.expect("site-000.example.com")
        verify_selection(terminal, "site-000.example.com")
        assert_layout(terminal)
        terminal.command("/copy", "Copied current results to clipboard")
        copied: str = clipboard_text()
        if copied != sites_copy_text(fixture_routing(), ""):
            raise AssertionError(
                "Clipboard omitted full chains, raw node names, or off-screen rows"
            )
        if "site-079.example.com:443" not in copied or NODE not in copied or "\x1b" in copied:
            raise AssertionError("Clipboard data was truncated or contained ANSI styling")
        terminal.send("\x1b[A")
        terminal.expect("› /copy")
        terminal.send(mouse_packet(65, screen_point(terminal, "› /copy"), "M") * 3)
        terminal.until(lambda: "site-000.example.com" not in terminal.text(), 5.0)
        if "› /copy" not in terminal.text():
            raise AssertionError("Wheel events navigated command history")
        terminal.send("\x1b[B")
        terminal.until(lambda: "› /copy" not in terminal.text(), 5.0)
        terminal.send("\x1b[1;5H")
        terminal.send("\x1bOQ")
        terminal.expect("Display paused.")
        transcript_offset: int = len(terminal.transcript)
        wait_for_paint(terminal, 1.2)
        if terminal.transcript[transcript_offset:]:
            raise AssertionError("Background redraw disturbed the paused snapshot")
        terminal.send(mouse_packet(65, (20, 10), "M") * 3)
        terminal.until(lambda: "site-000.example.com" not in terminal.text(), 5.0)
        terminal.send(mouse_packet(64, (20, 10), "M") * 3)
        terminal.expect("site-000.example.com")
        terminal.command("/copy", "Copied current results to clipboard")
        terminal.command("/freeze", "Live updates resumed")
        resize(terminal, 80, 24)
        terminal.expect("Website / address")
        wait_for_paint(terminal, 0.7)
        assert_layout(terminal)
        terminal.send("\x1b[6~")
        terminal.until(lambda: "site-000.example.com" not in terminal.text(), 5.0)
        terminal.send("\x1b[1;5H")
        terminal.expect("site-000.example.com")
        preview: Path = Path(__file__).resolve().parent.parent / ".cache/shell-sites-preview.txt"
        preview.write_text(terminal.text(), encoding="utf-8")
        terminal.command("/help", "Your local Clash workspace")
        terminal.until(
            lambda: (
                "Live Clash connections" not in terminal.text() and "site-" not in terminal.text()
            ),
            5.0,
        )
        terminal.command("/nodes", "Showing: 2")
        terminal.expect("DEMO1【0.3】 [v6]")
        terminal.expect("DEMO2【0.6】")
        node_rows: list[str] = [
            row for row in terminal.screen.display if " n" in row and "DEMO" in row
        ]
        if len(node_rows) != 2 or len({row.index("DEMO") for row in node_rows}) != 1:
            raise AssertionError(f"IPv6 and ordinary node labels did not align: {terminal.text()}")
        if not any("DEMO1【0.3】 [v6]" in row for row in node_rows):
            raise AssertionError("IPv6 node metadata wrapped onto another line")
        if "Your local Clash workspace" in terminal.text():
            raise AssertionError("Help accumulated in the node panel")
        verify_selection(terminal, "DEMO1【0.3】 [v6]")
        terminal.quit()
        if b"\x1b[?1000l" not in terminal.transcript[-1000:]:
            raise AssertionError("Mouse capture was not released on exit")


def main() -> None:
    parser: argparse.ArgumentParser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fixture", action="store_true")
    arguments: argparse.Namespace = parser.parse_args()
    if arguments.fixture:
        asyncio.run(run_fixture())
        return
    for name in (NODE, GROUP, "🚀 Acceleration", "🇯🇵 日本 JP-M1", "DIRECT"):
        label: str = node_label(name)
        if cell_len(label) != get_cwidth(label):
            raise AssertionError(f"Layout libraries disagree about terminal width: {label!r}")
    copied_rules: str = rules_copy_text(fixture_routing(), "")
    if len(copied_rules.splitlines()) != 261 or GROUP not in copied_rules:
        raise AssertionError("Rule export truncated matching rules or raw policy names")
    original_clipboard: str = clipboard_snapshot()
    try:
        with tempfile.TemporaryDirectory(prefix="clashctl-terminal-test-") as temporary:
            verify_terminal(Path(temporary))
    finally:
        restore_clipboard(original_clipboard)
    print(
        "PASS: compact layout, mouse wheel, command history, paging, refresh, resize, "
        "mouse selection, wide-character selection, clipboard, terminal restoration"
    )


if __name__ == "__main__":
    main()
