"""Scrollable result text with mouse selection independent of terminal scrollback."""

import re
from collections.abc import Callable
from dataclasses import dataclass
from itertools import groupby

from prompt_toolkit.data_structures import Point
from prompt_toolkit.formatted_text import (
    ANSI,
    StyleAndTextTuples,
    to_formatted_text,
)
from prompt_toolkit.formatted_text.utils import split_lines
from prompt_toolkit.layout.controls import UIContent, UIControl
from prompt_toolkit.mouse_events import MouseEvent


@dataclass(frozen=True)
class PanelSelection:
    anchor: Point
    cursor: Point


type TextFragment = tuple[str, str]


@dataclass(frozen=True)
class PanelText:
    fragments: tuple[tuple[TextFragment, ...], ...]
    lines: tuple[str, ...]


def prepare_panel(value: str) -> PanelText:
    """Parse ANSI once and combine adjacent styles, retaining exact selection coordinates."""
    fragments: tuple[tuple[TextFragment, ...], ...] = tuple(
        tuple(
            (style, "".join(fragment[1] for fragment in grouped))
            for style, grouped in groupby(line, key=lambda fragment: fragment[0])
        )
        for line in split_lines(to_formatted_text(ANSI(value)))
    )
    return PanelText(fragments, tuple("".join(text for _, text in line) for line in fragments))


def clamp_point(lines: tuple[str, ...], point: Point) -> Point:
    row: int = max(0, min(len(lines) - 1, point.y))
    return Point(x=max(0, min(len(lines[row]), point.x)), y=row)


def selection_bounds(selection: PanelSelection) -> tuple[Point, Point]:
    if (selection.anchor.y, selection.anchor.x) <= (selection.cursor.y, selection.cursor.x):
        return selection.anchor, selection.cursor
    return selection.cursor, selection.anchor


def selected_text(lines: tuple[str, ...], selection: PanelSelection) -> str:
    start, end = selection_bounds(selection)
    if start.y == end.y:
        return lines[start.y][start.x : end.x].rstrip()
    parts: tuple[str, ...] = (
        lines[start.y][start.x :],
        *lines[start.y + 1 : end.y],
        lines[end.y][: end.x],
    )
    return "\n".join(part.rstrip() for part in parts)


def line_fragments(
    fragments: tuple[TextFragment, ...], row: int, selection: PanelSelection | None
) -> StyleAndTextTuples:
    """Highlight only a requested viewport row, without visiting off-screen content."""
    if selection is None:
        return [(style, text) for style, text in fragments]
    start, end = selection_bounds(selection)
    if not start.y <= row <= end.y:
        return [(style, text) for style, text in fragments]
    output: StyleAndTextTuples = []
    column: int = 0
    for style, text in fragments:
        lower: int = start.x if row == start.y else 0
        upper: int = end.x if row == end.y else column + len(text)
        left: int = max(0, min(len(text), lower - column))
        right: int = max(left, min(len(text), upper - column))
        for token in (
            (style, text[:left]),
            (style + " class:selection", text[left:right]),
            (style, text[right:]),
        ):
            if token[1]:
                output.append(token)
        column += len(text)
    return output


def mouse_code(data: str) -> int | None:
    """Decode the button code shared by X10, SGR, and urxvt mouse packets."""
    if data.startswith("\x1b[M") and len(data) == 6:
        return ord(data[3]) - 32
    match: re.Match[str] | None = re.fullmatch(r"\x1b\[(<?)(\d+);\d+;\d+[Mm]", data)
    if match is None:
        return None
    return int(match.group(2)) - (0 if match.group(1) else 32)


def wheel_rows(data: str) -> int | None:
    code: int | None = mouse_code(data)
    if code is None:
        return None
    button: int = code & ~(4 | 8 | 16)
    if button == 64:
        return -3
    if button == 65:
        return 3
    return None


def mouse_released(data: str) -> bool:
    code: int | None = mouse_code(data)
    return code is not None and (data.endswith("m") or code & 3 == 3)


def mouse_hovered(data: str) -> bool:
    code: int | None = mouse_code(data)
    return code is not None and bool(code & 32) and code & 3 == 3 and not data.endswith("m")


class PanelControl(UIControl):
    """Receive character coordinates from Window while keeping command input focused."""

    def __init__(
        self,
        text: Callable[[], PanelText],
        selection: Callable[[], PanelSelection | None],
        cursor: Callable[[], Point],
        mouse: Callable[[MouseEvent], None],
    ) -> None:
        self.text: Callable[[], PanelText] = text
        self.selection: Callable[[], PanelSelection | None] = selection
        self.cursor: Callable[[], Point] = cursor
        self.mouse: Callable[[MouseEvent], None] = mouse

    def create_content(self, width: int, height: int) -> UIContent:
        text: PanelText = self.text()
        selection: PanelSelection | None = self.selection()
        return UIContent(
            get_line=lambda row: line_fragments(text.fragments[row], row, selection),
            line_count=len(text.lines),
            cursor_position=self.cursor(),
            show_cursor=False,
        )

    def mouse_handler(self, mouse_event: MouseEvent) -> None:
        self.mouse(mouse_event)
