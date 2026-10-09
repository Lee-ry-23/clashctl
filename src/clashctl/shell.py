"""Full-screen command shell with completion and an owned hourly measurement worker."""

import asyncio
import logging
import sys
import threading
import time
from collections.abc import Callable, Iterable
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from queue import Empty, SimpleQueue
from typing import TYPE_CHECKING, Literal, cast

from prompt_toolkit.application import Application
from prompt_toolkit.auto_suggest import AutoSuggestFromHistory
from prompt_toolkit.buffer import Buffer
from prompt_toolkit.completion import CompleteEvent, Completer, Completion
from prompt_toolkit.data_structures import Point
from prompt_toolkit.document import Document
from prompt_toolkit.filters import Condition, has_completions, is_done
from prompt_toolkit.formatted_text import FormattedText
from prompt_toolkit.history import InMemoryHistory
from prompt_toolkit.key_binding import KeyBindings, KeyPressEvent
from prompt_toolkit.key_binding.bindings.mouse import load_mouse_bindings
from prompt_toolkit.key_binding.key_bindings import Binding
from prompt_toolkit.keys import Keys
from prompt_toolkit.layout import (
    ConditionalContainer,
    Float,
    FloatContainer,
    HSplit,
    Layout,
    Window,
)
from prompt_toolkit.layout.controls import FormattedTextControl
from prompt_toolkit.layout.margins import ScrollbarMargin
from prompt_toolkit.layout.menus import CompletionsMenu
from prompt_toolkit.mouse_events import MouseButton, MouseEvent, MouseEventType
from prompt_toolkit.styles import Style
from prompt_toolkit.widgets import Box, Frame, TextArea

from clashctl.controller import ClashClient
from clashctl.models import (
    BenchmarkCancelled,
    ClashError,
    ConfigurationError,
    Settings,
    choose_group,
    proxy_by_name,
)
from clashctl.monitor import (
    BackgroundMonitor,
    CacheEvent,
    ContextEvent,
    EventLogHandler,
    LiveContext,
    MonitorEvent,
    MonitorLease,
    MonitorOptions,
    NoticeEvent,
    ScanEvent,
    StatusEvent,
    WatchStatus,
    group_nodes,
    load_context,
    monitored_nodes,
)
from clashctl.routing import (
    apply_rules,
    check_hosts,
    normalize_host,
    observed_hosts,
    plan_rules,
    undo_rules,
)
from clashctl.routing_display import rules_copy_text, sites_copy_text
from clashctl.routing_models import Connection, RuleAudit, RulePlan, RuntimeRule, empty_routing
from clashctl.service_checks import (
    OpenAICache,
    ProbeEvent,
    ProbeStatusEvent,
    merge_openai_results,
    read_openai_cache,
    run_openai_checks,
    write_openai_cache,
)
from clashctl.shell_commands import (
    ShellCommand,
    ShellState,
    cached_best,
    command_hints,
    group_id,
    node_id,
    parse_command,
    resolve_reference,
)
from clashctl.shell_display import PanelRevision, panel_render_state, render_panel, visible_nodes
from clashctl.terminal_display import copy_to_clipboard, display_name, node_label, plain_text
from clashctl.terminal_panel import (
    PanelControl,
    PanelSelection,
    PanelText,
    TextFragment,
    clamp_point,
    mouse_hovered,
    mouse_released,
    prepare_panel,
    selected_text,
    wheel_rows,
)

if TYPE_CHECKING:
    from prompt_toolkit.key_binding.key_bindings import NotImplementedOrNone


@dataclass(frozen=True)
class FrameRevision:
    header: tuple[TextFragment, ...]
    watch: str
    notice: tuple[TextFragment, ...]
    footer: str


class ShellCompleter(Completer):
    """Complete command names and stable ASCII IDs using current node/group names as hints."""

    def __init__(self, state: Callable[[], ShellState]) -> None:
        self.state: Callable[[], ShellState] = state

    def get_completions(
        self, document: Document, complete_event: CompleteEvent
    ) -> Iterable[Completion]:
        text: str = document.text_before_cursor
        if not text and not complete_event.completion_requested:
            return
        command, separator, argument = text.partition(" ")
        if not separator:
            for hint in command_hints():
                value: str = (
                    "/" + hint.name if command.startswith("/") or not command else hint.name
                )
                if value.startswith(command.casefold()):
                    yield Completion(
                        value, start_position=-len(command), display_meta=hint.description
                    )
            return
        name: str = command.lstrip("/").casefold()
        key: str = argument.casefold()
        state: ShellState = self.state()
        choices: tuple[tuple[str, str], ...] = ()
        if name in {"connect", "openai"}:
            choices = tuple(
                (node_id(node), node) for node in visible_nodes(replace(state, keyword=""))
            )
            if name == "openai":
                choices = (("all", "all"), ("stop", "stop"), *choices)
        elif name == "group" and state.context is not None:
            choices = tuple((group_id(group.name), group.name) for group in state.context.groups)
        elif name == "mode":
            choices = tuple((mode, mode) for mode in ("rule", "global", "direct"))
        elif name == "watch":
            choices = tuple((value, value) for value in ("status", "pause", "resume", "interval"))
        elif name == "rules":
            choices = (
                ("view", "All routing rules"),
                ("sites", "Active websites and matched rules"),
                ("check", "Preview rule changes"),
                ("apply", "Apply the checked changes"),
                ("refresh", "Check and apply rule changes"),
                ("undo", "Restore the previous rules"),
            )
        for identifier, label in choices:
            if key in identifier.casefold() or key in label.casefold():
                yield Completion(
                    identifier,
                    start_position=-len(argument),
                    display=(
                        f"{identifier}  {node_label(label)}"
                        if name != "rules" and identifier != label
                        else identifier
                    ),
                    display_meta=label if name == "rules" else "",
                )


class TerminalShell:
    """Own terminal I/O and serialize foreground controller actions without blocking input."""

    def __init__(self, settings: Settings, options: MonitorOptions) -> None:
        self.settings: Settings = settings
        self.events: SimpleQueue[MonitorEvent] = SimpleQueue()
        self.monitor: BackgroundMonitor = BackgroundMonitor(settings, options, self.events)
        self.state: ShellState = ShellState(
            None,
            None,
            None,
            WatchStatus("starting", 0, 0, "Connecting to Clash", None),
            "help",
            "",
            "Ready. Type /help or press Tab.",
            "info",
            (),
            empty_routing(),
            None,
            None,
            "",
        )
        self.action_cancel: threading.Event = threading.Event()
        self.foreground: asyncio.Task[None] | None = None
        self.openai_task: asyncio.Task[None] | None = None
        self.openai_cancel: threading.Event = threading.Event()
        self.closing: bool = False
        self.has_command: bool = False
        self.body_text: str = ""
        self.panel_text: PanelText = prepare_panel("")
        self.panel_revision: PanelRevision | None = None
        self.frame_revision: FrameRevision | None = None
        self.panel_state: ShellState = self.state
        self.selection_mode: bool = False
        self.selection: PanelSelection | None = None
        self.dragging: bool = False
        self.clipboard_lock: asyncio.Lock = asyncio.Lock()
        self.clipboard_task: asyncio.Task[None] | None = None
        self.last_width: int = 0
        self.last_render: float = 0.0
        self.last_watch_line: str = ""
        self.completer: ShellCompleter = ShellCompleter(self.get_state)
        self.input: TextArea = TextArea(
            height=1,
            multiline=False,
            prompt="› ",
            completer=self.completer,
            complete_while_typing=True,
            auto_suggest=AutoSuggestFromHistory(),
            history=InMemoryHistory(),
            accept_handler=self.accept,
            style="class:input",
        )
        self.body: Window = Window(
            PanelControl(
                lambda: self.panel_text,
                lambda: self.selection,
                self.panel_cursor,
                self.panel_mouse,
            ),
            wrap_lines=False,
            right_margins=[ScrollbarMargin(display_arrows=True)],
        )
        bindings: KeyBindings = KeyBindings()
        bindings.add("tab")(self.complete)
        bindings.add("s-tab")(self.complete_previous)
        bindings.add("c-c")(self.clear_input)
        bindings.add("c-d")(self.quit_key)
        bindings.add("pageup")(self.page_up)
        bindings.add("pagedown")(self.page_down)
        bindings.add("c-home")(self.first_page)
        bindings.add("c-end")(self.last_page)
        bindings.add("f2")(self.selection_key)
        bindings.add("escape", filter=Condition(self.has_selection))(self.clear_selection_key)
        bindings.add(Keys.ScrollUp)(self.scroll_up_key)
        bindings.add(Keys.ScrollDown)(self.scroll_down_key)
        bindings.add(Keys.Vt100MouseEvent)(self.mouse_event)
        self.default_mouse_binding: Binding = load_mouse_bindings().get_bindings_for_keys(
            (Keys.Vt100MouseEvent,)
        )[0]
        layout: HSplit = HSplit(
            [
                Window(FormattedTextControl(self.header), height=2, style="class:header"),
                Frame(
                    Box(
                        self.body, padding_left=1, padding_right=1, padding_top=1, padding_bottom=0
                    ),
                    title=" workspace ",
                    style="class:panel",
                ),
                Window(FormattedTextControl(self.watch_line), height=1, style="class:watch"),
                Window(FormattedTextControl(self.notice), height=2),
                Frame(self.input, title=" command ", style="class:entry"),
                Window(
                    FormattedTextControl(self.footer),
                    height=1,
                    style="class:muted",
                ),
            ]
        )
        self.app: Application[None] = Application(
            layout=Layout(
                FloatContainer(
                    layout,
                    floats=[
                        Float(
                            xcursor=True,
                            bottom=4,
                            content=ConditionalContainer(
                                Frame(
                                    CompletionsMenu(max_height=7),
                                    title=" suggestions · Tab ",
                                    style="class:entry",
                                ),
                                filter=has_completions & ~is_done,
                            ),
                        )
                    ],
                ),
                focused_element=self.input,
            ),
            key_bindings=bindings,
            full_screen=True,
            mouse_support=True,
            min_redraw_interval=1 / 60,
            terminal_size_polling_interval=None,
            before_render=self.reflow,
            style=Style.from_dict(
                {
                    "": "bg:default fg:default",
                    "header": "#2563a6",
                    "panel.border": "#667085",
                    "panel.label": "#667085",
                    "entry.border": "#2563a6",
                    "entry.label": "#2563a6",
                    "input": "bg:default fg:default",
                    "watch": "#2563a6",
                    "muted": "#667085",
                    "info": "fg:default",
                    "success": "#21804a",
                    "error": "#b91c1c",
                    "completion-menu": "bg:default fg:default",
                    "completion-menu.completion.current": (
                        "bg:default #2563a6 bold underline noreverse"
                    ),
                    "completion-menu.meta.completion": "bg:default #667085",
                    "completion-menu.meta.completion.current": (
                        "bg:default #2563a6 bold noreverse"
                    ),
                    "scrollbar.background": "bg:default",
                    "scrollbar.button": "bg:default #667085 underline",
                    "auto-suggestion": "#667085",
                    "selection": "bg:#dbeafe #1e3a5f underline",
                }
            ),
        )

    def get_state(self) -> ShellState:
        return self.state

    def header(self) -> FormattedText:
        state: ShellState = self.panel_state if self.display_paused() else self.state
        context: LiveContext | None = state.context
        mode: str = "connecting" if context is None else context.snapshot.mode
        selected: str = "—"
        if context is not None and state.group is not None:
            selected = proxy_by_name(context.snapshot.proxies, state.group).selected or "—"
        return FormattedText(
            [
                ("bold", "  clashctl"),
                ("class:muted", "   /   local network workspace\n"),
                (
                    "",
                    f"  {mode}  ·  {display_name(state.group or 'choose /group')}"
                    f"  ·  {node_label(selected)}",
                ),
            ]
        )

    def watch_line(self) -> str:
        state: ShellState = self.panel_state if self.display_paused() else self.state
        status: WatchStatus = state.watch
        progress: str = f" {status.completed}/{status.total}" if status.total else ""
        next_scan: str = ""
        if status.next_at is not None:
            seconds: float = max(
                0.0, (datetime.fromisoformat(status.next_at) - datetime.now(UTC)).total_seconds()
            )
            next_scan = f" · next in {seconds / 60:.0f}m"
        updated: str = ""
        if state.view == "sites":
            timestamp: str = (
                "waiting"
                if state.routing.checked_at is None
                else datetime.fromisoformat(state.routing.checked_at).astimezone().strftime("%H:%M")
            )
            updated = f" SITES UPDATED {timestamp} ·"
        return (
            f"{updated} WATCH {status.phase.upper()}{progress} · "
            f"{self.monitor.options.interval_seconds / 60:g}m{next_scan}"
            f" · {display_name(status.message)}"
        )

    def notice(self) -> FormattedText:
        return FormattedText([(f"class:{self.state.level}", " " + display_name(self.state.notice))])

    def footer(self) -> str:
        if self.selection is not None:
            return " SELECTED: wheel scroll · Ctrl+C copy · Esc resume"
        if self.selection_mode:
            return " PAUSED: wheel scroll · Drag to select + copy · F2 resume · /copy all"
        return " Wheel scroll · Drag to select + copy · /copy all · Tab · Ctrl+D quit"

    def has_selection(self) -> bool:
        return self.selection is not None

    def display_paused(self) -> bool:
        return self.selection_mode or self.has_selection()

    def mouse_event(self, event: KeyPressEvent) -> "NotImplementedOrNone":
        """Keep wheel events in the result panel even when the pointer is over input."""
        rows: int | None = wheel_rows(event.data)
        if rows is not None:
            self.scroll_panel(rows)
            return None
        if mouse_hovered(event.data):
            return cast("NotImplementedOrNone", NotImplemented)
        self.default_mouse_binding.call(event)
        if self.dragging and mouse_released(event.data):
            self.finish_selection()
        return None

    def panel_mouse(self, event: MouseEvent) -> None:
        if event.button != MouseButton.LEFT:
            return
        point: Point = clamp_point(self.panel_text.lines, event.position)
        if event.event_type == MouseEventType.MOUSE_DOWN:
            self.selection = PanelSelection(point, point)
            self.dragging = True
            self.set_notice("Drag to select. Release to copy; Esc resumes live updates.")
        elif self.dragging and self.selection is not None:
            self.selection = replace(self.selection, cursor=point)
            if event.event_type == MouseEventType.MOUSE_UP:
                self.finish_selection()
            else:
                self.app.invalidate()

    def finish_selection(self) -> None:
        self.dragging = False
        text: str = self.selection_text()
        if text:
            self.queue_selection_copy(text)
        else:
            self.clear_selection()

    def selection_text(self) -> str:
        if self.selection is None:
            return ""
        return selected_text(self.panel_text.lines, self.selection)

    def queue_selection_copy(self, text: str) -> None:
        self.set_notice("Copying selected text… Esc resumes live updates.")
        self.clipboard_task = asyncio.create_task(self.copy_selection(text))
        self.clipboard_task.add_done_callback(self.task_finished)

    async def write_clipboard(self, text: str) -> None:
        async with self.clipboard_lock:
            await asyncio.to_thread(copy_to_clipboard, text)

    async def copy_selection(self, text: str) -> None:
        try:
            await self.write_clipboard(text)
            self.state = replace(
                self.state,
                notice=f"Copied selected text ({len(text)} characters). Esc resumes live updates.",
                level="success",
            )
        except (ClashError, OSError) as error:
            self.state = replace(self.state, notice=str(error), level="error")
        self.app.invalidate()

    def clear_selection(self) -> None:
        self.selection = None
        self.dragging = False
        self.set_notice("Selection cleared.")
        self.redraw()

    def clear_selection_key(self, event: KeyPressEvent) -> None:
        self.selection_mode = False
        self.clear_selection()

    def panel_cursor(self) -> Point:
        return Point(x=0, y=min(self.body.vertical_scroll, self.scroll_limit()))

    def page_height(self) -> int:
        info = self.body.render_info
        return max(1, info.window_height if info is not None else 1)

    def scroll_limit(self) -> int:
        return max(0, len(self.panel_text.lines) - self.page_height())

    def scroll_panel(self, rows: int) -> None:
        self.body.vertical_scroll = max(
            0, min(self.scroll_limit(), self.body.vertical_scroll + rows)
        )
        self.app.invalidate()

    def toggle_selection(self) -> None:
        self.selection_mode = not self.display_paused()
        self.selection = None
        self.dragging = False
        self.state = replace(
            self.state,
            notice=(
                "Display paused. Wheel scrolls; drag and release to copy. F2 resumes updates."
                if self.selection_mode
                else "Live updates resumed."
            ),
            level="info",
        )
        if not self.selection_mode:
            self.redraw()
        self.app.invalidate()

    def selection_key(self, event: KeyPressEvent) -> None:
        self.toggle_selection()

    def reflow(self, app: Application[None]) -> None:
        """Use terminal resize signals instead of repeatedly polling the terminal size."""
        if max(30, app.output.get_size().columns - 7) != self.last_width:
            self.redraw()

    def redraw(self) -> None:
        if self.display_paused():
            return
        width: int = max(30, self.app.output.get_size().columns - 7)
        revision: PanelRevision = PanelRevision(
            panel_render_state(self.state),
            self.monitor.options,
            width,
            int(time.time() // 30) if self.state.view in {"nodes", "rank"} else 0,
        )
        panel_changed: bool = revision != self.panel_revision
        if panel_changed:
            self.body_text = render_panel(self.state, self.monitor.options, width)
            self.panel_text = prepare_panel(self.body_text)
            self.panel_revision = revision
            self.last_render = time.monotonic()
        self.panel_state = self.state
        self.body.vertical_scroll = min(self.body.vertical_scroll, self.scroll_limit())
        self.last_width = width
        self.last_watch_line = self.watch_line()
        frame: FrameRevision = FrameRevision(
            tuple((fragment[0], fragment[1]) for fragment in self.header()),
            self.last_watch_line,
            tuple((fragment[0], fragment[1]) for fragment in self.notice()),
            self.footer(),
        )
        if panel_changed or frame != self.frame_revision:
            self.frame_revision = frame
            self.app.invalidate()

    def set_notice(self, text: str) -> None:
        self.state = replace(self.state, notice=text, level="info")
        self.app.invalidate()

    def accept(self, buffer: Buffer) -> bool:
        text: str = buffer.text.strip()
        if not text:
            return False
        self.has_command = True
        try:
            command: ShellCommand = parse_command(text)
        except ConfigurationError as error:
            self.state = replace(self.state, notice=str(error), level="error")
            return False
        if command.name == "quit":
            self.closing = True
            self.action_cancel.set()
            self.openai_cancel.set()
            self.monitor.request_stop()
            self.app.exit()
        elif self.foreground is not None and not self.foreground.done():
            self.set_notice(
                "Finishing the current controller request. Background scanning is independent."
            )
        else:
            if command.name not in {"copy", "freeze"}:
                self.selection = None
                self.dragging = False
                self.selection_mode = False
                self.body.vertical_scroll = 0
            self.set_notice(f"› {text}")
            self.foreground = asyncio.create_task(self.execute(command))
        return False

    def clear_input(self, event: KeyPressEvent) -> None:
        text: str = self.selection_text()
        if text:
            self.queue_selection_copy(text)
            return
        self.input.buffer.reset()
        self.set_notice("Input cleared. Use /watch pause to stop downloads, or /quit to exit.")

    def complete(self, event: KeyPressEvent) -> None:
        buffer: Buffer = event.current_buffer
        if not buffer.text:
            buffer.start_completion()
        elif buffer.complete_state is not None and buffer.complete_state.completions:
            buffer.complete_next()
        else:
            choices: tuple[Completion, ...] = tuple(
                self.completer.get_completions(
                    buffer.document, CompleteEvent(completion_requested=True)
                )
            )
            if choices:
                buffer.apply_completion(choices[0])

    def complete_previous(self, event: KeyPressEvent) -> None:
        event.current_buffer.complete_previous()

    def quit_key(self, event: KeyPressEvent) -> None:
        self.closing = True
        self.action_cancel.set()
        self.openai_cancel.set()
        self.monitor.request_stop()
        self.app.exit()

    def page_up(self, event: KeyPressEvent) -> None:
        self.scroll_panel(-max(1, self.page_height() - 2))

    def scroll_up_key(self, event: KeyPressEvent) -> None:
        self.scroll_panel(-3)

    def scroll_down_key(self, event: KeyPressEvent) -> None:
        self.scroll_panel(3)

    def page_down(self, event: KeyPressEvent) -> None:
        self.scroll_panel(max(1, self.page_height() - 2))

    def first_page(self, event: KeyPressEvent) -> None:
        self.scroll_panel(-self.scroll_limit())

    def last_page(self, event: KeyPressEvent) -> None:
        self.scroll_panel(self.scroll_limit())

    async def copy_panel(self) -> None:
        state: ShellState = self.panel_state
        text: str
        if state.view == "sites":
            text = sites_copy_text(state.routing, state.keyword)
        elif state.view == "rules":
            text = rules_copy_text(state.routing, state.keyword)
        else:
            text = plain_text(self.body_text)
        await self.write_clipboard(text)
        self.state = replace(
            self.state,
            notice="Copied current results to clipboard, including rows outside the viewport.",
            level="success",
        )
        self.app.invalidate()

    async def fresh_context(self) -> LiveContext:
        context: LiveContext = await asyncio.to_thread(load_context, self.settings)
        self.apply_context(context)
        return context

    async def openai_command(self, arguments: tuple[str, ...]) -> None:
        if arguments == ("stop",):
            if self.openai_task is None or self.openai_task.done():
                raise ConfigurationError("No independent OpenAI check is running.")
            self.openai_cancel.set()
            self.set_notice("Stopping OpenAI checks; finished node results are retained.")
            return
        if self.openai_task is not None and not self.openai_task.done():
            raise ConfigurationError(
                "OpenAI checks are already running. Use /openai stop to cancel."
            )
        context: LiveContext = await self.fresh_context()
        if self.closing:
            raise BenchmarkCancelled("Shell closed before OpenAI checks started")
        nodes: tuple[str, ...] = monitored_nodes(context, self.monitor.options)
        if arguments and arguments != ("all",):
            node: str = resolve_reference(
                " ".join(arguments), tuple((node_id(name), name) for name in context.nodes)
            )
            nodes = (node,)
        self.openai_cancel.clear()
        self.state = replace(
            self.state,
            view=self.state.view if self.state.view in {"nodes", "rank"} else "nodes",
            keyword="",
            service_message=f"OpenAI 0/{len(nodes)} · checking API connectivity",
            notice="OpenAI checks started. No speed download. Keep using other commands.",
        )
        self.openai_task = asyncio.create_task(self.check_openai_nodes(context, nodes))
        self.openai_task.add_done_callback(self.task_finished)

    async def check_openai_nodes(self, context: LiveContext, nodes: tuple[str, ...]) -> None:
        try:
            await asyncio.to_thread(
                run_openai_checks,
                self.settings,
                context.snapshot,
                nodes,
                min(self.monitor.options.timeout, 4.0),
                self.events.put,
                self.openai_cancel.is_set,
            )
        except BenchmarkCancelled:
            self.events.put(
                ProbeStatusEvent("OpenAI checks stopped; completed results retained.", "info")
            )
        except (ClashError, OSError) as error:
            self.events.put(ProbeStatusEvent("OpenAI checks failed: " + str(error), "error"))
            self.events.put(NoticeEvent(str(error)))
        if not self.closing:
            self.redraw()

    def apply_context(self, context: LiveContext) -> None:
        group: str | None = self.state.group
        if group is not None and group not in {item.name for item in context.groups}:
            group = None
        if group is None and context.snapshot.mode != "direct":
            try:
                group = choose_group(context.snapshot, None)
            except ConfigurationError as error:
                self.events.put(NoticeEvent(f"{error} Use /groups then /group."))
        self.state = replace(self.state, context=context, group=group)

    async def working_context(self) -> tuple[LiveContext, str]:
        context: LiveContext = await self.fresh_context()
        group: str | None = self.state.group
        if group is None:
            raise ConfigurationError("Choose a working group with /groups and /group <id> first.")
        return context, group

    async def select_node(self, group: str, node: str) -> None:
        client: ClashClient = ClashClient(self.settings)
        path: tuple[tuple[str, str], ...] = await asyncio.to_thread(client.select_node, group, node)
        context: LiveContext = await self.fresh_context()
        message: str = "; ".join(f"{name} → {member}" for name, member in path)
        if context.snapshot.mode == "direct":
            message += ". Direct mode is active; use /mode rule or /mode global to proxy traffic."
        elif context.snapshot.mode == "global":
            message += ". Global traffic follows GLOBAL. Existing connections retain their routes."
        else:
            message += ". New connections matching this group use the selection."
        self.state = replace(self.state, notice="Verified: " + message, level="success")

    async def execute(self, command: ShellCommand) -> None:
        try:
            self.state = replace(self.state, level="info")
            arguments: tuple[str, ...] = command.arguments
            name: str = command.name
            if (
                name
                in {"help", "clear", "status", "groups", "best", "bench", "logs", "copy", "freeze"}
                and arguments
            ):
                raise ConfigurationError(f"/{name} takes no arguments. Use /help for syntax.")
            if name == "copy":
                await self.copy_panel()
            elif name == "freeze":
                self.toggle_selection()
            elif name in {"help", "clear"}:
                self.state = replace(
                    self.state, view="help", keyword="", notice="Ready.", level="info"
                )
            elif name == "status":
                await self.fresh_context()
                self.state = replace(
                    self.state, view="status", notice="Live controller state refreshed."
                )
            elif name in {"nodes", "rank", "groups", "logs"}:
                self.state = replace(
                    self.state,
                    view=cast(Literal["nodes", "rank", "groups", "logs"], name),
                    keyword=" ".join(arguments),
                    notice="Cached view. Background downloads continue independently.",
                    level="info",
                )
            elif name == "group":
                if not arguments:
                    self.state = replace(self.state, view="groups")
                else:
                    context: LiveContext = await self.fresh_context()
                    group: str = resolve_reference(
                        " ".join(arguments),
                        tuple((group_id(item.name), item.name) for item in context.groups),
                    )
                    self.state = replace(
                        self.state,
                        group=group,
                        view="nodes",
                        keyword="",
                        notice=f"Working group: {group}. Routing mode retained.",
                        level="success",
                    )
            elif name == "connect":
                if not arguments:
                    raise ConfigurationError(
                        "Usage: /connect <node ID or unique name>. Tab completes nodes."
                    )
                context, group = await self.working_context()
                members: tuple[str, ...] = group_nodes(context, group)
                node: str = resolve_reference(
                    " ".join(arguments), tuple((node_id(item), item) for item in members)
                )
                await self.select_node(group, node)
            elif name == "best":
                context, group = await self.working_context()
                node = cached_best(
                    self.state.cache, context, group, self.monitor.options, datetime.now(UTC)
                )
                await self.select_node(group, node)
            elif name == "mode":
                if len(arguments) != 1 or arguments[0] not in {"rule", "global", "direct"}:
                    raise ConfigurationError("Usage: /mode rule|global|direct")
                await asyncio.to_thread(ClashClient(self.settings).set_mode, arguments[0])
                self.state = replace(self.state, group=None)
                await self.fresh_context()
                self.state = replace(
                    self.state, notice=f"Verified mode: {arguments[0]}", level="success"
                )
            elif name == "bench":
                self.monitor.scan_now()
                self.state = replace(
                    self.state, notice="Background refresh requested. Keep using the shell."
                )
            elif name == "watch":
                self.watch_command(arguments)
            elif name == "openai":
                await self.openai_command(arguments)
            elif name == "sites":
                await self.sites_command(arguments)
            elif name == "rules":
                await self.rules_command(arguments)
            self.redraw()
        except (ClashError, OSError) as error:
            self.state = replace(self.state, notice=str(error), level="error")
            self.redraw()
            self.app.invalidate()

    async def sites_command(self, arguments: tuple[str, ...]) -> None:
        """Show current connections and their matched rules, with an optional keyword filter."""
        await self.refresh_connections()
        self.state = replace(
            self.state,
            view="sites",
            keyword=" ".join(arguments),
            notice="Live Clash traffic. TUN-off applications may bypass this list.",
        )

    async def refresh_connections(self) -> None:
        connections: tuple[Connection, ...] = await asyncio.to_thread(
            ClashClient(self.settings).connections
        )
        self.update_connections(connections)

    def update_connections(self, connections: tuple[Connection, ...]) -> None:
        self.state = replace(
            self.state,
            routing=replace(
                self.state.routing,
                connections=connections,
                observed=observed_hosts(connections),
                checked_at=datetime.now(UTC).isoformat(),
                error=None,
            ),
        )

    async def connections_loop(self) -> None:
        with ClashClient(self.settings) as client:
            while not self.closing:
                if self.state.view != "sites" or self.display_paused():
                    await asyncio.sleep(0.5)
                    continue
                try:
                    self.update_connections(await self.read_connections(client))
                except (ClashError, OSError) as error:
                    message: str = str(error)
                    if message != self.state.routing.error:
                        self.events.put(NoticeEvent("Connection refresh failed: " + message))
                    self.state = replace(
                        self.state, routing=replace(self.state.routing, error=message)
                    )
                if self.state.view == "sites":
                    self.redraw()
                await asyncio.sleep(5.0)

    async def read_connections(self, client: ClashClient) -> tuple[Connection, ...]:
        """Finish an in-flight read before closing its reused HTTP session on cancellation."""
        task: asyncio.Task[tuple[Connection, ...]] = asyncio.create_task(
            asyncio.to_thread(client.connections)
        )
        try:
            return await asyncio.shield(task)
        except asyncio.CancelledError:
            await task
            raise

    async def rules_command(self, arguments: tuple[str, ...]) -> None:
        action: str = arguments[0] if arguments else "view"
        if action == "sites":
            await self.sites_command(arguments[1:])
            return
        directory = self.monitor.options.directory
        if action in {"check", "refresh"}:
            context, group = await self.working_context()
            await self.refresh_connections()
            hosts: tuple[str, ...] = (
                tuple(dict.fromkeys(normalize_host(value) for value in arguments[1:]))
                if len(arguments) > 1
                else self.state.routing.observed
            )
            self.set_notice(f"Checking {len(hosts)} websites via DIRECT and the selected VPN node…")
            audits: tuple[RuleAudit, ...] = await asyncio.to_thread(
                check_hosts,
                self.settings,
                context.snapshot,
                group,
                hosts,
                self.action_cancel.is_set,
            )
            plan: RulePlan = await asyncio.to_thread(
                plan_rules,
                self.settings,
                context.snapshot,
                context.digest,
                group,
                audits,
                directory,
            )
            self.state = replace(
                self.state, view="rulecheck", routing=replace(self.state.routing, plan=plan)
            )
            if action == "check":
                self.set_notice(
                    "Preview ready. /rules apply activates it; unconfirmed routes are retained."
                )
                return
            action = "apply"
        if action == "apply":
            if len(arguments) > 1 and arguments[0] != "refresh":
                raise ConfigurationError("Usage: /rules apply")
            plan_to_apply: RulePlan | None = self.state.routing.plan
            if plan_to_apply is None:
                raise ConfigurationError("Run /rules check first, or use /rules refresh")
            backup = await asyncio.to_thread(
                apply_rules, self.settings, plan_to_apply, directory, self.action_cancel.is_set
            )
            await self.fresh_context()
            self.set_notice(
                f"Rules applied and verified. /rules undo restores backup: {backup.name}"
            )
            self.monitor.refresh_configuration()
        elif action == "undo":
            if len(arguments) != 1:
                raise ConfigurationError("Usage: /rules undo")
            await asyncio.to_thread(undo_rules, self.settings, directory)
            await self.fresh_context()
            self.state = replace(self.state, routing=replace(self.state.routing, plan=None))
            self.set_notice(
                "Previous rules restored and verified. Existing connections keep their routes."
            )
            self.monitor.refresh_configuration()
        else:
            rules: tuple[RuntimeRule, ...] = await asyncio.to_thread(
                ClashClient(self.settings).rules
            )
            keyword: str = " ".join(arguments[1:] if action == "view" else arguments)
            self.state = replace(
                self.state,
                view="rules",
                keyword=keyword,
                routing=replace(self.state.routing, rules=rules),
                notice=(
                    f"Filtering rules by {keyword!r}. /rules view clears the filter."
                    if keyword
                    else f"Viewing {len(rules)} routing rules. /sites shows current website rules."
                ),
            )

    def watch_command(self, arguments: tuple[str, ...]) -> None:
        if not arguments or arguments == ("status",):
            self.state = replace(
                self.state, view="watch", notice="Background schedule and traffic budget."
            )
        elif arguments == ("pause",):
            self.monitor.pause()
            self.set_notice("Pausing downloads. The last complete cache is retained.")
        elif arguments == ("resume",):
            self.monitor.resume()
            self.set_notice("Background scans resumed. A refresh is requested.")
        elif len(arguments) == 2 and arguments[0] == "interval":
            try:
                minutes: float = float(arguments[1])
            except ValueError as error:
                raise ConfigurationError("Interval must be a number of minutes") from error
            self.monitor.set_interval(minutes * 60)
            self.set_notice(f"Scan interval set to {minutes:g} minutes for this session.")
        else:
            raise ConfigurationError("Usage: /watch status|pause|resume|interval <minutes>")

    async def collect_events(self) -> bool:
        """Serialize benchmark and independent probe writes through one event-loop owner."""
        changed: bool = False
        previous: OpenAICache | None = self.state.services
        while True:
            try:
                event: MonitorEvent = self.events.get_nowait()
            except Empty:
                break
            changed = True
            if isinstance(event, ContextEvent):
                self.apply_context(event.context)
            elif isinstance(event, CacheEvent):
                self.state = replace(self.state, cache=event.cache)
                if not self.has_command:
                    self.state = replace(self.state, view="rank")
            elif isinstance(event, ScanEvent):
                self.state = replace(self.state, scan=event.report)
                if not self.has_command:
                    self.state = replace(self.state, view="rank")
                if (
                    self.state.context is not None
                    and event.report.source_digest == self.state.context.digest
                ):
                    self.state = replace(
                        self.state,
                        services=merge_openai_results(
                            self.state.services,
                            event.report.source_digest,
                            tuple(
                                (result.node, result.openai)
                                for result in event.report.results
                                if result.openai is not None
                            ),
                        ),
                    )
            elif isinstance(event, ProbeEvent):
                if self.state.context is None or self.state.context.digest != event.source_digest:
                    self.events.put(
                        NoticeEvent(
                            "OpenAI result discarded: configuration changed. Run /openai again."
                        )
                    )
                    continue
                phase: str = (
                    "stopped"
                    if self.openai_cancel.is_set()
                    else "complete"
                    if event.completed == event.total
                    else "checking"
                )
                self.state = replace(
                    self.state,
                    services=merge_openai_results(
                        self.state.services, event.source_digest, ((event.node, event.result),)
                    ),
                    service_message=(
                        f"OpenAI {phase} {event.completed}/{event.total}"
                        f" · {node_label(event.node)} · {event.result.status}"
                    ),
                )
            elif isinstance(event, StatusEvent):
                self.state = replace(self.state, watch=event.status)
            elif isinstance(event, ProbeStatusEvent):
                self.state = replace(
                    self.state,
                    service_message=event.message,
                    notice=event.message,
                    level=event.level,
                )
            else:
                timestamp: str = datetime.now().strftime("%H:%M:%S")
                self.state = replace(
                    self.state, logs=(*self.state.logs, timestamp + " " + event.message)[-30:]
                )
        if self.state.services is not None and self.state.services != previous:
            await asyncio.to_thread(
                write_openai_cache,
                self.state.services,
                self.monitor.options.directory / "openai-cache.json",
            )
        return changed

    async def refresh(self) -> None:
        while not self.closing:
            changed: bool = await self.collect_events()
            if changed or (
                self.state.view in {"nodes", "rank"} and time.monotonic() - self.last_render >= 30.0
            ):
                self.redraw()
            watch_line: str = self.watch_line()
            if not self.display_paused() and watch_line != self.last_watch_line:
                self.last_watch_line = watch_line
                self.app.invalidate()
            if self.foreground is not None and self.foreground.done():
                failure: BaseException | None = self.foreground.exception()
                if failure is not None:
                    self.app.exit(exception=failure)
                    return
            active: bool = self.state.watch.phase == "scanning" or (
                self.openai_task is not None and not self.openai_task.done()
            )
            await asyncio.sleep(0.2 if active else 1.0)

    async def run(self) -> None:
        services: OpenAICache | None = await asyncio.to_thread(
            read_openai_cache, self.monitor.options.directory / "openai-cache.json"
        )
        self.state = replace(self.state, services=services)
        self.redraw()
        self.monitor.start()
        refresh: asyncio.Task[None] = asyncio.create_task(self.refresh())
        refresh.add_done_callback(self.task_finished)
        connections: asyncio.Task[None] = asyncio.create_task(self.connections_loop())
        connections.add_done_callback(self.task_finished)
        try:
            await self.app.run_async(set_exception_handler=False)
        except EOFError:
            self.closing = True
        finally:
            self.action_cancel.set()
            self.openai_cancel.set()
            self.monitor.request_stop()
            connections.cancel()
            try:
                await connections
            except asyncio.CancelledError:
                pass
            refresh.cancel()
            try:
                await refresh
            except asyncio.CancelledError:
                pass
            finally:
                try:
                    if self.foreground is not None:
                        await asyncio.shield(self.foreground)
                    self.openai_cancel.set()
                    if self.openai_task is not None:
                        await asyncio.shield(self.openai_task)
                finally:
                    try:
                        if self.clipboard_task is not None:
                            await asyncio.shield(self.clipboard_task)
                    finally:
                        try:
                            await asyncio.to_thread(self.monitor.close)
                        finally:
                            await self.collect_events()

    def task_finished(self, task: asyncio.Task[None]) -> None:
        if not task.cancelled():
            failure: BaseException | None = task.exception()
            if failure is not None and self.app.is_running:
                self.app.exit(exception=failure)


def run_shell(settings: Settings, options: MonitorOptions) -> None:
    """Keep all screen output inside the alternate buffer and release every owned worker on exit."""
    if not sys.stdin.isatty() or not sys.stdout.isatty():
        raise ConfigurationError(
            "The shell requires a terminal. Use clashctl status/bench for scripts."
        )
    with MonitorLease(options.directory):
        shell: TerminalShell = TerminalShell(settings, options)
        logger: logging.Logger = logging.getLogger("clashctl")
        handler: EventLogHandler = EventLogHandler(shell.events)
        previous_propagation: bool = logger.propagate
        logger.addHandler(handler)
        logger.propagate = False
        try:
            asyncio.run(shell.run())
        finally:
            logger.removeHandler(handler)
            logger.propagate = previous_propagation
