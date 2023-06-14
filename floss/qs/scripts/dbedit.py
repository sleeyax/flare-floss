import json
import asyncio
import logging
import pathlib
import textwrap
import dataclasses
from typing import Any, Dict, List, Literal, Sequence
from dataclasses import dataclass

import msgspec
import msgspec.json
from textual import on
from textual.app import App, ComposeResult
from textual.events import Click, Mount
from textual.screen import Screen
from textual.widget import Widget
from textual.binding import Binding
from textual.widgets import Input, Label, Button, Footer, Static, ListItem, ListView
from textual.containers import Vertical, Horizontal

import floss.qs.db.gp
import floss.qs.db.oss
import floss.qs.db.expert
import floss.qs.db.winapi
from floss.qs.db.gp import StringHashDatabase, StringGlobalPrevalenceDatabase
from floss.qs.db.oss import OpenSourceString, OpenSourceStringDatabase
from floss.qs.db.expert import ExpertStringDatabase
from floss.qs.db.winapi import WindowsApiStringDatabase

logger = logging.getLogger("floss.qs.dbedit")


@dataclass(frozen=True)
class DatabaseDescriptor:
    type: str
    path: pathlib.Path


@dataclass(frozen=True)
class DatabaseOperation:
    database: DatabaseDescriptor
    op: Literal["add", "remove"]

    # database-specific type, like OpenSourceString for OpenSourceStringDatabase
    string: Any


Database = (
    ExpertStringDatabase
    | StringGlobalPrevalenceDatabase
    | StringHashDatabase
    | WindowsApiStringDatabase
    | OpenSourceStringDatabase
)


class DataclassJSONEncoder(json.JSONEncoder):
    def default(self, o):
        if dataclasses.is_dataclass(o):
            return dataclasses.asdict(o)
        elif isinstance(o, pathlib.Path):
            return str(o)
        elif isinstance(o, msgspec.Struct):
            return json.loads(msgspec.json.encode(o).decode("utf-8"))
        return super().default(o)


from rich.text import Text
from rich.style import Style
from rich.table import Table
from rich.segment import Segment
from textual.strip import Strip
from textual.geometry import Size
from textual.reactive import reactive
from textual.containers import VerticalScroll
from textual.scroll_view import ScrollView


def render_string(s: str):
    return json.dumps(s)[1:-1]


from textual.message import Message


async def replace_one(self: Widget, query: str, widget: Widget):
    existing = self.query_one(query)
    container = existing.parent
    assert container is not None

    # mount then remove so that we can maintain the order of widgets
    await container.mount(widget, after=existing)
    await existing.remove()


class VirtualList(ScrollView):
    selected_index = reactive(0)

    COMPONENT_CLASSES = {
        "virtuallist--selected",
        "virtuallist--unselected",
    }

    DEFAULT_CSS = """
        VirtualList {
        }

        VirtualList .virtuallist--selected {
            background: $primary;
        }

        VirtualList .virtuallist--unselected {
        }
    """

    def __init__(self, items: Sequence[Any], *args, **kwargs):
        self.items = items
        super().__init__(*args, **kwargs)

        max_width = max((len(str(item)) for item in self.items), default=0)
        self.virtual_size = Size(width=max_width, height=len(self.items))

    def render_line(self, y: int) -> Strip:
        scroll_x, scroll_y = self.scroll_offset
        row_index = y + scroll_y

        if row_index >= len(self.items):
            return Strip.blank(self.size.width)

        item = self.items[row_index]
        s = str(item)

        if row_index == self.selected_index:
            style = self.get_component_rich_style("virtuallist--selected")
        else:
            style = self.get_component_rich_style("virtuallist--unselected")

        segments = [Segment(s, style=style)]

        strip = Strip(segments)
        if scroll_x >= strip.cell_length:
            return Strip.blank(self.size.width)

        strip = strip.crop(scroll_x, scroll_x + self.size.width)
        return strip

    class ItemSelected(Message):
        def __init__(self, item) -> None:
            self.item = item
            super().__init__()

    @on(Click)
    def on_row_selected(self, event):
        scroll_x, scroll_y = self.scroll_offset
        row_index = event.y + scroll_y

        if row_index >= len(self.items):
            return Strip.blank(self.size.width)

        item = self.items[row_index]
        event.stop()

        self.selected_index = row_index
        self.post_message(self.ItemSelected(item))


class InlineButton(Static):
    DEFAULT_CSS = """
        InlineButton {
            margin-left: 1;
            margin-right: 1;
        }

        InlineButton:hover {
            background: $primary;
        }
    """

    def __init__(self, label: str, *args, **kwargs):
        self.label = label
        super().__init__(*args, **kwargs)
        self.styles.width = len(self.label) + 4

    def render(self) -> Text:
        ret = Text()

        ret.append_text(Text(f"[ ", style=Style(color="grey0")))
        ret.append_text(Text(self.label, style=Style(color="blue")))
        ret.append_text(Text(f" ]", style=Style(color="grey0")))

        return ret

    @on(Click)
    def on_click(self, ev):
        ev.stop()
        self.post_message(Button.Pressed(self))


class OSSDatabaseView(Widget):
    filter: str = reactive("")
    visible_strings: List[OpenSourceString] = reactive([])

    DEFAULT_CSS = """
        OSSDatabaseView {
            width: 1fr;
            height: 1fr;
            layout: vertical;
        }

        OSSDatabaseView StringMetadataView {
            height: 11;
        }

        OSSDatabaseView Vertical.header {
            height: 9;
        }

        OSSDatabaseView Vertical.header InlineButton.add-button {
            margin-top: 1;
            margin-left: 1;
        }
    """

    def __init__(self, descriptor: DatabaseDescriptor, database: OpenSourceStringDatabase, *args, **kwargs):
        self.descriptor = descriptor
        self.database = database
        super().__init__(*args, **kwargs)

        self.strings = list(sorted(self.database.metadata_by_string.values(), key=lambda x: x.string))

    class StringMetadataView(Static):
        def __init__(self, string: OpenSourceString, *args, **kwargs):
            self.string = string
            super().__init__(*args, **kwargs)
            self.add_class("dbedit--pane")

        def render(self):
            table = Table(
                title="metadata:\n",
                show_header=False,
                show_lines=False,
                border_style=None,
                box=None,
                title_style=Style(color="blue"),
                title_justify="left",
                width=self.size.width,
            )
            table.add_column("key", style="dim", no_wrap=True, width=20)
            table.add_column("value", no_wrap=True, width=self.size.width - 20)

            table.add_row("string", render_string(self.string.string))
            table.add_row("library name", self.string.library_name)
            table.add_row("library version", self.string.library_version)
            table.add_row("file path", self.string.file_path)
            table.add_row("function name", self.string.function_name)
            table.add_row("line number", str(self.string.line_number))

            return table

    class StringsView(Widget):
        DEFAULT_CSS = """
            StringsView {
                width: 1fr;
                height: 1fr;
                layout: vertical;
                overflow: hidden hidden;
            }

        """

        def __init__(self, strings, *args, **kwargs):
            self.strings = strings
            super().__init__(*args, **kwargs)
            self.add_class("dbedit--pane")

        class StringView:
            def __init__(self, string: OpenSourceString) -> None:
                self.string = string

            def __str__(self) -> str:
                return render_string(self.string.string)

        def compose(self):
            count = len(self.strings) if self.strings else 0
            yield Static(Text(f"strings ({count}):\n", style=Style(color="blue")))
            if self.strings:
                yield VirtualList([self.StringView(metadata) for metadata in self.strings])

        class StringSelected(Message):
            def __init__(self, string: OpenSourceString) -> None:
                self.string = string
                super().__init__()

        @on(VirtualList.ItemSelected)
        def on_string_selected(self, event: VirtualList.ItemSelected):
            item: self.StringView = event.item
            string: OpenSourceString = item.string
            event.stop()

            self.post_message(self.StringSelected(string))

    def compose(self):
        yield Vertical(
            Static(Text(f"database: {self.descriptor.type} {self.descriptor.path.name}\n", style=Style(color="blue"))),
            Input(placeholder="filter..."),
            InlineButton("add string", classes="add-button"),
            classes="dbedit--pane header",
        )

        yield self.StringsView(self.strings)

        yield self.StringMetadataView(self.strings[0])

    @on(StringsView.StringSelected)
    async def on_string_selected(self, ev) -> None:
        await self.query_one("StringMetadataView").remove()
        await self.mount(self.StringMetadataView(ev.string))

    @on(Input.Changed)
    def on_filter_changed(self, event: Input.Changed) -> None:
        event.stop()

        self.log("filter: " + self.filter)
        self.filter = str(event.value or "")

    def watch_filter(self, filter: str) -> None:
        if not filter:
            self.visible_strings = self.strings
        else:
            self.visible_strings = [string for string in self.strings if filter in string.string]
        self.log(f"filtered to {len(self.visible_strings)} strings")

    async def watch_visible_strings(self, visible_strings: List[OpenSourceString]) -> None:
        if visible_strings is None:
            # when the reactive is initialized, this fires with the default value, None.
            # we want to skip this one event.
            return

        await self.query_one("StringsView").remove()
        smv = self.query("StringMetadataView")
        if smv:
            await smv.remove()

        await self.mount(self.StringsView(visible_strings))
        if visible_strings:
            await self.mount(self.StringMetadataView(visible_strings[0]))

    class StringAdded(Message):
        def __init__(self, database: DatabaseDescriptor, string: OpenSourceString) -> None:
            self.database = database
            self.string = string
            super().__init__()

    @on(Button.Pressed, selector=".add-button")
    def on_add_string(self, ev):
        ev.stop()

        # TODO: fetch the string
        s = OpenSourceString("new string", "foo", "unknown")
        self.post_message(self.StringAdded(self.descriptor, s))


class UnsupportedDatabaseView(Widget):
    DEFAULT_CSS = """
        UnsupportedDatabaseView {
            height: 100%;
            width: 100%;
        }
    """

    def __init__(self, descriptor: DatabaseDescriptor, database: Any, *args, **kwargs):
        self.descriptor = descriptor
        self.database = database
        super().__init__(*args, **kwargs)
        self.add_class("dbedit--pane")

    def compose(self) -> ComposeResult:
        yield Static(f"unsupported database: {self.descriptor.type} {self.descriptor.path.name}")


class PendingOperationsView(Widget):
    DEFAULT_CSS = """
        PendingOperationsView .controls {
            height: 1;
        }
    """
    pending_operations: List[DatabaseOperation] = reactive([])

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.add_class("dbedit--pane")

    def compose(self) -> ComposeResult:
        yield Vertical(
            Static(Text("pending operations:\n", style=Style(color="blue"))),
            Static(Text("(none)", style=Style(color="grey50")), classes="oplist"),
            Horizontal(
                InlineButton("commit", classes="button-commit"), InlineButton("reset", classes="button-reset"), classes="controls"
            ),
        )

    async def render_oplist(self):
        await replace_one(
            self, ".oplist", ListView(*[ListItem(Static(str(op))) for op in self.pending_operations], classes="oplist")
        )

    async def watch_pending_operations(self, pending_operations):
        await self.render_oplist()

    class Commit(Message):
        pass

    class Reset(Message):
        pass

    @on(Button.Pressed, selector=".button-commit")
    async def on_commit(self) -> None:
        self.post_message(self.Commit())

    @on(Button.Pressed, selector=".button-reset")
    async def on_reset(self) -> None:
        self.post_message(self.Reset())


class MainScreen(Screen):
    pending_operations: List[DatabaseOperation] = reactive([])

    DEFAULT_CSS = """
        MainScreen {
        }
        
        MainScreen .navpane {
            width: 34;
        }

        MainScreen .navpane .dblist {
            height: 1fr;
        }

        MainScreen .navpane PendingOperationsView {
            height: 1fr;
        }
    """

    BINDINGS = [
        Binding("q", "quit", "Quit"),
        # vim-like bindings: line, page, home/end
        Binding("j", "scroll_down", "Down", show=False),
        Binding("k", "scroll_up", "Up", show=False),
        Binding("ctrl+f,space", "scroll_page_down", "Page Down", show=False),
        Binding("ctrl+b", "scroll_page_up", "Page Up", show=False),
        Binding("g", "scroll_home", "home", show=False),
        Binding("G", "scroll_end", "end", show=False),
    ]

    def __init__(self, database_descriptors: Sequence[DatabaseDescriptor], *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.database_descriptors = database_descriptors

        self.databases: Dict[str, Database] = {
            str(descriptor.path.absolute): self._load_database(descriptor) for descriptor in self.database_descriptors
        }

    def _load_database(self, descriptor: DatabaseDescriptor) -> Database:
        match descriptor.type:
            case "expert":
                return ExpertStringDatabase.from_file(descriptor.path)
            case "gp":
                if descriptor.path.suffix == ".bin":
                    return StringHashDatabase.from_file(descriptor.path)
                elif str(descriptor.path).endswith(".jsonl.gz"):
                    return StringGlobalPrevalenceDatabase.from_file(descriptor.path)
                else:
                    raise ValueError(f"unknown gp database type: {descriptor.path}")
            case "winapi":
                return WindowsApiStringDatabase.from_dir(descriptor.path)
            case "oss":
                return OpenSourceStringDatabase.from_file(descriptor.path)
            case _:
                raise ValueError(f"unknown database type: {descriptor.type}")

    def action_scroll_down(self):
        self.scroll_relative(
            y=2,
            animate=False,
        )

    def action_scroll_up(self):
        self.scroll_relative(
            y=-2,
            animate=False,
        )

    def action_scroll_page_up(self):
        self.scroll_page_up(
            animate=False,
        )

    def action_scroll_page_down(self):
        self.scroll_page_down(
            animate=False,
        )

    def action_scroll_home(self):
        self.scroll_home(
            animate=False,
        )

    def action_scroll_end(self):
        self.scroll_end(
            animate=False,
        )

    def action_quit(self):
        self.app.exit()

    class DatabaseListItem(ListItem):
        def __init__(self, database: DatabaseDescriptor, *args, **kwargs):
            self.database = database
            super().__init__(*args, **kwargs)

    def compose(self) -> ComposeResult:
        first_descriptor = self.database_descriptors[0]
        first_database = self.databases[str(first_descriptor.path.absolute)]

        yield Horizontal(
            Vertical(
                ListView(
                    *[
                        # TODO: show string count
                        # TODO: maybe strip file extension
                        self.DatabaseListItem(descriptor, Label(f"{descriptor.type}: {descriptor.path.name}"))
                        for descriptor in self.database_descriptors
                    ],
                    classes="dblist dbedit--pane",
                ),
                PendingOperationsView(),
                classes="navpane",
            ),
            # this will be replaced upon click of something supported.
            UnsupportedDatabaseView(first_descriptor, first_database, classes="databaseview"),
        )

        yield Footer()

    @on(ListView.Selected, selector=".dblist")
    async def on_database_selected(self, ev: ListView.Selected) -> None:
        item = ev.item
        assert isinstance(item, self.DatabaseListItem)
        descriptor = item.database
        database = self.databases[str(descriptor.path.absolute)]

        if descriptor.type == "oss":
            view = OSSDatabaseView(descriptor, database, classes="databaseview")
        else:
            view = UnsupportedDatabaseView(descriptor, database, classes="databaseview")

        await replace_one(self, ".databaseview", view)

    @on(OSSDatabaseView.StringAdded)
    def on_oss_string_added(self, ev):
        metadata: OpenSourceString = ev.string
        descriptor: DatabaseDescriptor = ev.database

        assert descriptor.type == "oss"

        op = DatabaseOperation(descriptor, "add", metadata)
        self.log("op: " + str(op))

        # TODO: dedup
        self.pending_operations = self.pending_operations + [op]

    def watch_pending_operations(self, pending_operations):
        self.query_one("PendingOperationsView", PendingOperationsView).pending_operations = pending_operations

    @on(PendingOperationsView.Commit)
    def on_commit(self):
        if not self.pending_operations:
            return

        for descriptor in self.database_descriptors:
            key = str(descriptor.path.absolute)
            database = self.databases[key]

            ops = [op for op in self.pending_operations if op.database == descriptor]

            if not ops:
                continue

            if descriptor.type == "oss":
                assert isinstance(database, OpenSourceStringDatabase)

                for op in ops:
                    if op.op == "add":
                        database.metadata_by_string[op.string.string] = op.string
                    elif op.op == "remove":
                        del database.metadata_by_string[op.string.string]
                    else:
                        raise ValueError(f"unknown operation: {op.op}")

                database.to_file(descriptor.path)
                self.databases[key] = self._load_database(descriptor)
            else:
                raise NotImplementedError(f"commit not implemented for database type: {descriptor.type}")

        log = pathlib.Path(floss.qs.db.__file__).parent / "data" / "db.log"
        if log.exists():
            entries = log.read_text(encoding="utf-8").split("\n")
        else:
            entries = []
        entries.extend([json.dumps(op, cls=DataclassJSONEncoder) for op in self.pending_operations])
        log.write_text("\n".join(entries), encoding="utf-8")

        # we would update this,
        # but we're about to tear down the entire screen.
        # self.pending_operations = []

        # hack: reload the UI
        # TODO: re-select the current database, for comfort
        self.app.pop_screen()
        self.app.push_screen(MainScreen(self.database_descriptors))

    @on(PendingOperationsView.Reset)
    def on_reset(self):
        self.pending_operations = []


class TitleScreen(Screen):
    DEFAULT_CSS = """
        TitleScreen {
            height: 100%;
            width: 100%;
            align: center middle;
        }
    """

    def compose(self) -> ComposeResult:
        yield Label(
            textwrap.dedent(
                """\
          QUANTUMSTRAND database editor
        """.rstrip()
            ),
            classes="logo",
        )


class DBEditApp(App):
    TITLE = "QUANTUMSTRAND"
    DEFAULT_CSS = """
        .dbedit--title {
            color: $secondary;
        }

        .dbedit--key {
            color: $accent;
        }

        .dbedit--address {
            color: $accent;
        }

        .dbedit--decoration {
            color: $text-muted;
        }

        .dbedit--muted {
            color: $text-muted;
        }

        .dbedit--pane {
            /* appear as a new layer on top of the screen */
            background: $boost;

            /* border takes an extra line, but is visually nicer for regions. */
            /* use `tall` or `wide` only with background: boost */
            /* use other styles when there's not a boost/new layer */
            border: tall $background;

            /* padding: inside the bounding box */
            /* padding-y: 0 */
            /* padding-x: 1 */
            padding: 0 1;

            /* margin: outside the bounding box */
            /* margin: 0 on all sides but top */
            margin: 0;
            margin-top: 1;
        }
    """

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.title = "qs"

        self.database_descriptors = []
        for type, module in (
            # TODO: disabled during dev
            # ("expert", floss.qs.db.expert),
            # ("gp", floss.qs.db.gp),
            ("oss", floss.qs.db.oss),
            # ("winapi", floss.qs.db.winapi),
        ):
            for path in module.DEFAULT_PATHS:
                self.database_descriptors.append(DatabaseDescriptor(type, path))

    @on(Mount)
    def on_mount(self):
        self.push_screen(MainScreen(self.database_descriptors))


async def main(argv=None):
    from textual.logging import TextualHandler

    if argv is None:
        argv = sys.argv[1:]

    parser = argparse.ArgumentParser(description="QUANTUMSTRAND database editor.")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable debug logging")
    parser.add_argument("-q", "--quiet", action="store_true", help="Disable all output but errors")
    parser.add_argument("--dev", action="store_true", help="Run app in textual dev mode")
    args = parser.parse_args(args=argv)

    if args.verbose:
        logging.basicConfig(level=logging.DEBUG, handlers=[TextualHandler()])
    elif args.quiet:
        logging.basicConfig(level=logging.CRITICAL, handlers=[TextualHandler()])
    else:
        logging.basicConfig(level=logging.INFO, handlers=[TextualHandler()])

    if args.dev:
        # so we can use the textual console.
        #
        # undocumented, so probably subject to change:
        # https://github.com/Textualize/textual/blob/d9a229ff0f6b77171fbf61cefc851c4d7498b200/src/textual/cli/cli.py#LL77C5-L77C55
        os.environ["TEXTUAL"] = ",".join(sorted(["debug", "devtools"]))

    app = DBEditApp()
    await app.run_async()

    # silly graceful shutdown to avoid ResourceWarning
    # see here: https://docs.aiohttp.org/en/stable/client_advanced.html#graceful-shutdown
    await asyncio.sleep(0.125)


if __name__ == "__main__":
    import os
    import sys
    import mmap
    import argparse

    sys.exit(asyncio.run(main()))
