import json
import asyncio
import logging
import pathlib
import textwrap
from typing import Any, Set, Dict, List, Tuple, Literal, Mapping, Callable, Iterable, Optional, Sequence
from dataclasses import dataclass

import rich.console
from textual.app import App, ComposeResult
from textual.screen import Screen
from textual.widget import Widget
from textual.binding import Binding
from textual.widgets import Input, Label, Footer, Static, TabPane, ListItem, ListView, TabbedContent
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


@dataclass
class DatabaseDescriptor:
    type: str
    path: pathlib.Path


Database = (
    ExpertStringDatabase
    | StringGlobalPrevalenceDatabase
    | StringHashDatabase
    | WindowsApiStringDatabase
    | OpenSourceStringDatabase
)


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
        strip = strip.crop(scroll_x, scroll_x + self.size.width)
        return strip

    class ItemSelected(Message):
        def __init__(self, item) -> None:
            self.item = item
            super().__init__()

    def on_click(self, event):
        scroll_x, scroll_y = self.scroll_offset
        row_index = event.y + scroll_y

        if row_index >= len(self.items):
            return Strip.blank(self.size.width)

        item = self.items[row_index]
        event.stop()

        self.selected_index = row_index
        self.post_message(self.ItemSelected(item))


class OSSDatabaseView(VerticalScroll):
    filter = reactive(0)
    visible_strings = reactive([])

    DEFAULT_CSS = """
        OSSDatabaseView {
        }
    """

    def __init__(self, descriptor: DatabaseDescriptor, database: OpenSourceStringDatabase, *args, **kwargs):
        self.descriptor = descriptor
        self.database = database
        super().__init__(*args, **kwargs)

        self.strings = list(sorted(self.database.metadata_by_string.values(), key=lambda x: x.string))
        self.visible_strings = self.strings

    class StringMetadataView(Static):
        DEFAULT_CSS = """
            StringMetadataView {
                height: 10;
            }
        """

        def __init__(self, string: OpenSourceString, *args, **kwargs):
            self.string = string
            super().__init__(*args, **kwargs)
            self.add_class("dbedit--pane")

        def render(self):
            table = Table(
                title="metadata:",
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
            yield Static(Text("strings:\n", style=Style(color="blue")))
            yield VirtualList([self.StringView(metadata) for metadata in self.strings])

        class StringSelected(Message):
            def __init__(self, string: OpenSourceString) -> None:
                self.string = string
                super().__init__()

        def on_virtual_list_item_selected(self, event: VirtualList.ItemSelected):
            item: self.StringView = event.item
            string: OpenSourceString = item.string
            event.stop()

            self.post_message(self.StringSelected(string))

    def compose(self):
        v = Vertical(
            Static(Text(f"database: {self.descriptor.type} {self.descriptor.path.name}", style=Style(color="blue"))),
            Static(""),
            Input(placeholder="filter..."),
            classes="dbedit--pane",
        )
        v.styles.height = 7
        yield v

        yield self.StringsView(self.visible_strings)

        yield self.StringMetadataView(self.visible_strings[0])
        # TODO: add action to add string

    def on_strings_view_string_selected(self, ev) -> None:
        self.query_one("StringMetadataView").remove()
        self.mount(self.StringMetadataView(ev.string))

    def on_input_changed(self, event: Input.Changed) -> None:
        self.filter = str(event.value or "")
        event.stop()
        self.log("filter: " + self.filter)

    def watch_filter(self, filter: str) -> None:
        if not filter:
            self.visible_strings = self.strings
        else:
            self.visible_strings = [string for string in self.strings if filter in string.string]
        self.log(f"filtered to {len(self.visible_strings)} strings")

    async def watch_visible_strings(self, visible_strings: List[OpenSourceString]) -> None:
        await self.query_one("StringsView").remove()
        smv = self.query("StringMetadataView")
        if smv:
            await smv.remove()

        await self.mount(self.StringsView(visible_strings))
        if visible_strings:
            await self.mount(self.StringMetadataView(visible_strings[0]))


class UnsupportedDatabaseView(Widget):
    DEFAULT_CSS = """
        UnsupportedDatabaseView {
            height: 100%;
            width: 100%;
        }
    """

    def __init__(self, descriptor: DatabaseDescriptor, database: OpenSourceStringDatabase, *args, **kwargs):
        self.descriptor = descriptor
        self.database = database
        super().__init__(*args, **kwargs)
        self.add_class("dbedit--pane")

    def compose(self) -> ComposeResult:
        yield Static(f"unsupported database: {self.descriptor.type} {self.descriptor.path.name}")


class MainScreen(Screen):
    DEFAULT_CSS = """
        MainScreen {
        }
        
        MainScreen Horizontal ListView.dblist {
            width: 30;
            padding-top: 1;
            border-right: solid grey;
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
            ListView(
                *[
                    self.DatabaseListItem(descriptor, Label(f"{descriptor.type}: {descriptor.path.name}"))
                    for descriptor in self.database_descriptors
                ],
                classes="dblist",
            ),
            UnsupportedDatabaseView(first_descriptor, first_database, classes="databaseview"),
        )

        yield Footer()

    def on_list_view_selected(self, ev: ListView.Selected) -> None:
        descriptor = ev.item.database
        database = self.databases[str(descriptor.path.absolute)]

        if descriptor.type == "oss":
            view = OSSDatabaseView(descriptor, database, classes="databaseview")
        else:
            view = UnsupportedDatabaseView(descriptor, database, classes="databaseview")

        self.query_one(".databaseview").remove()
        self.query_one("Horizontal").mount(view)


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
            ("expert", floss.qs.db.expert),
            ("gp", floss.qs.db.gp),
            ("oss", floss.qs.db.oss),
            ("winapi", floss.qs.db.winapi),
        ):
            for path in module.DEFAULT_PATHS:
                self.database_descriptors.append(DatabaseDescriptor(type, path))

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
