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
from floss.qs.db.oss import OpenSourceStringDatabase
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
from textual.reactive import reactive
from textual.containers import VerticalScroll
from textual.scroll_view import ScrollView


def render_string(s: str):
    return json.dumps(s)[1:-1]


from textual.message import Message


class OSSDatabaseView(VerticalScroll):
    DEFAULT_CSS = """
        OSSDatabaseView {
        }
    """

    def __init__(self, descriptor: DatabaseDescriptor, database: OpenSourceStringDatabase, *args, **kwargs):
        self.descriptor = descriptor
        self.database = database
        super().__init__(*args, **kwargs)

        self.strings = list(sorted(self.database.metadata_by_string.values(), key=lambda x: x.string))

    class StringMetadataView(Static):
        def __init__(self, metadata, *args, **kwargs):
            self.metadata = metadata
            super().__init__(*args, **kwargs)
            self.add_class("dbedit--pane")

        def render(self):
            ret = Text(no_wrap=True, overflow="ellipsis")

            ret.append_text(Text("metadata:\n", style=Style(color="blue")))
            ret.append_text(Text("\n"))

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

            table.add_row("string", render_string(self.metadata.string))
            table.add_row("library name", self.metadata.library_name)
            table.add_row("library version", self.metadata.library_version)
            table.add_row("file path", self.metadata.file_path)
            table.add_row("function name", self.metadata.function_name)
            table.add_row("line number", str(self.metadata.line_number))

            return table

            # this is a hack to emit the table into a Text object.
            # the table is supposed to be rendered to a console, which requires a size,
            # so we emulate it here.
            console = rich.console.Console(width=self.size.width, force_terminal=True)
            with console.capture() as capture:
                console.print(table)

            ret.append(Text.from_ansi(capture.get()))

            # TODO: add action to delete

            return ret

    class StringsView(VerticalScroll):
        def __init__(self, strings, *args, **kwargs):
            self.strings = strings
            super().__init__(*args, **kwargs)
            self.add_class("dbedit--pane")

        def compose(self):
            # we use text here because 10k widgets is really slow with textual
            ret = Text(no_wrap=True, overflow="ellipsis")

            for metadata in self.strings:
                # TODO: highlight the currently selected row
                ret.append(render_string(metadata.string) + "\n")

            yield Static(Text("strings:\n", style=Style(color="blue")))

            yield Static(ret)

        class StringSelected(Message):
            def __init__(self, string: floss.qs.db.oss.OpenSourceString) -> None:
                self.string = string
                super().__init__()

        def on_click(self, event):
            # TODO: bug in that click on the strings: title is handled here.
            # we should ignore that, maybe by inspecting the parent widget.
            string = self.strings[event.y]
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

        yield self.StringsView(self.strings)

        m = self.StringMetadataView(self.strings[0])
        m.styles.height = 10
        yield m
        # TODO: add action to add string

    def on_strings_view_string_selected(self, ev) -> None:
        self.query_one("StringMetadataView").remove()
        self.mount(self.StringMetadataView(ev.string))


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
