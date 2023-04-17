"""
    "textual==0.19.1",
    "rich==13.3.3",
"""
import os
import sys
import mmap
import pathlib
import asyncio
import logging
import argparse
from typing import Any, List, Tuple, Union, Optional
from dataclasses import dataclass

import pefile
import hexdump
import textwrap
from textual import events
from rich.text import Text
from textual.logging import TextualHandler
from textual.app import App, ComposeResult
from textual.widgets import Header, Label, Static

logger = logging.getLogger("pe")

from textual.logging import TextualHandler


@dataclass
class Context:
    path: pathlib.Path
    buf: bytearray
    pe: pefile.PE


def w(s) -> str:
    """ wrapper for multi-line text """
    return Text.from_markup(textwrap.dedent(s.lstrip("\n")).strip())


class MetadataView(Static):
    def __init__(self, ctx: Context, *args, **kwargs):
        super().__init__(self.render_text(ctx), *args, **kwargs)
        self.add_class("pe-pane")

    @staticmethod
    def render_text(ctx: Context) -> Text:
        return w(f"""
            [yellow]metadata:[/yellow]
             [blue]name:[/blue] {ctx.path.name}
             [blue]size:[/blue] 0x{len(ctx.buf):x}
        """)


class HexView(Static):
    # TODO: coloring
    # TODO: virtual scrolling
    # TODO: offset/alignment
    # TODO: label/title
    # TODO: make this width the application global width?

    def __init__(self, ctx: Context, address: int, size: int, *args, **kwargs):
        super().__init__(self.render_text(ctx, address, size), *args, **kwargs)
        self.add_class("pe-pane")

    @staticmethod
    def render_text(ctx: Context, address: int, size: int) -> Text:
        return w(hexdump.hexdump(ctx.buf[address:address + size], result="return"))


# TODO: StructureView


class PEApp(App):
    TITLE = "pe"
    DEFAULT_CSS = """
        .pe-pane {
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
            /* margin: 1 on all sides but bottom, to collapse with next pane */
            margin: 1;
            margin-bottom: 0;
        }
    """

    def __init__(self, path: pathlib.Path=None, buf: bytearray=None) -> None:
        super().__init__()

        # premature optimization consideration:
        # do the parsing within the app, in case the file is really large and this is laggy.
        # we can introduce background parsing later.
        pe = pefile.PE(data=buf, fast_load=False)

        self.ctx = Context(path, buf, pe)

        self.title = f"pe: {self.ctx.path.name}"

    def compose(self) -> ComposeResult:
        yield Header()
        yield MetadataView(self.ctx)
        yield HexView(self.ctx, 0, 0x100)

    def on_mount(self) -> None:
        self.log("mounted")

    async def on_key(self, event: events.Key) -> None:
        if event.key == "q":
            self.exit()


async def main(argv=None):
    if argv is None:
        argv = sys.argv[1:]

    parser = argparse.ArgumentParser(description="Portable Executable viewer.")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable debug logging")
    parser.add_argument("-q", "--quiet", action="store_true", help="Disable all output but errors")
    parser.add_argument("--dev", action="store_true", help="Run app in textual dev mode")
    parser.add_argument("path", type=str, help="path to PE file to inspect")
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

    path = pathlib.Path(args.path)
    if not path.exists():
        logging.error("%s does not exist", path)
        return 1

    with path.open("rb") as f:
        WHOLE_FILE = 0
        with mmap.mmap(f.fileno(), length=WHOLE_FILE, access=mmap.ACCESS_READ) as mm:

            # treat the mmap as a readable bytearray
            buf: bytearray = mm  # type: ignore

            app = PEApp(path, buf)
            await app.run_async()

    # silly graceful shutdown to avoid ResourceWarning
    # see here: https://docs.aiohttp.org/en/stable/client_advanced.html#graceful-shutdown
    await asyncio.sleep(0.125)


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
