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
from textual.app import App, ComposeResult, RenderResult
from textual.widgets import Header, Label, Static
from textual.strip import Strip
from textual.geometry import Size
from textual.scroll_view import ScrollView

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

    def __init__(self, ctx: Context, address: int, length: int, *args, **kwargs):
        super().__init__(self.render_text(ctx, address, length), *args, **kwargs)
        self.add_class("pe-pane")

    @staticmethod
    def render_text(ctx: Context, address: int, length: int) -> Text:
        return w(hexdump.hexdump(ctx.buf[address:address + length], result="return"))

    def get_content_width(self, container: Size, viewport: Size) -> int:
        return 76  # default width of hexdump.hexdump


class VirtualHexView(ScrollView):
    # TODO: virtual scrolling
    # TODO: offset/alignment
    # TODO: label/title
    # TODO: make this width the application global width?
    # TODO: make it easy to copy from

    def __init__(self, ctx: Context, address: int, length: int, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.add_class("pe-pane")
        self.styles.height = "auto"

        self.ctx = ctx
        self.address = address
        self.length = length

        self.has_aligned_start = self.address % 16 == 0
        self.has_aligned_end = (self.address + self.length) % 16 == 0

        DEFAULT_WIDTH = 76

        self.row_count = self.length // 16
        self.virtual_size = Size(width=DEFAULT_WIDTH, height=self.row_count + 4)

    def render(self) -> RenderResult:
        buf = self.ctx.buf[self.address:self.address + self.length]

        rows: List[str] = []

        ROW_LENGTH = 0x10

        if not self.has_aligned_start:
            # number of bytes of padding at the start of the line 
            # when the region start is unaligned.
            padding_length = self.address % ROW_LENGTH

            # the aligned row address, which is a multiple of 16
            row_address = self.address - padding_length

            # the bytes of the row.
            # the length of this is less than 16:
            # padding_length + len(row_buf) == 16
            row_buf = buf[0:self.address % ROW_LENGTH]

            row: List[str] = []

            row.append(f"[blue]{row_address:08x}[/blue]:",)
            row.append("  ")

            for _ in range(padding_length):
                row.append("  ")
                row.append(" ")

            for b in row_buf:
                if b == 0x0:
                    row.append("[grey50]00[/grey50]")
                else:
                    row.append(f"[white]{b:02X}[/white]")

                row.append(" ")

            for _ in range(ROW_LENGTH - len(row_buf) - padding_length):
                row.append("  ")
                row.append(" ")

            # remove the trailing space thats usually used
            # to separate each hex byte value.
            row.pop()

            # separate the hex data from the ascii data
            row.append("  ")

            for _ in range(padding_length):
                row.append(" ")

            for b in row_buf:
                if 0x20 <= b <= 0x7E:
                    row.append(f"[white]{chr(b)}[/white]")
                else:
                    row.append("[grey50].[/grey50]")

            # when the end of the region is unaligned,
            # pad the row with spaces.
            for _ in range(ROW_LENGTH - len(row_buf) - padding_length):
                row.append(" ")

            # remove the trailing space thats usually used
            # to separate each ascii byte value.
            row.pop()

            rows.append("".join(row))

        for row_offset in range(0, self.length, ROW_LENGTH):
            row_address = self.address + row_offset
            row_buf = buf[row_offset:row_offset + ROW_LENGTH]

            row: List[str] = []

            row.append(f"[blue]{row_address:08x}[/blue]:",)
            row.append("  ")

            for b in row_buf:
                if b == 0x0:
                    row.append("[grey50]00[/grey50]")
                else:
                    row.append(f"[white]{b:02X}[/white]")

                row.append(" ")

            # when the end of the region is unaligned,
            # pad the row with spaces.
            for _ in range(ROW_LENGTH - len(row_buf)):
                row.append("  ")
                row.append(" ")

            # remove the trailing space thats usually used
            # to separate each hex byte value.
            row.pop()

            # separate the hex data from the ascii data
            row.append("  ")

            for b in row_buf:
                if 0x20 <= b <= 0x7E:
                    row.append(f"[white]{chr(b)}[/white]")
                else:
                    row.append("[grey50].[/grey50]")

            # when the end of the region is unaligned,
            # pad the row with spaces.
            for _ in range(ROW_LENGTH - len(row_buf)):
                row.append("  ")
                row.append(" ")

            # remove the trailing space thats usually used
            # to separate each ascii byte value.
            row.pop()

            rows.append("".join(row))

        return "\n".join(rows)

    def _render_line(self, y: int) -> Strip:
        """Render a line of the widget. y is relative to the top of the widget."""

        scroll_x, scroll_y = self.scroll_offset  # The current scroll position
        y += scroll_y  # The line at the top of the widget is now `scroll_y`, not zero!
        row_index = y // 4  # four lines per row

        white = self.get_component_rich_style("checkerboard--white-square")
        black = self.get_component_rich_style("checkerboard--black-square")

        if row_index >= self.board_size:
            return Strip.blank(self.size.width)

        is_odd = row_index % 2

        segments = [
            Segment(" " * 8, black if (column + is_odd) % 2 else white)
            for column in range(self.board_size)
        ]
        strip = Strip(segments, self.board_size * 8)
        # Crop the strip so that is covers the visible area
        strip = strip.crop(scroll_x, scroll_x + self.size.width)
        return strip



# TODO: StructureView


class PEApp(App):

    # TODO: how does the app layout when there are hundreds of hex views, each with thousands of lines?

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
        yield HexView(self.ctx, 0, 0x30)
        yield VirtualHexView(self.ctx, 0x4, 0x8)
        yield VirtualHexView(self.ctx, 0x4, 0x10)
        yield VirtualHexView(self.ctx, 0x8, 0x28)

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
