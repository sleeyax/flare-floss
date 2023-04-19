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
from textual.widget import Widget
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
    # TODO: label/title
    # TODO: make this width the application global width?
    # TODO: make it easy to copy from

    # refer directly to line api documentation here: 
    # https://textual.textualize.io/guide/widgets/#line-api
    COMPONENT_CLASSES = {
        "virtualhexview--address",
        "virtualhexview--padding",
        "virtualhexview--hex-nonzero",
        "virtualhexview--hex-zero",
        "virtualhexview--ascii-printable",
        "virtualhexview--ascii-nonprintable",
    }

    DEFAULT_CSS = """
        VirtualHexView {
            /* take up full height of hex view, unless specified otherwise */
            height: auto;
        }

        VirtualHexView .virtualhexview--address {
            color: $accent;
        }

        VirtualHexView .virtualhexview--padding {
            /* nothing special, empty space */
        }

        VirtualHexView .virtualhexview--hex-nonzero {
            color: $text;
        }

        VirtualHexView .virtualhexview--hex-zero {
            color: $text-muted;
        }

        VirtualHexView .virtualhexview--ascii-printable {
            color: $text;
        }

        VirtualHexView .virtualhexview--ascii-nonprintable {
            color: $text-muted;
        }
    """

    def __init__(self, ctx: Context, address: int, length: int, row_length: int=0x10, *args, **kwargs):
        if length <= 0:
            raise ValueError("length must be > 0")

        if address < 0:
            raise ValueError("address must be >= 0")

        if address > len(ctx.buf):
            raise ValueError("address must be <= len(ctx.buf)")

        if address + length > len(ctx.buf):
            raise ValueError("address + length must be <= len(ctx.buf)")

        if row_length <= 0:
            raise ValueError("row_length must be > 0")

        super().__init__(*args, **kwargs)
        self.add_class("pe-pane")

        self.ctx = ctx
        self.address = address
        self.length = length
        self.row_length = row_length

        self.has_aligned_start = self.address % self.row_length == 0
        self.has_aligned_end = (self.address + self.length) % self.row_length == 0

        DEFAULT_WIDTH = 76

        self.row_count = (self.length // self.row_length) + 1
        if self.has_aligned_start and self.length % self.row_length == 0:
            self.row_count -= 1

        self.virtual_size = Size(width=DEFAULT_WIDTH, height=self.row_count)

    def render(self) -> RenderResult:
        rows: List[str] = []

        for i in range(self.row_count):
            rows.append(self._render_line(i))

        return "\n".join(rows)

    def _render_line(self, i) -> str:
        # row_offset is the aligned row offset into buf, which is a multiple of 16.
        row_offset = i * self.row_length 

        if i == 0:
            # number of bytes of padding at the start of the line 
            # when the region start is unaligned.
            padding_start_length = self.address % self.row_length 

            # number of bytes of data to display on this line.
            row_data_length = min(self.row_length - padding_start_length, self.length)

        else:
            padding_start_length = 0

            row_data_length = min(self.row_length, self.address + self.length - row_offset)

        # the offset in to the buf to find the bytes shown on this line.
        row_data_offset = row_offset + padding_start_length

        # number of bytes of padding at the end of the line
        # when the region start is unaligned.
        padding_end_length = self.row_length - row_data_length - padding_start_length

        # the bytes of data to show on this line.
        row_buf = self.ctx.buf[row_data_offset:row_data_offset + row_data_length]

        row: List[str] = []

        # render address column.
        # like:
        #
        #     0x00000000:
        #     0x00000010:
        #
        # TODO: make this 8 bytes for x64
        row.append(f"[blue]{row_offset:08x}[/blue]:",)
        row.append("  ")

        # render hex column.
        # there may be padding at the start and/or end of line.
        # like:
        #
        #                    FF 00 00 B8 00 00 00 00 00 00 00
        #     04 00 00 00 FF FF 00 00 B8 00 00 00 00 00 00 00
        #     04 00 00 00 FF FF 00 00 B8 00 00 00 
        for _ in range(padding_start_length):
            # width of a hex value is 2 characters.
            row.append("  ")
            # space-separate hex values.
            row.append(" ")

        # render hex value,
        # bright when non-zero, muted when zero.
        for b in row_buf:
            if b == 0x0:
                row.append("[grey50]00[/grey50]")
            else:
                row.append(f"[white]{b:02X}[/white]")

            row.append(" ")

        for _ in range(padding_end_length):
            row.append("  ")
            row.append(" ")

        # remove the trailing space thats usually used
        # to separate each hex byte value.
        row.pop()

        # separate the hex data from the ascii data
        row.append("  ")

        # render ascii column.
        # there may be padding at the start and/or end of line.
        # like:
        #
        #          .....ABCD...
        #      MZ.......ABCD...
        #      MZ.......ABC    
        for _ in range(padding_start_length):
            # the width of an ascii value is one character,
            # and these are not separated by spaces.
            row.append(" ")

        # render ascii value,
        # bright when printable, muted when non-printable.
        for b in row_buf:
            if 0x20 <= b <= 0x7E:
                row.append(f"[white]{chr(b)}[/white]")
            else:
                row.append("[grey50].[/grey50]")

        for _ in range(padding_end_length):
            row.append(" ")

        return "".join(row)

    def _render_line_(self, y: int) -> Strip:
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


class VirtualHexTestView(Widget):
    DEFAULT_CSS = """
        VirtualHexTestView > Label {
            padding-top: 1;
        }

        VirtualHexTestView > VirtualHexView.tall {
            height: 6;  /* margin-top: 1 + four lines of content + margin-bottom: 1 */
        }
    """

    def __init__(self, ctx: Context, *args, **kwargs):
        super().__init__()
        self.add_class("pe-pane")
        self.styles.height = "auto"

        self.ctx = ctx

    def compose(self) -> ComposeResult:
        yield Label("0, 100: tall, overflowing")
        yield VirtualHexView(self.ctx, 0x0, 0x100, classes="tall")

        yield Label("0, 4: single line, end padding")
        yield VirtualHexView(self.ctx, 0x0, 0x4)

        yield Label("0, 10: single line, aligned")
        yield VirtualHexView(self.ctx, 0x0, 0x10)

        yield Label("0, 18: two lines, end padding")
        yield VirtualHexView(self.ctx, 0x0, 0x18)

        yield Label("0, 20: two lines, aligned")
        yield VirtualHexView(self.ctx, 0x0, 0x20)

        yield Label("0, 28: three lines, end padding")
        yield VirtualHexView(self.ctx, 0x0, 0x28)

        yield Label("0, 30: three lines, aligned")
        yield VirtualHexView(self.ctx, 0x0, 0x30)

        yield Label("3, 4: one line, start padding, end padding")
        yield VirtualHexView(self.ctx, 0x3, 0x4)

        yield Label("3, D: one line, start padding")
        yield VirtualHexView(self.ctx, 0x3, 0xD)

        yield Label("3, 10: two lines, start padding, end padding")
        yield VirtualHexView(self.ctx, 0x3, 0x10)

        yield Label("3, 1D: two lines, start padding")
        yield VirtualHexView(self.ctx, 0x3, 0x1D)

        yield Label("3, 20: three lines, start padding, end padding")
        yield VirtualHexView(self.ctx, 0x3, 0x20)

        yield Label("3, 2D: three lines, start padding")
        yield VirtualHexView(self.ctx, 0x3, 0x2D)

        yield Label("0, 4, 7: single line, end padding")
        yield VirtualHexView(self.ctx, 0x0, 0x4, row_length=7)

        yield Label("0, 7, 7: single line, aligned")
        yield VirtualHexView(self.ctx, 0x0, 0x10, row_length=7)

        yield Label("0, 13, 7: two lines, end padding")
        yield VirtualHexView(self.ctx, 0x0, 0x18, row_length=7)

        yield Label("0, 100: tall")
        yield VirtualHexView(self.ctx, 0x0, 0x100)

        yield Label("0, 100: tall, overflowing")
        yield VirtualHexView(self.ctx, 0x0, 0x100, classes="tall")




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

        yield VirtualHexTestView(self.ctx)


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
