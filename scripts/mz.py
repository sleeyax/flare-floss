"""
    "textual==0.20.1",
    "rich==13.3.3",
    "dissect.cstruct==3.6",
"""
import os
import sys
import mmap
import asyncio
import logging
import pathlib
import argparse
import textwrap
from typing import Any, Dict, List, Callable, Tuple, Optional
from dataclasses import dataclass

import pefile
from dissect import cstruct
from textual import events
from rich.text import Text
import rich.table
from textual.app import App, ComposeResult
from rich.segment import Segment
from textual.strip import Strip
from textual.widget import Widget
from textual.logging import TextualHandler
from textual.widgets import Label, Header, Static
from textual.geometry import Size
from textual.containers import Horizontal, Container
from textual.scroll_view import ScrollView
from dissect.cstruct.types.enum import EnumInstance

logger = logging.getLogger("mz")


@dataclass
class Context:
    path: pathlib.Path
    buf: bytearray
    pe: pefile.PE
    cparser: cstruct.cstruct
    renderers: Dict[str, Callable[[Any], str]]

    @property
    def bitness(self):
        if self.pe.FILE_HEADER.Machine == pefile.MACHINE_TYPE["IMAGE_FILE_MACHINE_I386"]:
            return 32
        elif self.pe.FILE_HEADER.Machine == pefile.MACHINE_TYPE["IMAGE_FILE_MACHINE_AMD64"]:
            return 64
        else:
            raise ValueError("unknown bitness")


def w(s: str) -> Text:
    """wrapper for multi-line text"""
    return Text.from_markup(textwrap.dedent(s.lstrip("\n")).strip())


class Line(Horizontal):
    """A line of text. Children should be Static widgets."""

    DEFAULT_CSS = """
        Line {
            /* ensure each line doesn't overflow to subsequent row */
            height: 1;
        }

        Line > Static {
            /* by default, the widget will expand to fill the available space */
            width: auto;
        }
    """


class MetadataView(Static):
    DEFAULT_CSS = """
        MetadataView .metadataview--title {
            color: $secondary;
        }

        MetadataView .metadataview--key {
            color: $accent;
        }

        MetadataView .metadataview--value {
            color: $text;
        }
    """

    def __init__(self, ctx: Context, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.add_class("pe-pane")

        self.ctx = ctx

    def compose(self) -> ComposeResult:
        yield Label("metadata:", classes="metadataview--title")
        yield Line(
            Static(f"  name: ", classes="metadataview--key"),
            Static(self.ctx.path.name, classes="metadataview--value"),
        )
        yield Line(
            Static(f"  size: ", classes="metadataview--key"),
            Static(hex(len(self.ctx.buf)), classes="metadataview--value")
        )

        warnings = self.ctx.pe.get_warnings()
        if warnings:
            yield Label("  warnings:", classes="metadataview--key")
            for warning in warnings:
                yield Label(f"    - {warning}")


class HexView(ScrollView):
    # TODO: label/title
    # TODO: make this width the application global width?
    # TODO: make it easy to copy from
    # TODO: strings

    # refer directly to line api documentation here:
    # https://textual.textualize.io/guide/widgets/#line-api
    COMPONENT_CLASSES = {
        "hexview--address",
        "hexview--padding",
        "hexview--hex-nonzero",
        "hexview--hex-zero",
        "hexview--ascii-printable",
        "hexview--ascii-nonprintable",
    }

    DEFAULT_CSS = """
        HexView {
            /* take up full height of hex view, unless specified otherwise */
            height: auto;
        }

        HexView .hexview--address {
            color: $accent;
        }

        HexView .hexview--padding {
            /* nothing special, empty space */
        }

        HexView .hexview--hex-nonzero {
            color: $text;
        }

        HexView .hexview--hex-zero {
            color: $text-muted;
        }

        HexView .hexview--ascii-printable {
            color: $text;
        }

        HexView .hexview--ascii-nonprintable {
            color: $text-muted;
        }
    """

    def __init__(self, ctx: Context, address: int, length: int, row_length: int = 0x10, *args, **kwargs):
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

    def render_line(self, y: int) -> Strip:
        scroll_x, scroll_y = self.scroll_offset
        row_index = y + scroll_y

        if row_index >= self.row_count:
            return Strip.blank(self.size.width)

        # row_offset is the aligned row offset into buf, which is a multiple of 16.
        row_offset = row_index * self.row_length

        if row_index == 0:
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
        row_buf = self.ctx.buf[self.address + row_data_offset : self.address + row_data_offset + row_data_length]

        segments: List[Segment] = []

        style_address = self.get_component_rich_style("hexview--address")
        style_padding = self.get_component_rich_style("hexview--padding")
        style_hex_nonzero = self.get_component_rich_style("hexview--hex-nonzero")
        style_hex_zero = self.get_component_rich_style("hexview--hex-zero")
        style_ascii_printable = self.get_component_rich_style("hexview--ascii-printable")
        style_ascii_nonprintable = self.get_component_rich_style("hexview--ascii-nonprintable")

        # render address column.
        # like:
        #
        #     0x00000000:
        #     0x00000010:
        #
        # TODO: make this 8 bytes for x64
        segments.append(Segment(f"{self.address + row_offset:08x}:", style_address))
        segments.append(Segment("  ", style_padding))

        # render hex column.
        # there may be padding at the start and/or end of line.
        # like:
        #
        #                    FF 00 00 B8 00 00 00 00 00 00 00
        #     04 00 00 00 FF FF 00 00 B8 00 00 00 00 00 00 00
        #     04 00 00 00 FF FF 00 00 B8 00 00 00
        for _ in range(padding_start_length):
            # width of a hex value is 2 characters.
            segments.append(Segment("  ", style_padding))
            # space-separate hex values.
            segments.append(Segment(" ", style_padding))

        # render hex value,
        # bright when non-zero, muted when zero.
        for b in row_buf:
            if b == 0x0:
                segments.append(Segment("00", style_hex_zero))
            else:
                segments.append(Segment(f"{b:02X}", style_hex_nonzero))
            segments.append(Segment(" ", style_padding))

        for _ in range(padding_end_length):
            segments.append(Segment("  ", style_padding))
            segments.append(Segment(" ", style_padding))

        # remove the trailing space thats usually used
        # to separate each hex byte value.
        segments.pop()

        # separate the hex data from the ascii data
        segments.append(Segment("  ", style_padding))

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
            segments.append(Segment(" ", style_padding))

        # render ascii value,
        # bright when printable, muted when non-printable.
        for b in row_buf:
            if 0x20 <= b <= 0x7E:
                segments.append(Segment(chr(b), style_ascii_printable))
            else:
                segments.append(Segment(".", style_ascii_nonprintable))

        for _ in range(padding_end_length):
            segments.append(Segment(" ", style_padding))

        strip = Strip(segments)
        strip = strip.crop(scroll_x, scroll_x + self.size.width)
        return strip


class HexTestView(Widget):
    DEFAULT_CSS = """
        HexTestView > Label {
            padding-top: 1;
        }

        HexTestView > HexView.tall {
            height: 6;  /* margin-top: 1 + four lines of content + margin-bottom: 1 */
        }
    """

    def __init__(self, ctx: Context, *args, **kwargs):
        super().__init__()
        self.add_class("pe-pane")
        self.styles.height = "auto"

        self.ctx = ctx

    def compose(self) -> ComposeResult:
        yield Label("0, 4: single line, end padding")
        yield HexView(self.ctx, 0x0, 0x4)

        yield Label("0, 10: single line, aligned")
        yield HexView(self.ctx, 0x0, 0x10)

        yield Label("0, 18: two lines, end padding")
        yield HexView(self.ctx, 0x0, 0x18)

        yield Label("0, 20: two lines, aligned")
        yield HexView(self.ctx, 0x0, 0x20)

        yield Label("0, 28: three lines, end padding")
        yield HexView(self.ctx, 0x0, 0x28)

        yield Label("0, 30: three lines, aligned")
        yield HexView(self.ctx, 0x0, 0x30)

        yield Label("3, 4: one line, start padding, end padding")
        yield HexView(self.ctx, 0x3, 0x4)

        yield Label("3, D: one line, start padding")
        yield HexView(self.ctx, 0x3, 0xD)

        yield Label("3, 10: two lines, start padding, end padding")
        yield HexView(self.ctx, 0x3, 0x10)

        yield Label("3, 1D: two lines, start padding")
        yield HexView(self.ctx, 0x3, 0x1D)

        yield Label("3, 20: three lines, start padding, end padding")
        yield HexView(self.ctx, 0x3, 0x20)

        yield Label("3, 2D: three lines, start padding")
        yield HexView(self.ctx, 0x3, 0x2D)

        yield Label("0, 4, 7: single line, end padding")
        yield HexView(self.ctx, 0x0, 0x4, row_length=7)

        yield Label("0, 7, 7: single line, aligned")
        yield HexView(self.ctx, 0x0, 0x10, row_length=7)

        yield Label("0, 13, 7: two lines, end padding")
        yield HexView(self.ctx, 0x0, 0x18, row_length=7)

        yield Label("0, 100: tall, overflowing")
        yield HexView(self.ctx, 0x0, len(self.ctx.buf), classes="tall")


STRUCTURES = """
    struct IMAGE_DOS_HEADER {               // DOS .EXE header
        WORD   e_magic;                     // Magic number
        WORD   e_cblp;                      // Bytes on last page of file
        WORD   e_cp;                        // Pages in file
        WORD   e_crlc;                      // Relocations
        WORD   e_cparhdr;                   // Size of header in paragraphs
        WORD   e_minalloc;                  // Minimum extra paragraphs needed
        WORD   e_maxalloc;                  // Maximum extra paragraphs needed
        WORD   e_ss;                        // Initial (relative) SS value
        WORD   e_sp;                        // Initial SP value
        WORD   e_csum;                      // Checksum
        WORD   e_ip;                        // Initial IP value
        WORD   e_cs;                        // Initial (relative) CS value
        WORD   e_lfarlc;                    // File address of relocation table
        WORD   e_ovno;                      // Overlay number
        WORD   e_res[4];                    // Reserved words
        WORD   e_oemid;                     // OEM identifier (for e_oeminfo)
        WORD   e_oeminfo;                   // OEM information; e_oemid specific
        WORD   e_res2[10];                  // Reserved words
        LONG   e_lfanew;                    // File address of new exe header
    };

    enum IMAGE_FILE_MACHINE : uint16 {
        IMAGE_FILE_MACHINE_UNKNOWN = 0x0,
        IMAGE_FILE_MACHINE_I386 = 0x14c,
        IMAGE_FILE_MACHINE_IA64 = 0x200,
        IMAGE_FILE_MACHINE_AMD64 = 0x8664,
    };

    struct IMAGE_FILE_HEADER {
        IMAGE_FILE_MACHINE Machine;
        WORD  NumberOfSections;
        DWORD TimeDateStamp;
        DWORD PointerToSymbolTable;
        DWORD NumberOfSymbols;
        WORD  SizeOfOptionalHeader;
        WORD  Characteristics;
    };

    enum HDR_MAGIC : uint16 {
        IMAGE_NT_OPTIONAL_HDR32_MAGIC = 0x10B,
        IMAGE_NT_OPTIONAL_HDR64_MAGIC = 0x20B,
        IMAGE_ROM_OPTIONAL_HDR_MAGIC = 0x107,
    };

    enum HDR_SUBSYSTEM : uint16 {
        IMAGE_SUBSYSTEM_UNKNOWN = 0,
        IMAGE_SUBSYSTEM_NATIVE = 1,
        IMAGE_SUBSYSTEM_WINDOWS_GUI = 2,
        IMAGE_SUBSYSTEM_WINDOWS_CUI = 3,
        IMAGE_SUBSYSTEM_OS2_CUI = 5,
        IMAGE_SUBSYSTEM_POSIX_CUI = 7,
        IMAGE_SUBSYSTEM_WINDOWS_CE_GUI = 9,
        IMAGE_SUBSYSTEM_EFI_APPLICATION = 10,
        IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER = 11,
        IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER = 12,
        IMAGE_SUBSYSTEM_EFI_ROM = 13,
        IMAGE_SUBSYSTEM_XBOX = 14,
        IMAGE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION = 16,
    };

    struct IMAGE_DATA_DIRECTORY {
        DWORD VirtualAddress;
        DWORD Size;
    };

    #define IMAGE_NUMBEROF_DIRECTORY_ENTRIES 16

    enum IMAGE_DIRECTORY_ENTRY : uint8 {
        IMAGE_DIRECTORY_ENTRY_EXPORT = 0,
        IMAGE_DIRECTORY_ENTRY_IMPORT = 1,
        IMAGE_DIRECTORY_ENTRY_RESOURCE = 2,
        IMAGE_DIRECTORY_ENTRY_EXCEPTION = 3,
        IMAGE_DIRECTORY_ENTRY_SECURITY = 4,
        IMAGE_DIRECTORY_ENTRY_BASERELOC = 5,
        IMAGE_DIRECTORY_ENTRY_DEBUG = 6,
        IMAGE_DIRECTORY_ENTRY_ARCHITECTURE = 7,
        IMAGE_DIRECTORY_ENTRY_GLOBALPTR = 8,
        IMAGE_DIRECTORY_ENTRY_TLS = 9,
        IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG = 10,
        IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT = 11,
        IMAGE_DIRECTORY_ENTRY_IAT = 12,
        IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT = 13,
        IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR = 14,
    };

    struct IMAGE_OPTIONAL_HEADER32 {
        HDR_MAGIC            Magic;
        BYTE                 MajorLinkerVersion;
        BYTE                 MinorLinkerVersion;
        DWORD                SizeOfCode;
        DWORD                SizeOfInitializedData;
        DWORD                SizeOfUninitializedData;
        DWORD                AddressOfEntryPoint;
        DWORD                BaseOfCode;
        DWORD                BaseOfData;
        DWORD                ImageBase;
        DWORD                SectionAlignment;
        DWORD                FileAlignment;
        WORD                 MajorOperatingSystemVersion;
        WORD                 MinorOperatingSystemVersion;
        WORD                 MajorImageVersion;
        WORD                 MinorImageVersion;
        WORD                 MajorSubsystemVersion;
        WORD                 MinorSubsystemVersion;
        DWORD                Win32VersionValue;
        DWORD                SizeOfImage;
        DWORD                SizeOfHeaders;
        DWORD                CheckSum;
        HDR_SUBSYSTEM        Subsystem;
        WORD                 DllCharacteristics;
        DWORD                SizeOfStackReserve;
        DWORD                SizeOfStackCommit;
        DWORD                SizeOfHeapReserve;
        DWORD                SizeOfHeapCommit;
        DWORD                LoaderFlags;
        DWORD                NumberOfRvaAndSizes;
        IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
    };

    struct IMAGE_OPTIONAL_HEADER64 {
        HDR_MAGIC            Magic;
        BYTE                 MajorLinkerVersion;
        BYTE                 MinorLinkerVersion;
        DWORD                SizeOfCode;
        DWORD                SizeOfInitializedData;
        DWORD                SizeOfUninitializedData;
        DWORD                AddressOfEntryPoint;
        DWORD                BaseOfCode;
        ULONGLONG            ImageBase;
        DWORD                SectionAlignment;
        DWORD                FileAlignment;
        WORD                 MajorOperatingSystemVersion;
        WORD                 MinorOperatingSystemVersion;
        WORD                 MajorImageVersion;
        WORD                 MinorImageVersion;
        WORD                 MajorSubsystemVersion;
        WORD                 MinorSubsystemVersion;
        DWORD                Win32VersionValue;
        DWORD                SizeOfImage;
        DWORD                SizeOfHeaders;
        DWORD                CheckSum;
        HDR_SUBSYSTEM        Subsystem;
        WORD                 DllCharacteristics;
        ULONGLONG            SizeOfStackReserve;
        ULONGLONG            SizeOfStackCommit;
        ULONGLONG            SizeOfHeapReserve;
        ULONGLONG            SizeOfHeapCommit;
        DWORD                LoaderFlags;
        DWORD                NumberOfRvaAndSizes;
        IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
    };

    #define IMAGE_SIZEOF_SHORT_NAME 8

    struct IMAGE_SECTION_HEADER {
        uint8_t	Name[IMAGE_SIZEOF_SHORT_NAME];
        union {
            uint32_t PhysicalAddress;
            uint32_t VirtualSize;
        } Misc;
        uint32_t VirtualAddress;
        uint32_t SizeOfRawData;
        uint32_t PointerToRawData;
        uint32_t PointerToRelocations;
        uint32_t PointerToLinenumbers;
        uint16_t NumberOfRelocations;
        uint16_t NumberOfLinenumbers;
        uint32_t Characteristics;
    };
"""


class StructureView(Widget):
    COMPONENT_CLASSES = {
        "structureview--field-name",
        "structureview--field-type",
        "structureview--field-offset",
        "structureview--field-value",
        "structureview--field-decoration",
    }

    DEFAULT_CSS = """
        StructureView > Static.fields {
          margin-left: 1;
        }

        StructureView .structureview--struct-name {
          color: $secondary;
        }

        StructureView .structureview--field-name {
          color: $accent;
        }

        StructureView .structureview--field-type {
          color: $text-muted;
        }

        StructureView .structureview--field-offset {
          color: $text-muted;
        }

        StructureView .structureview--field-value {
          color: $text;
        }

        StructureView .structureview--field-decoration {
          color: $text-muted;
        }
    """

    def __init__(self, ctx: Context, address: int, typename: str, name: Optional[str] = None, *args, **kwargs):
        super().__init__(name=name, *args, **kwargs)
        self.add_class("pe-pane")
        self.styles.height = "auto"

        self.ctx = ctx
        self.address = address
        #self.name = name

        self.type = self.ctx.cparser.typedefs[typename]

        buf = self.ctx.buf[self.address:self.address + self.type.size]
        self.structure = self.type(buf)

    def compose(self) -> ComposeResult:
        yield Line(
            # like: struct IMAGE_DOS_HEADER {
            Static("struct ", classes="structureview--field-decoration"),
            Static(self.name or self.type.name, classes="structureview--struct-name"),
            Static(" {", classes="structureview--field-decoration")
        )

        # use a table for formatting the structure fields,
        # so that alignment is easy.
        table = rich.table.Table(box=None, show_header=False)

        style_name = self.get_component_rich_style("structureview--field-name")
        style_offset = self.get_component_rich_style("structureview--field-offset")
        style_value = self.get_component_rich_style("structureview--field-value")
        style_decoration = self.get_component_rich_style("structureview--field-decoration")

        table.add_column("name", style=style_name)
        table.add_column("=", style=style_decoration)
        table.add_column("value", style=style_value)
        table.add_column("@", style=style_decoration)
        table.add_column("offset", style=style_offset)

        for field in self.type.fields:
            value = getattr(self.structure, field.name)

            key = f"{self.type.name}.{field.name}"
            if key in self.ctx.renderers:
                try:
                    value = self.ctx.renderers[key](value)
                except DontRender:
                    continue
            elif isinstance(value, int):
                value = hex(value)
            elif isinstance(value, EnumInstance):
                # strip of enum name, leaving just the value.
                # like IMAGE_FILE_MACHINE_I386
                value = value.name

            table.add_row(
                str(field.name),
                "=",
                str(value),
                "@",
                hex(field.offset),
            )

        yield Static(table, classes="fields")

        yield Line(
            Static("}", classes="structureview--field-decoration")
        )
 

def render_timestamp(v: int) -> str:
    import datetime

    try:
        return datetime.datetime.fromtimestamp(v).isoformat("T") + "Z"
    except ValueError:
        return "(invalid)"


def render_bitflags(bits: List[Tuple[str, int]], v: int) -> str:
    if not v:
        return "(empty)"

    ret = []

    for flag, bit in bits:
        if (v & bit) == bit:
            ret.append(flag)

    return " |\n".join(ret)


def render_characteristics(v: int) -> str:
    bits = [
        ("IMAGE_FILE_RELOCS_STRIPPED", 0x0001),
        ("IMAGE_FILE_EXECUTABLE_IMAGE", 0x0002),
        ("IMAGE_FILE_LINE_NUMS_STRIPPED", 0x0004),
        ("IMAGE_FILE_LOCAL_SYMS_STRIPPED", 0x0008),
        ("IMAGE_FILE_AGGRESIVE_WS_TRIM", 0x0010),
        ("IMAGE_FILE_LARGE_ADDRESS_AWARE", 0x0020),
        ("IMAGE_FILE_16BIT_MACHINE", 0x0040),
        ("IMAGE_FILE_BYTES_REVERSED_LO", 0x0080),
        ("IMAGE_FILE_32BIT_MACHINE", 0x0100),
        ("IMAGE_FILE_DEBUG_STRIPPED", 0x0200),
        ("IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP", 0x0400),
        ("IMAGE_FILE_NET_RUN_FROM_SWAP", 0x0800),
        ("IMAGE_FILE_SYSTEM", 0x1000),
        ("IMAGE_FILE_DLL", 0x2000),
        ("IMAGE_FILE_UP_SYSTEM_ONLY", 0x4000),
        ("IMAGE_FILE_BYTES_REVERSED_HI", 0x8000),
    ]
    return render_bitflags(bits, v)


def render_dll_characteristics(v: int) -> str:
    bits = [
        ("IMAGE_LIBRARY_PROCESS_INIT", 0x0001),  # reserved
        ("IMAGE_LIBRARY_PROCESS_TERM", 0x0002),  # reserved
        ("IMAGE_LIBRARY_THREAD_INIT", 0x0004),  # reserved
        ("IMAGE_LIBRARY_THREAD_TERM", 0x0008),  # reserved
        ("IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA", 0x0020),
        ("IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE", 0x0040),
        ("IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY", 0x0080),
        ("IMAGE_DLLCHARACTERISTICS_NX_COMPAT", 0x0100),
        ("IMAGE_DLLCHARACTERISTICS_NO_ISOLATION", 0x0200),
        ("IMAGE_DLLCHARACTERISTICS_NO_SEH", 0x0400),
        ("IMAGE_DLLCHARACTERISTICS_NO_BIND", 0x0800),
        ("IMAGE_DLLCHARACTERISTICS_APPCONTAINER", 0x1000),
        ("IMAGE_DLLCHARACTERISTICS_WDM_DRIVER", 0x2000),
        ("IMAGE_DLLCHARACTERISTICS_GUARD_CF", 0x4000),
        ("IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE", 0x8000),
    ]
    return render_bitflags(bits, v)


class DontRender(Exception):
    pass


def dont_render(v: Any) -> str:
    raise DontRender()


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

        .section-hexview {
            height: 30;
        }
    """

    def __init__(self, path: pathlib.Path, buf: bytearray) -> None:
        super().__init__()

        # premature optimization consideration:
        # do the parsing within the app, in case the file is really large and this is laggy.
        # we can introduce background parsing later.
        pe = pefile.PE(data=buf, fast_load=False)

        cparser = cstruct.cstruct()
        cparser.load(STRUCTURES)

        renderers = {
            "IMAGE_FILE_HEADER.TimeDateStamp": render_timestamp,
            "IMAGE_FILE_HEADER.Characteristics": render_characteristics,
            "IMAGE_OPTIONAL_HEADER32.DllCharacteristics": render_dll_characteristics,
            "IMAGE_OPTIONAL_HEADER64.DllCharacteristics": render_dll_characteristics,
            # parsed in more detail elsewhere.
            "IMAGE_OPTIONAL_HEADER32.DataDirectory": dont_render,
            "IMAGE_OPTIONAL_HEADER64.DataDirectory": dont_render,
        }

        self.ctx = Context(path, buf, pe, cparser, renderers)

        self.title = f"pe: {self.ctx.path.name}"

    def compose(self) -> ComposeResult:
        yield Header()
        yield MetadataView(self.ctx)

        # sections
        # imports
        # exports
        # rich header (hex, parsed)
        # resources
        yield StructureView(self.ctx, self.ctx.pe.DOS_HEADER.get_file_offset(), "IMAGE_DOS_HEADER")
        yield StructureView(self.ctx, self.ctx.pe.FILE_HEADER.get_file_offset(), "IMAGE_FILE_HEADER")

        if self.ctx.bitness == 32:
            yield StructureView(self.ctx, self.ctx.pe.OPTIONAL_HEADER.get_file_offset(), "IMAGE_OPTIONAL_HEADER32")
        elif self.ctx.bitness == 64:
            yield StructureView(self.ctx, self.ctx.pe.OPTIONAL_HEADER.get_file_offset(), "IMAGE_OPTIONAL_HEADER64")
        else:
            raise ValueError(f"unknown bitness: {self.ctx.bitness}")

        for i, directory in enumerate(self.ctx.pe.OPTIONAL_HEADER.DATA_DIRECTORY):
            if directory.VirtualAddress == 0 or directory.Size == 0:
                continue

            enum = self.ctx.cparser.typedefs["IMAGE_DIRECTORY_ENTRY"]
            name = enum.reverse[i]

            # TODO: don't actually show these
            # show maybe as hex view
            yield StructureView(self.ctx, directory.get_file_offset(), f"IMAGE_DATA_DIRECTORY", name=name)

        for section in self.ctx.pe.sections:
            yield HexView(self.ctx, section.get_file_offset(), section.SizeOfRawData, classes="section-hexview")

            """
            # TODO: section view
            # height: size of screen?
            section.name

            section_dict["Entropy"] = section.get_entropy()
            if md5 is not None:
                section_dict["MD5"] = section.get_hash_md5()
            if sha1 is not None:
                section_dict["SHA1"] = section.get_hash_sha1()
            if sha256 is not None:
                section_dict["SHA256"] = section.get_hash_sha256()
            if sha512 is not None:
                section_dict["SHA512"] = section.get_hash_sha512()
            """

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
