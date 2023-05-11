import json
import re
import sys
import mmap
import pathlib
import logging
import argparse
import itertools
from dataclasses import dataclass
from typing import Dict, List, Tuple, Literal, Iterable, Set

from rich.text import Text
from rich.style import Style
from rich.console import Console


MIN_STR_LEN = 6

logger = logging.getLogger(__name__)


ASCII_BYTE = r" !\"#\$%&\'\(\)\*\+,-\./0123456789:;<=>\?@ABCDEFGHIJKLMNOPQRSTUVWXYZ\[\]\^_`abcdefghijklmnopqrstuvwxyz\{\|\}\\\~\t".encode(
    "ascii"
)
ASCII_RE_6 = re.compile(b"([%s]{%d,})" % (ASCII_BYTE, 6))
UNICODE_RE_6 = re.compile(b"((?:[%s]\x00){%d,})" % (ASCII_BYTE, 6))


@dataclass
class ExtractedString:
    string: str
    offset: int
    encoding: Literal["ascii", "unicode"]


Tag = str


@dataclass
class TaggedString:
    string: ExtractedString
    tags: Set[Tag]


def extract_ascii_strings(
    buf: bytes, n: int = MIN_STR_LEN
) -> Iterable[ExtractedString]:
    """Extract ASCII strings from the given binary data."""

    if not buf:
        return

    r = None
    if n == MIN_STR_LEN:
        r = ASCII_RE_6
    else:
        reg = b"([%s]{%d,})" % (ASCII_BYTE, n)
        r = re.compile(reg)
    for match in r.finditer(buf):
        yield ExtractedString(match.group().decode("ascii"), match.start(), "ascii")


def extract_unicode_strings(
    buf: bytes, n: int = MIN_STR_LEN
) -> Iterable[ExtractedString]:
    """Extract naive UTF-16 strings from the given binary data."""
    if not buf:
        return

    if n == MIN_STR_LEN:
        r = UNICODE_RE_6
    else:
        reg = b"((?:[%s]\x00){%d,})" % (ASCII_BYTE, n)
        r = re.compile(reg)
    for match in r.finditer(buf):
        try:
            yield ExtractedString(
                match.group().decode("utf-16"), match.start(), "unicode"
            )
        except UnicodeDecodeError:
            pass


def render_string(
    width: int,
    s: TaggedString,
    tag_rules: Dict[Tag, Literal["mute"] | Literal["highlight"]],
) -> Text:
    #
    #  | stringstringstring              #tag #tag #tag  00000001 |
    #  | stringstring                              #tag  0000004A |
    #  | string                                    #tag  00000050 |
    #  | stringstringstringstringstringst...  #tag #tag  0000005E |
    #
    #    length: varies                      2 varies   2     8

    PADDING_WIDTH = 2
    ADDRESS_WIDTH = 8
    # length of each tag + 1 space between tags
    TAG_WIDTH = (sum(map(len, s.tags)) + len(s.tags) - 1) if s.tags else 0
    RIGHT_WIDTH = ADDRESS_WIDTH + PADDING_WIDTH + TAG_WIDTH + PADDING_WIDTH
    LEFT_WIDTH = width - RIGHT_WIDTH

    MUTED = Style(color="gray50")
    DEFAULT = Style()
    HIGHLIGHT = Style(color="yellow")

    def Span(text: str, style: Style = DEFAULT) -> Text:
        return Text(text, style=style, no_wrap=True, overflow="ellipsis", end="")

    line = Text()

    string_style = DEFAULT
    for tag in s.tags:
        if string_style == HIGHLIGHT:
            # highlight overrules mute.
            # if we're already highlight, don't mute
            continue

        # string style is either muted or default
        rule = tag_rules.get(tag, "mute")
        if rule == "highlight":
            # upgrade to highlight
            string_style = HIGHLIGHT
        elif rule == "mute":
            # default -> mute
            # mute -> mute
            string_style = MUTED
        else:
            raise ValueError(f"unknown tag rule: {rule}")

    # render like json, but strip the leading/trailing quote marks.
    # this means that whitespace characters like \t and \n will be rendered as such,
    # which ensures that the rendered string will be a single line.
    rendered_string = json.dumps(s.string.string)[1:-1]
    string = Span(rendered_string, style=string_style)
    # this alignment clips the string if it's too long,
    # leaving an ellipsis at the end when it would collide with a tag/address.
    # this is bad for showing all data verbatim,
    # but is good for the common case of triage analysis.
    string.align("left", LEFT_WIDTH)

    line.append_text(string)

    line.append_text(Span(" " * PADDING_WIDTH))

    tags = Text()
    for i, tag in enumerate(s.tags):
        tag_style = DEFAULT
        rule = tag_rules.get(tag, "mute")
        if rule == "highlight":
            tag_style = HIGHLIGHT
        elif rule == "mute":
            tag_style = MUTED
        else:
            raise ValueError(f"unknown tag rule: {rule}")

        tags.append_text(Span(tag, style=tag_style))
        if i < len(s.tags) - 1:
            tags.append_text(" ")

    tags.align("right", TAG_WIDTH)
    line.append_text(tags)

    line.append_text(Span(" " * PADDING_WIDTH))

    if True:
        # render the 000 prefix of the 8-digit address in muted gray
        # and the non-zero suffix as blue.
        addr_chars = f"{s.string.offset:08x}"
        unpadded = addr_chars.lstrip("0")
        padding_width = len(addr_chars) - len(unpadded)

        addr = Span("")
        addr.append_text(Span("0" * padding_width, style=MUTED))
        addr.append_text(Span(unpadded, style=Style(color="blue")))
        line.append_text(addr)

    return line


def main():
    parser = argparse.ArgumentParser(
        description="Extract human readable strings from binary data, quantum-style."
    )
    parser.add_argument("path", help="file or path to analyze")
    logging_group = parser.add_argument_group("logging arguments")
    logging_group.add_argument(
        "-d", "--debug", action="store_true", help="enable debugging output on STDERR"
    )
    logging_group.add_argument(
        "-q",
        "--quiet",
        action="store_true",
        help="disable all status output except fatal errors",
    )
    args = parser.parse_args()

    if args.quiet:
        logging.basicConfig(level=logging.WARNING)
        logging.getLogger().setLevel(logging.WARNING)
    elif args.debug:
        logging.basicConfig(level=logging.DEBUG)
        logging.getLogger().setLevel(logging.DEBUG)
    else:
        logging.basicConfig(level=logging.INFO)
        logging.getLogger().setLevel(logging.INFO)

    path = pathlib.Path(args.path)
    if not path.exists():
        logging.error("%s does not exist", path)
        return 1

    with path.open("rb") as f:
        WHOLE_FILE = 0

        # TODO: needs to be tested on Windows, macOS
        with mmap.mmap(f.fileno(), length=WHOLE_FILE, access=mmap.ACCESS_READ) as mm:
            # treat the mmap as a readable bytearray
            buf: bytearray = mm  # type: ignore

            strings = list(
                sorted(
                    itertools.chain(
                        extract_ascii_strings(buf), extract_unicode_strings(buf)
                    ),
                    key=lambda s: s.offset,
                )
            )

    global_prevalence = {
        "!This program cannot be run in DOS mode.",
        "Rich",
        "This program must be run under Win32",
        "This program cannot be run in Win32 mode.",
        "kernel32.dll",
        "USER32.dll",
        "ADVAPI32.dll",
        "January",
        "February",
    }

    libraries = {
        "zlib": {
            " 1.2.13 Copyright 1995-2022 Jean-loup Gailly and Mark Adler ",
            " deflate 1.2.13 Copyright 1995-2022 Jean-loup Gailly and Mark Adler ",
            " inflate 1.2.13 Copyright 1995-2022 Mark Adler ",
            "%s%s%s",
            "1.2.13",
            "<fd:%d>",
            "compressed data error",
            "internal error: deflate stream corrupt",
            "internal error: inflate stream corrupt",
            "invalid block type",
            "invalid distance code",
            "invalid distance too far back",
            "invalid literal/length code",
            "need dictionary",
            "out of memory",
            "out of room to push characters",
            "request does not fit in a size_t",
            "request does not fit in an int",
            "requested length does not fit in int",
            "string length does not fit in int",
            "unexpected end of file",
        },
        "bzip2": {
            "        %d pointers, %d sorted, %d scanned",
            "        bucket sorting ...",
            "        depth %6d has ",
            "        main sort initialise ...",
            "        qsort [0x%x, 0x%x]   done %d   this %d",
            "        reconstructing block ...",
            "      %d in block, %d after MTF & 1-2 coding, %d+2 syms in use",
            "      %d work, %d block, ratio %5.2f",
            "      bytes: mapping %d, ",
            "      initial group %d, [%d .. %d], has %d syms (%4.1f%%)",
            "      pass %d: size is %d, grp uses are ",
            "    block %d: crc = 0x%08x, combined CRC = 0x%08x, size = %d",
            "    final combined CRC = 0x%08x",
            "    too repetitive; using fallback sorting algorithm",
            " {0x%08x, 0x%08x}",
            "%6d unresolved strings",
            "1.0.8, 13-Jul-2019",
            "    combined CRCs: stored = 0x%08x, computed = 0x%08x",
            "bzip2/libbzip2: internal error number %d.",
            "This is a bug in bzip2/libbzip2, %s.",
            "Please report it to: bzip2-devel@sourceware.org.  If this happened",
            "when you were using some program which uses libbzip2 as a",
            "component, you should also report this bug to the author(s)",
            "of that program.  Please make an effort to report this bug;",
            "timely and accurate bug reports eventually lead to higher",
            "quality software.  Thanks.",
            "code lengths %d, ",
            "codes %d",
            "selectors %d, ",
        },
        "sqlite3": {
            'cannot %s %s "%s"',
            'cannot INSERT into generated column "%s"',
            'cannot UPDATE generated column "%s"',
            "cannot UPSERT a view",
            "cannot VACUUM - SQL statements in progress",
            "cannot VACUUM from within a transaction",
            "cannot add a STORED column",
            "cannot create %s trigger on view: %S",
            "cannot create INSTEAD OF trigger on table: %S",
            'cannot create a TEMP index on non-TEMP table "%s"',
            "cannot create trigger on system table",
            "cannot create triggers on virtual tables",
            "cannot detach database %s",
            'cannot drop %s column: "%s"',
            'cannot drop column "%s": no other columns exist',
            "cannot join using column %s - column not present in both tables",
            "cannot limit WAL size: %s",
            "cannot modify %s because it is a view",
            "cannot open %s column for writing",
            "cannot open file",
            "cannot open table without rowid: %s",
            "cannot open value of type %s",
            "cannot open view: %s",
            "cannot open virtual table: %s",
            "cannot override %s of window: %s",
            "cannot use DEFAULT on a generated column",
            "cannot use RETURNING in a trigger",
            "cannot use window functions in recursive queries",
        },
    }

    tagged_strings = list(map(lambda s: TaggedString(s, set()), strings))

    for string in tagged_strings:
        key = string.string.string

        if key in global_prevalence:
            string.tags.add(Tag("#common"))

        for library, library_strings in libraries.items():
            if key in library_strings:
                string.tags.add(Tag(f"#{library}"))

    console = Console()
    tag_rules = {
        "#common": "mute",
        "#zlib": "mute",
        "#bzip2": "mute",
        "#sqlite3": "mute",
    }
    for string in tagged_strings:
        console.print(render_string(console.width, string, tag_rules))

    return 0


if __name__ == "__main__":
    sys.exit(main())
