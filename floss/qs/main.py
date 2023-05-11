import re
import sys
import json
import mmap
import logging
import pathlib
import argparse
import itertools
from typing import Set, Dict, Literal, Iterable, Sequence
from dataclasses import dataclass

from rich.text import Text
from rich.style import Style
from rich.console import Console

import floss.qs.db.oss
import floss.qs.db.winapi
from floss.qs.db.oss import OpenSourceStringDatabase
from floss.qs.db.winapi import WindowsApiStringDatabase

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


def extract_ascii_strings(buf: bytes, n: int = MIN_STR_LEN) -> Iterable[ExtractedString]:
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


def extract_unicode_strings(buf: bytes, n: int = MIN_STR_LEN) -> Iterable[ExtractedString]:
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
            yield ExtractedString(match.group().decode("utf-16"), match.start(), "unicode")
        except UnicodeDecodeError:
            pass


MUTED_STYLE = Style(color="gray50")
DEFAULT_STYLE = Style()
HIGHLIGHT_STYLE = Style(color="yellow")


def Span(text: str, style: Style = DEFAULT_STYLE) -> Text:
    """convenience function for single-line, styled text region"""
    return Text(text, style=style, no_wrap=True, overflow="ellipsis", end="")


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
    #    ^                                  ^ ^        ^ ^
    #    |                                  | |        | address
    #    |                                  | |        padding
    #    |                                  | tags
    #    |                                  padding
    #    string
    #
    #    ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^  ^^^^^^^^^^^^^^^^^^^^^^
    #    left column                       right column
    #
    # fields are basically laid out from right to left,
    # which means that the metadata may cause a string to be clipped.
    #
    # field sizes:
    #   address: 8
    #   padding: 2
    #   tags: variable, or 0
    #   padding: 2
    #   string: variable

    PADDING_WIDTH = 2
    ADDRESS_WIDTH = 8
    # length of each tag + 1 space between tags
    TAG_WIDTH = (sum(map(len, s.tags)) + len(s.tags) - 1) if s.tags else 0
    RIGHT_WIDTH = ADDRESS_WIDTH + PADDING_WIDTH + TAG_WIDTH + PADDING_WIDTH
    LEFT_WIDTH = width - RIGHT_WIDTH

    line = Text()

    string_style = DEFAULT_STYLE
    for tag in s.tags:
        if string_style == HIGHLIGHT_STYLE:
            # highlight overrules mute.
            # if we're already highlight, don't mute
            continue

        # string style is either muted or default
        rule = tag_rules.get(tag, "mute")
        if rule == "highlight":
            # upgrade to highlight
            string_style = HIGHLIGHT_STYLE
        elif rule == "mute":
            # default -> mute
            # mute -> mute
            string_style = MUTED_STYLE
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
        tag_style = DEFAULT_STYLE
        rule = tag_rules.get(tag, "mute")
        if rule == "highlight":
            tag_style = HIGHLIGHT_STYLE
        elif rule == "mute":
            tag_style = MUTED_STYLE
        else:
            raise ValueError(f"unknown tag rule: {rule}")

        tags.append_text(Span(tag, style=tag_style))
        if i < len(s.tags) - 1:
            tags.append_text(Span(" "))

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
        addr.append_text(Span("0" * padding_width, style=MUTED_STYLE))
        addr.append_text(Span(unpadded, style=Style(color="blue")))
        line.append_text(addr)

    return line


def query_global_prevalence_database(string: str) -> Sequence[Tag]:
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

    if string in global_prevalence:
        return ("#common",)

    else:
        return ()


def query_library_string_databases(dbs: Sequence[OpenSourceStringDatabase], string: str) -> Sequence[Tag]:
    tags = set()
    for db in dbs:
        meta = db.metadata_by_string.get(string)
        if not meta:
            continue

        tags.add(f"#{meta.library_name}")

    return tuple(tags)


def query_winapi_name_database(db: WindowsApiStringDatabase, string: str) -> Sequence[Tag]:
    if string.lower() in db.dll_names:
        return ("#winapi",)

    if string in db.api_names:
        return ("#winapi",)

    return ()


def main():
    # set environment variable NO_COLOR=1 to disable color output.
    # set environment variable FORCE_COLOR=1 to force color output, such as when piping to a pager.
    parser = argparse.ArgumentParser(description="Extract human readable strings from binary data, quantum-style.")
    parser.add_argument("path", help="file or path to analyze")
    logging_group = parser.add_argument_group("logging arguments")
    logging_group.add_argument("-d", "--debug", action="store_true", help="enable debugging output on STDERR")
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
                    itertools.chain(extract_ascii_strings(buf), extract_unicode_strings(buf)),
                    key=lambda s: s.offset,
                )
            )

    winapi_path = pathlib.Path(floss.qs.db.winapi.__file__).parent / "data" / "winapi"
    winapi_database = floss.qs.db.winapi.WindowsApiStringDatabase.from_dir(winapi_path)

    library_databases = (
        OpenSourceStringDatabase.from_file(
            pathlib.Path(floss.qs.db.oss.__file__).parent / "data" / "oss" / "zlib.jsonl.gz"
        ),
    )

    tagged_strings = list(map(lambda s: TaggedString(s, set()), strings))

    for string in tagged_strings:
        key = string.string.string

        string.tags.update(query_global_prevalence_database(key))
        string.tags.update(query_library_string_databases(library_databases, key))
        string.tags.update(query_winapi_name_database(winapi_database, key))

    console = Console()
    tag_rules = {
        "#common": "mute",
        "#zlib": "mute",
        "#bzip2": "mute",
        "#sqlite3": "mute",
        "#winapi": "mute",
    }
    for string in tagged_strings:
        console.print(render_string(console.width, string, tag_rules))

    return 0


if __name__ == "__main__":
    sys.exit(main())
