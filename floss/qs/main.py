import re
import sys
import json
import mmap
import logging
import pathlib
import argparse
import itertools
from typing import Set, Dict, Literal, Iterable, Optional, Sequence
from dataclasses import dataclass

import pefile
from rich.text import Text
from rich.style import Style
from rich.console import Console

import floss.qs.db.oss
import floss.qs.db.winapi
from floss.qs.db.gp import StringGlobalPrevalenceDatabase
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
    #    |                                  | |        | offset
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
    #   offset: 8
    #   padding: 2
    #   tags: variable, or 0
    #   padding: 2
    #   string: variable

    PADDING_WIDTH = 2
    OFFSET_WIDTH = 8
    # length of each tag + 1 space between tags
    TAG_WIDTH = (sum(map(len, s.tags)) + len(s.tags) - 1) if s.tags else 0
    RIGHT_WIDTH = OFFSET_WIDTH + PADDING_WIDTH + TAG_WIDTH + PADDING_WIDTH
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
    # leaving an ellipsis at the end when it would collide with a tag/offset.
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
        # render the 000 prefix of the 8-digit offset in muted gray
        # and the non-zero suffix as blue.
        offset_chars = f"{s.string.offset:08x}"
        unpadded = offset_chars.lstrip("0")
        padding_width = len(offset_chars) - len(unpadded)

        offset = Span("")
        offset.append_text(Span("0" * padding_width, style=MUTED_STYLE))
        offset.append_text(Span(unpadded, style=Style(color="blue")))
        line.append_text(offset)

    return line


def query_global_prevalence_database(global_prevalence_database, string):
    if global_prevalence_database.query(string):
        return ("#common",)

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


@dataclass
class Segment:
    offset: int
    length: int
    type: Literal["segment"] | Literal["section"]
    section: Optional[pefile.SectionStructure] = None

    @property
    def end(self) -> int:
        return self.offset + self.length


def compute_file_segments(pe: pefile.PE) -> Sequence[Segment]:
    regions = []

    for section in sorted(pe.sections, key=lambda s: s.PointerToRawData):
        if section.SizeOfRawData == 0:
            continue
        regions.append(Segment(section.get_PointerToRawData_adj(), section.SizeOfRawData, "section", section))

    # segment that contains all data until the first section
    regions.insert(0, Segment(0, regions[0].offset, "segment"))

    # segment that contains all data after the last section
    # aka. "overlay"
    last_section = regions[-1]
    if pe.__data__ is not None:
        buf = pe.__data__
        if last_section.end < len(buf):
            regions.append(Segment(last_section.end, len(buf) - last_section.end, "segment"))

    # add segments for any gaps between sections.
    # note that we append new items to the end of the list and then resort,
    # to avoid mutating the list while we're iterating over it.
    for i in range(1, len(regions)):
        prior = regions[i - 1]
        region = regions[i]

        if prior.end != region.offset:
            regions.append(Segment(prior.end, region.offset - prior.end, "segment"))
    regions.sort(key=lambda s: s.offset)

    return regions


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

        if hasattr(mmap, "MAP_PRIVATE"):
            # unix
            kwargs = {"flags": mmap.MAP_PRIVATE, "prot": mmap.PROT_READ}
        else:
            # windows
            kwargs = {"access": mmap.ACCESS_READ}

        with mmap.mmap(f.fileno(), length=WHOLE_FILE, **kwargs) as mm:
            # treat the mmap as a readable bytearray
            buf: bytearray = mm  # type: ignore

            strings = list(
                sorted(
                    itertools.chain(extract_ascii_strings(buf), extract_unicode_strings(buf)),
                    key=lambda s: s.offset,
                )
            )

            pe: Optional[pefile.PE] = None
            segments: Sequence[Segment] = []
            try:
                pe = pefile.PE(data=buf)
            except Exception as e:
                logger.warning("failed to parse as PE: %s", e, exc_info=True)
            else:
                segments = compute_file_segments(pe)

    winapi_path = pathlib.Path(floss.qs.db.winapi.__file__).parent / "data" / "winapi"
    winapi_database = floss.qs.db.winapi.WindowsApiStringDatabase.from_dir(winapi_path)

    library_databases = (
        OpenSourceStringDatabase.from_file(
            pathlib.Path(floss.qs.db.oss.__file__).parent / "data" / "oss" / "zlib.jsonl.gz"
        ),
    )

    tagged_strings = list(map(lambda s: TaggedString(s, set()), strings))

    gp_path = pathlib.Path(floss.qs.db.gp.__file__).parent / "data" / "gp" / "gp.jsonl.gz"
    global_prevalence_database = StringGlobalPrevalenceDatabase.from_file(gp_path)
    gp_path = pathlib.Path(floss.qs.db.gp.__file__).parent / "data" / "gp" / "cwindb-native.jsonl.gz"
    global_prevalence_database.update(StringGlobalPrevalenceDatabase.from_file(gp_path))
    gp_path = pathlib.Path(floss.qs.db.gp.__file__).parent / "data" / "gp" / "cwindb-dotnet.jsonl.gz"
    global_prevalence_database.update(StringGlobalPrevalenceDatabase.from_file(gp_path))

    for string in tagged_strings:
        key = string.string.string

        string.tags.update(query_global_prevalence_database(global_prevalence_database, key))
        string.tags.update(query_library_string_databases(library_databases, key))
        string.tags.update(query_winapi_name_database(winapi_database, key))

    console = Console()
    tag_rules: Dict[str, Literal["mute"] | Literal["highlight"]] = {
        "#common": "mute",
        "#zlib": "mute",
        "#bzip2": "mute",
        "#sqlite3": "mute",
        "#winapi": "mute",
    }

    if segments:
        for i, segment in enumerate(segments):
            strings_in_segment = list(filter(lambda s: segment.offset <= s.string.offset < segment.end, tagged_strings))

            if len(strings_in_segment) == 0:
                continue

            if segment.type == "section":
                try:
                    assert segment.section is not None
                    assert isinstance(segment.section, pefile.SectionStructure)
                    key = segment.section.Name.partition(b"\x00")[0].decode("utf-8")
                except UnicodeDecodeError:
                    key = "(invalid)"
            elif segment.type == "segment":
                if i == 0:
                    key = "header"
                elif i == len(segments) - 1:
                    key = "overlay"
                else:
                    key = f"gap ({i - 1})"
            else:
                raise NotImplementedError(segment.type)

            header = Span(key, style=MUTED_STYLE)
            header.pad(1)
            header.align("center", width=console.width, character="━")
            console.print(header)

            for string in strings_in_segment:
                console.print(render_string(console.width, string, tag_rules))

    else:
        for string in tagged_strings:
            console.print(render_string(console.width, string, tag_rules))

    return 0


if __name__ == "__main__":
    sys.exit(main())
