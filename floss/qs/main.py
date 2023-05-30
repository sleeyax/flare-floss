import abc
import io
import re
import sys
import json
import time
import bisect
import logging
import pathlib
import argparse
import itertools
import contextlib
from typing import Any, Callable, List, Set, Dict, Union, Literal, Iterable, Optional, Sequence
from dataclasses import dataclass, field

import pefile
import colorama
import lancelot
import intervaltree
import rich.traceback
from rich.text import Text
from rich.style import Style
from rich.console import Console

import floss.main
import floss.qs.db.oss
import floss.qs.db.winapi
from floss.qs.db.gp import StringHashDatabase, StringGlobalPrevalenceDatabase
from floss.qs.db.oss import OpenSourceStringDatabase
from floss.qs.db.expert import ExpertStringDatabase
from floss.qs.db.winapi import WindowsApiStringDatabase

MIN_STR_LEN = 6

logger = logging.getLogger("quantumstrand")


@contextlib.contextmanager
def timing(msg: str):
    t0 = time.time()
    yield
    t1 = time.time()
    logger.debug("perf: %s: %0.2fs", msg, t1 - t0)


@dataclass
class Range:
    offset: int
    length: int

    @property
    def end(self) -> int:
        return self.offset + self.length

    def slice(self, offset, size) -> "Range":
        "create a new range thats a sub-range of this one"
        assert offset < self.length
        assert offset + size <= self.length
        return Range(self.offset + offset, size)

    def __contains__(self, other: Union[int, "Range"]) -> bool:
        if isinstance(other, int):
            # this range strictly contains the point
            return self.offset <= other < self.end
        elif isinstance(other, Range):
            # this range strictly contains the other one
            return (other.offset in self) and (other.end in self)
        else:
            raise TypeError(f"unsupported type: {type(other)}")

    def __iter__(self):
        yield from range(self.offset, self.end)

    def __repr__(self):
        return f"Range(start: 0x{self.offset:x}, size: 0x{self.length:x}, end: 0x{self.end:x})"

    def __str__(self):
        return repr(self)


@dataclass
class Slice:
    """
    a contiguous range within a sequence of bytes.
    notably, it can be further sliced without copying the underlying bytes.
    a bit like a memoryview.
    """

    buf: bytes
    range: Range

    @property
    def data(self) -> bytes:
        return self.buf[self.range.offset : self.range.end]

    def slice(self, offset, size) -> "Slice":
        "create a new slice thats a sub-slice of this one"
        return Slice(self.buf, self.range.slice(offset, size))

    @classmethod
    def from_bytes(cls, buf: bytes) -> "Range":
        return cls(buf, Range(0, len(buf)))

    def __repr__(self):
        return f"Slice({repr(self.range)} of bytes of size 0x{len(self.buf):x})"

    def __str__(self):
        return repr(self)


@dataclass
class ExtractedString:
    string: str
    slice: Slice
    encoding: Literal["ascii", "unicode"]


Tag = str


@dataclass
class TaggedString:
    string: ExtractedString
    tags: Set[Tag]
    structure: str = ""

    @property
    def offset(self) -> int:
        "convenience"
        return self.string.slice.range.offset


ASCII_BYTE = r" !\"#\$%&\'\(\)\*\+,-\./0123456789:;<=>\?@ABCDEFGHIJKLMNOPQRSTUVWXYZ\[\]\^_`abcdefghijklmnopqrstuvwxyz\{\|\}\\\~\t".encode(
    "ascii"
)
ASCII_RE_6 = re.compile(b"([%s]{%d,})" % (ASCII_BYTE, 6))
UNICODE_RE_6 = re.compile(b"((?:[%s]\x00){%d,})" % (ASCII_BYTE, 6))


def extract_ascii_strings(slice: Slice, n: int = MIN_STR_LEN) -> Iterable[ExtractedString]:
    """Extract ASCII strings from the given binary data."""

    if not slice.range.length:
        return

    r: re.Pattern
    if n == MIN_STR_LEN:
        r = ASCII_RE_6
    else:
        reg = b"([%s]{%d,})" % (ASCII_BYTE, n)
        r = re.compile(reg)

    for match in r.finditer(slice.data):
        offset = match.start()
        length = match.end() - match.start()
        string = match.group().decode("ascii")
        yield ExtractedString(
            string=string, 
            slice=slice.slice(offset, length), 
            encoding="ascii"
        )


def extract_unicode_strings(slice: Slice, n: int = MIN_STR_LEN) -> Iterable[ExtractedString]:
    """Extract naive UTF-16 strings from the given binary data."""

    if not slice.range.length:
        return

    r: re.Pattern
    if n == MIN_STR_LEN:
        r = UNICODE_RE_6
    else:
        reg = b"((?:[%s]\x00){%d,})" % (ASCII_BYTE, n)
        r = re.compile(reg)

    for match in r.finditer(slice.data):
        offset = match.start()
        length = match.end() - match.start()
        
        try:
            string = match.group().decode("utf-16")
        except UnicodeDecodeError:
            continue

        yield ExtractedString(
            string=string, 
            slice=slice.slice(offset, length),
            encoding="unicode"
        )


def extract_strings(slice: Slice, n: int = MIN_STR_LEN) -> Iterable[ExtractedString]:
    return list(
        sorted(
            itertools.chain(extract_ascii_strings(slice, n), extract_unicode_strings(slice, n)),
            key=lambda s: s.slice.range.offset,
        )
    )


MUTED_STYLE = Style(color="gray50")
DEFAULT_STYLE = Style()
HIGHLIGHT_STYLE = Style(color="yellow")


def Span(text: str, style: Style = DEFAULT_STYLE) -> Text:
    """convenience function for single-line, styled text region"""
    return Text(text, style=style, no_wrap=True, overflow="ellipsis", end="")


PADDING_WIDTH = 2
OFFSET_WIDTH = 8
STRUCTURE_WIDTH = 16


def render_string_padding():
    return Span(" " * PADDING_WIDTH)


TagRules = Dict[Tag, Literal["mute"] | Literal["highlight"] | Literal["default"] | Literal["hide"]]


def should_hide_string(s: TaggedString, tag_rules: TagRules) -> bool:
    return any(map(lambda tag: tag_rules.get(tag) == "hide", s.tags))


def compute_string_style(s: TaggedString, tag_rules: TagRules) -> Optional[Style]:
    """compute the style for a string based on its tags

    returns: Style, or None if the string should be hidden.
    """
    styles = set(tag_rules.get(tag, "mute") for tag in s.tags)

    # precedence:
    #
    #  1. highlight
    #  2. hide
    #  3. mute
    #  4. default
    if "highlight" in styles:
        return HIGHLIGHT_STYLE
    elif "hide" in styles:
        return None
    elif "mute" in styles:
        return MUTED_STYLE
    else:
        return DEFAULT_STYLE


def render_string_string(s: TaggedString, tag_rules: TagRules) -> Text:
    string_style = compute_string_style(s, tag_rules)
    if string_style is None:
        raise ValueError("string should be hidden")

    # render like json, but strip the leading/trailing quote marks.
    # this means that whitespace characters like \t and \n will be rendered as such,
    # which ensures that the rendered string will be a single line.
    rendered_string = json.dumps(s.string.string)[1:-1]
    return Span(rendered_string, style=string_style)


def render_string_tags(s: TaggedString, tag_rules: TagRules):
    ret = Text()

    tags = s.tags
    if len(tags) != 1 and "#common" in tags:
        # don't show #common if there are other tags,
        # because the other tags will be more specific (like library names).
        tags.remove("#common")

    for i, tag in enumerate(sorted(tags)):
        tag_style = DEFAULT_STYLE
        rule = tag_rules.get(tag, "mute")
        if rule == "highlight":
            tag_style = HIGHLIGHT_STYLE
        elif rule == "mute":
            tag_style = MUTED_STYLE
        elif rule == "default":
            tag_style = DEFAULT_STYLE
        else:
            raise ValueError(f"unknown tag rule: {rule}")

        ret.append_text(Span(tag, style=tag_style))
        if i < len(s.tags) - 1:
            ret.append_text(Span(" "))

    return ret


def render_string_offset(s: TaggedString):
    # render the 000 prefix of the 8-digit offset in muted gray
    # and the non-zero suffix as blue.
    offset_chars = f"{s.offset:08x}"
    unpadded = offset_chars.lstrip("0")
    padding_width = len(offset_chars) - len(unpadded)

    offset = Span("")
    offset.append_text(Span("0" * padding_width, style=MUTED_STYLE))
    offset.append_text(Span(unpadded, style=Style(color="blue")))

    return offset


def render_string_structure(s: TaggedString):
    ret = Text()

    if s.structure:
        structure = Span("/" + s.structure, style=MUTED_STYLE)
        structure.align("left", STRUCTURE_WIDTH)
        ret.append(structure)
    else:
        ret.append_text(Span(" " * STRUCTURE_WIDTH))

    return ret


def render_string(width: int, s: TaggedString, tag_rules: TagRules) -> Text:
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
    #   structure: 8
    #   padding: 2
    #   offset: 8
    #   padding: 2
    #   tags: variable, or 0
    #   padding: 2
    #   string: variable

    left = render_string_string(s, tag_rules)

    right = Span("")
    right.append_text(render_string_padding())
    right.append_text(render_string_tags(s, tag_rules))
    right.append_text(render_string_padding())
    right.append_text(render_string_offset(s))
    right.append_text(render_string_structure(s))

    # this alignment clips the string if it's too long,
    # leaving an ellipsis at the end when it would collide with a tag/offset.
    # this is bad for showing all data verbatim,
    # but is good for the common case of triage analysis.
    left.align("left", width - len(right))

    line = Text()
    line.append_text(left)
    line.append_text(right)

    return line


def get_reloc_offsets(slice: Slice, pe: pefile.PE) -> Set[int]:
    ret = set()

    directory_index = pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_BASERELOC"]

    if pe.OPTIONAL_HEADER is None or pe.OPTIONAL_HEADER.DATA_DIRECTORY is None:
        return ret

    try:
        dir_entry = pe.OPTIONAL_HEADER.DATA_DIRECTORY[directory_index]
    except IndexError:
        return ret

    rva = dir_entry.VirtualAddress
    offset = pe.get_offset_from_rva(rva)
    size = dir_entry.Size

    for fo in slice.range.slice(offset, size):
        ret.add(fo)

    return ret


def check_is_reloc(reloc_offsets: Set[int], string: ExtractedString):
    for addr in string.slice.range:
        if addr in reloc_offsets:
            return ("#reloc",)

    return ()


def check_is_code(code_offsets: Set[int], string: ExtractedString):
    for addr in string.slice.range:
        if addr in code_offsets:
            return ("#code",)

    return ()


def query_global_prevalence_database(db: StringGlobalPrevalenceDatabase, string: str):
    if db.query(string):
        return ("#common",)

    return ()


def query_global_prevalence_hash_database(db: StringHashDatabase, string: str):
    if string in db:
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


def query_expert_string_database(db: ExpertStringDatabase, string: str) -> Sequence[Tag]:
    return tuple(db.query(string))


def query_winapi_name_database(db: WindowsApiStringDatabase, string: str) -> Sequence[Tag]:
    if string.lower() in db.dll_names:
        return ("#winapi",)

    if string in db.api_names:
        return ("#winapi",)

    return ()


Tagger = Callable[[TaggedString], Sequence[Tag]]

OSS_DATABASE_FILENAMES = (
    "brotli.jsonl.gz",
    "bzip2.jsonl.gz",
    "cryptopp.jsonl.gz",
    "curl.jsonl.gz",
    "detours.jsonl.gz",
    "jemalloc.jsonl.gz",
    "jsoncpp.jsonl.gz",
    "kcp.jsonl.gz",
    "liblzma.jsonl.gz",
    "libsodium.jsonl.gz",
    "libpcap.jsonl.gz",
    "mbedtls.jsonl.gz",
    "openssl.jsonl.gz",
    "sqlite3.jsonl.gz",
    "tomcrypt.jsonl.gz",
    "wolfssl.jsonl.gz",
    "zlib.jsonl.gz",
)


def load_databases() -> Sequence[Tagger]:
    ret = []

    data_path = pathlib.Path(floss.qs.db.oss.__file__).parent / "data"

    if True:
        winapi_database = floss.qs.db.winapi.WindowsApiStringDatabase.from_dir(data_path / "winapi")

        def winapi_database_tagger(s: ExtractedString) -> Sequence[Tag]:
            return query_winapi_name_database(winapi_database, s.string)

        ret.append(winapi_database_tagger)

    if True:
        capa_expert_database = ExpertStringDatabase.from_file(data_path / "expert" / "capa.jsonl")

        def capa_expert_database_tagger(s: ExtractedString) -> Sequence[Tag]:
            return query_expert_string_database(capa_expert_database, s.string)

        ret.append(capa_expert_database_tagger)

    if True:


        library_databases = [
            OpenSourceStringDatabase.from_file(data_path / "oss" / filename) for filename in OSS_DATABASE_FILENAMES
        ]

        library_databases.append(OpenSourceStringDatabase.from_file(data_path / "crt" / "msvc_v143.jsonl.gz"))


        def library_databases_tagger(s: ExtractedString) -> Sequence[Tag]:
            return query_library_string_databases(library_databases, s.string)

        ret.append(library_databases_tagger)

    if True:
        global_prevalence_database = StringGlobalPrevalenceDatabase.from_file(data_path / "gp" / "gp.jsonl.gz")
        global_prevalence_database.update(StringGlobalPrevalenceDatabase.from_file(data_path / "gp" / "cwindb-native.jsonl.gz"))
        global_prevalence_database.update(StringGlobalPrevalenceDatabase.from_file(data_path / "gp" / "cwindb-dotnet.jsonl.gz"))

        def global_prevalence_database_tagger(s: ExtractedString) -> Sequence[Tag]:
            return query_global_prevalence_database(global_prevalence_database, s.string)

        ret.append(global_prevalence_database_tagger)

    if True:
        global_prevalence_hash_database_xaa = StringHashDatabase.from_file(data_path / "gp" / "xaa-hashes.bin")

        def global_prevalence_hash_database_xaa_tagger(s: ExtractedString) -> Sequence[Tag]:
            return query_global_prevalence_hash_database(global_prevalence_hash_database_xaa, s.string)

        ret.append(global_prevalence_hash_database_xaa_tagger)

    if True:
        global_prevalence_hash_database_yaa = StringHashDatabase.from_file(data_path / "gp" / "yaa-hashes.bin")

        def global_prevalence_hash_database_yaa_tagger(s: ExtractedString) -> Sequence[Tag]:
            return query_global_prevalence_hash_database(global_prevalence_hash_database_yaa, s.string)

        ret.append(global_prevalence_hash_database_yaa_tagger)

    return ret


@dataclass
class Layout(abc.ABC):
    slice: Slice

    # human readable name
    name: str

    parent: Optional["Layout"] = field(init=False, default=None)

    # ordered by address
    # non-overlapping
    # may not cover the entire range (non-contiguous)
    children: Sequence["Layout"] = field(init=False, default_factory=list)

    # this is populated by the call to extract_strings.
    # only strings not contained by the children are in this list.
    # so they come from before/between/after the children ranges.
    strings: List[TaggedString] = field(init=False, default_factory=list)

    @property
    def predecessors(self) -> Optional["Layout"]:
        """ traverse to the prior siblings` """
        if self.parent is None:
            return None

        index = self.parent.children.index(self)
        if index == 0:
            return None

        for i in range(index - 1, -1, -1):
            yield self.parent.children[i]

    @property
    def predecessor(self) -> Optional["Layout"]:
        """ traverse to the prior sibling """
        return next(self.predecessors, None)

    @property
    def successors(self) -> Optional["Layout"]:
        """ traverse to the next siblings """
        if self.parent is None:
            return None

        index = self.parent.children.index(self)
        if index == len(self.parent.children) - 1:
            return None

        for i in range(index + 1, len(self.parent.children)):
            yield self.parent.children[i]

    @property
    def successor(self) -> Optional["Layout"]:
        """ traverse to the next sibling """
        return next(self.successors, None)

    def add_child(self, child: "Layout"):
        bisect.insort(self.children, child, key=lambda c: c.slice.range.offset)
        child.parent = self

    @property
    def offset(self) -> int:
        return self.slice.range.offset

    @property
    def end(self) -> int:
        return self.slice.range.end

    def tag_strings(self, taggers: Sequence[Tagger]):
        """ 
        tag the strings in this layout and its children, recursively.
        this means that the .strings field will contain TaggedStrings now
        (it used to contain ExtractedStrings). 

        this can be overridden, if a subclass has more ways of tagging strings,
        such as a PE file and code/reloc regions.
        """
        tagged_strings = []
        for string in self.strings:
            tags = set()

            for tagger in taggers:
                tags.update(tagger(string))

            tagged_strings.append(TaggedString(string, tags))
        self.strings = tagged_strings

        for child in self.children:
            child.tag_strings(taggers)


@dataclass
class PELayout(Layout):
    # file offsets of bytes that are part of the relocation table
    reloc_offsets: Set[int]

    # file offsets of bytes that are recognized as code
    code_offsets: Set[int]

    def tag_strings(self, taggers: Sequence[Tagger]):

        def check_is_reloc_tagger(s: ExtractedString) -> Sequence[Tag]:
            return check_is_reloc(self.reloc_offsets, s)

        def check_is_code_tagger(s: ExtractedString) -> Sequence[Tag]:
            return check_is_code(self.code_offsets, s)

        taggers = tuple(taggers) + (
            check_is_reloc_tagger,
            check_is_code_tagger,
        )

        super().tag_strings(taggers)


@dataclass
class SectionLayout(Layout):
    section: pefile.SectionStructure


@dataclass
class SegmentLayout(Layout):
    """ region not covered by any section """
    pass


@dataclass
class ResourceLayout(Layout):
    pass


@dataclass
class Structure:
    slice: Slice
    name: str


def compute_file_structures(slice: Slice, pe: pefile.PE) -> Sequence[Structure]:
    structures = []

    for section in sorted(pe.sections, key=lambda s: s.PointerToRawData):
        offset = section.get_file_offset()
        size = section.sizeof()

        structures.append(Structure(
            slice=slice.slice(offset, size), 
            name="section header",
        ))

    if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
        for dll in pe.DIRECTORY_ENTRY_IMPORT:
            try:
                dll_name = dll.dll.decode("ascii")
            except UnicodeDecodeError:
                continue

            rva = dll.struct.Name
            size = len(dll_name)
            offset = pe.get_offset_from_rva(rva)

            structures.append(Structure(
                slice=slice.slice(offset, size),
                name="import table",
            ))

            for entry in dll.imports:
                if entry.name is None:
                    continue

                if entry.name_offset is None:
                    continue

                try:
                    symbol_name = entry.name.decode("ascii")
                except UnicodeDecodeError:
                    continue

                offset = entry.name_offset
                size = len(symbol_name)

                structures.append(Structure(
                    slice=slice.slice(offset, size),
                    name="import table",
                ))

    # TODO: other structures

    return structures


def compute_pe_layout(slice: Slice) -> Layout:
    data = slice.data

    try:
        pe = pefile.PE(data=data)
    except pefile.PEFormatError as e:
        raise ValueError("pefile failed to load workspace") from e

    structures = compute_file_structures(slice, pe)
    reloc_offsets = get_reloc_offsets(slice, pe)

    structures_by_range = intervaltree.IntervalTree()
    for interval in structures:
        structures_by_range.addi(interval.slice.range.offset, interval.slice.range.end, interval)

    # lancelot only accepts bytes, not mmap
    with timing("lancelot: load workspace"):
        try:
            ws = lancelot.from_bytes(data)
        except ValueError as e:
            raise ValueError("lancelot failed to load workspace") from e

    # contains the file offsets of bytes that are part of recognized instructions.
    code_offsets = set()
    with timing("lancelot: find code"):
        base_address = ws.base_address
        for function in ws.get_functions():
            cfg = ws.build_cfg(function)
            for bb in cfg.basic_blocks.values():
                va = bb.address
                rva = va - base_address
                offset = pe.get_offset_from_rva(rva)
                size = bb.length

                for fo in slice.range.slice(offset, size):
                    code_offsets.add(fo)

    layout = PELayout(
        slice=slice,
        name="pe",
        reloc_offsets=reloc_offsets,
        code_offsets=code_offsets,
    )

    for section in pe.sections:
        if section.SizeOfRawData == 0:
            continue

        try:
            name = section.Name.partition(b"\x00")[0].decode("utf-8")
        except UnicodeDecodeError:
            name = "(invalid)"

        offset = section.get_PointerToRawData_adj()
        size = section.SizeOfRawData
        layout.add_child(SectionLayout(
            slice=slice.slice(offset, size),
            name=name,
            section=section
        ))

    # segment that contains all data until the first section
    offset = 0
    size = layout.children[0].offset - slice.range.offset
    layout.add_child(SegmentLayout(
        slice=slice.slice(offset, size),
        name="header",
    ))

    # segment that contains all data after the last section
    # aka. "overlay"
    last_section: Layout = layout.children[-1]
    if last_section.end < layout.end:
        offset = last_section.end
        size = layout.end - last_section.end
        layout.add_child(SegmentLayout(
            slice=slice.slice(offset, size),
            name="overlay",
        ))

    # add segments for any gaps between sections.
    # note that we append new items to the end of the list and then resort,
    # to avoid mutating the list while we're iterating over it.
    for i in range(1, len(layout.children)):
        prior: Layout = layout.children[i - 1]
        current: Layout = layout.children[i]

        if prior.end != current.offset:
            offset = prior.end
            size = current.offset - prior.end
            layout.add_child(SegmentLayout(
                slice=slice.slice(offset, size),
                name="gap",
            ))

    if hasattr(pe, "DIRECTORY_ENTRY_RESOURCE"):

        def collect_pe_resources(dir_data: pefile.ResourceDirData, path: Sequence[str] = ()) -> Sequence[Layout]:
            resources = []
            for entry in dir_data.entries:
                if entry.name:
                    name = str(entry.name)
                else:
                    name = str(entry.id)

                epath = path + (name,)

                if hasattr(entry, "directory"):
                    resources.extend(collect_pe_resources(entry.directory, epath))

                else:
                    rva = entry.data.struct.OffsetToData
                    offset = pe.get_offset_from_rva(rva)
                    size = entry.data.struct.Size

                    logger.debug("resource: %s, size: 0x%x", "/".join(epath), size)

                    resources.append(ResourceLayout(
                        slice=slice.slice(offset, size),
                        name="rsrc: " + "/".join(epath),
                    ))

            return resources

        resources = collect_pe_resources(pe.DIRECTORY_ENTRY_RESOURCE)

        for resource in resources:
            # parse content of resources, such as embedded PE files
            resource.add_child(compute_layout(resource.slice))

        for resource in resources:
            # place resources into their parent section, usually .rsrc
            container = next(filter(lambda l: l.offset <= resource.offset < l.end, layout.children))
            container.add_child(resource)

    return layout


def compute_layout(slice: Slice) -> Layout:
    data = slice.data
    if data.startswith(b"MZ"):
        return compute_pe_layout(slice)

    else:
        return SegmentLayout(
            slice=slice,
            name="binary",
        )


def extract_layout_strings(layout: Layout):
    if not layout.children:
        # all the strings are found in this slice directly.
        layout.strings = extract_strings(layout.slice)
        return

    else:
        # we have children, so we need to recurse to find their strings,
        # and also find strings in the gaps between children.
        # lets find the gap strings first:
        for i, child in enumerate(layout.children):
            if i == 0:
                # find the strings before the first child
                offset = 0
                size = layout.children[0].offset - layout.offset

            else:
                # find strings between children
                prior = layout.children[i - 1]
                offset = prior.end - layout.offset
                size = child.offset - prior.end

            if size == 0:
                # there is no gap here.
                continue

            gap = layout.slice.slice(offset, size)
            layout.strings.extend(extract_strings(gap))

        # finally, find strings after the last child
        last_child = layout.children[-1]
        offset = last_child.end - layout.offset
        size = layout.end - last_child.end

        if size > 0:
            gap = layout.slice.slice(offset, size)
            layout.strings.extend(extract_strings(gap))

        # now recurse to find the strings in the children.
        for child in layout.children:
            extract_layout_strings(child)


def collect_strings(layout: Layout) -> List[TaggedString]:
    ret = []

    ret.extend(layout.strings)

    for child in layout.children:
        ret.extend(collect_strings(child))

    return ret


def remove_false_positive_lib_strings(layout: Layout):
    # list of references to all the tagged strings across the layout.
    # we can (carefully) manipulate the tags here.
    tagged_strings = collect_strings(layout)

    # open source libraries should have at least 5 strings,
    # or don't show their tag, since the couple hits are probably false positives.
    #
    # hack: assume the libname is embedded in the filename.
    # otherwise, we don't have an easy way to recover the library tag names.
    for filename in OSS_DATABASE_FILENAMES:
        libname = filename.partition(".")[0]
        tagname = f"#{libname}"

        count = 0
        for string in tagged_strings:
            if tagname in string.tags:
                count += 1

        if 0 < count < 5:
            # I picked 5 as a reasonable threshold.
            # we could research what a better value is.
            #
            # also note that large binaries with many strings have
            # a higher chance of false positives, even with this threshold.
            # this is still a useful filter, though.
            for string in tagged_strings:
                if tagname in string.tags:
                    string.tags.remove(tagname)


def hide_strings_by_rules(layout: Layout, tag_rules: TagRules):
    layout.strings = list(filter(lambda s: not should_hide_string(s, tag_rules), layout.strings))

    for child in layout.children:
        hide_strings_by_rules(child, tag_rules)


def has_visible_children(layout: Layout) -> bool:
    return any(map(is_visible, layout.children))


def is_visible(layout: Layout) -> bool:
    "a layout is visible if it has any strings (or its children do)"
    return bool(layout.strings) or has_visible_children(layout)


def has_visible_predecessors(layout: Layout) -> bool:
    return any(map(is_visible, layout.predecessors))


def has_visible_successors(layout: Layout) -> bool:
    return any(map(is_visible, layout.successors))


def render_strings(console: Console, layout: Layout, tag_rules: TagRules, depth: int = 0, name_hint: Optional[str] = None):
    if not is_visible(layout):
        return

    if len(layout.children) == 1 and layout.slice.range == layout.children[0].slice.range:
        # when a layout is completely dominated by its single child
        # then we can directly render the child,
        # retaining just a hint of the parent's name.
        #
        # for example: 
        #
        #     rsrc: BINARY/102/0 (pe)
        return render_strings(console, layout.children[0], tag_rules, depth, name_hint=layout.name)

    BORDER_STYLE = Style(color="grey50")

    name = layout.name
    if name_hint:
        name = f"{name_hint} ({name})"

    header = Span(name, style=BORDER_STYLE)
    header.pad(1)
    header.align("center", width=console.width, character="━")

    # box is muted color
    # name of section is blue
    name_offset = header.plain.index(" ") + 1
    header.stylize(Style(color="blue"), name_offset, name_offset + len(name))

    if not has_visible_predecessors(layout):
        header_shape = "┓"
    else:
        header_shape = "┫"

    header.remove_suffix("━" * (depth + 1))
    header.append_text(Span(header_shape, style=BORDER_STYLE))
    header.append_text(Span("┃" * depth, style=BORDER_STYLE))

    console.print(header)

    def render_string_line(console: Console, tag_rules: TagRules, string: TaggedString, depth: int):
        line = render_string(console.width, string, tag_rules)
        # TODO: this truncates the structure column
        line = line[:-depth - 1]
        line.append_text(Span("┃" * (depth + 1), style=BORDER_STYLE))
        console.print(line)

    if not layout.children:
        # for string in layout.strings[:4]:
        for string in layout.strings:
            render_string_line(console, tag_rules, string, depth)

    else:
        for i, child in enumerate(layout.children):
            if i == 0:
                # render strings before first child
                strings_before_child = list(filter(lambda s: layout.offset <= s.offset < child.offset, layout.strings))
            else:
                # render strings between children
                last_child = layout.children[i - 1]
                strings_before_child = list(filter(lambda s: last_child.end < s.offset < child.offset, layout.strings))

            # for string in strings_before_child[:4]:
            for string in strings_before_child:
                render_string_line(console, tag_rules, string, depth)

            render_strings(console, child, tag_rules, depth + 1)

        # render strings after last child
        strings_after_children = list(filter(lambda s: child.end < s.offset < layout.end, layout.strings))
        # for string in strings_after_children[:4]:
        for string in strings_after_children:
            render_string_line(console, tag_rules, string, depth)

    if not has_visible_successors(layout):
        footer = Span("", style=BORDER_STYLE)
        footer.align("center", width=console.width, character="━")

        footer.remove_suffix("━" * (depth + 1))
        footer.append_text(Span("┛", style=BORDER_STYLE))
        footer.append_text(Span("┃" * depth, style=BORDER_STYLE))

        console.print(footer)


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

    floss.main.set_log_config(args.debug, args.quiet)
    rich.traceback.install()
    if isinstance(sys.stdout, io.TextIOWrapper) or hasattr(sys.stdout, "reconfigure"):
        # from sys.stdout type hint:
        #
        # TextIO is used instead of more specific types for the standard streams,
        # since they are often monkeypatched at runtime. At startup, the objects
        # are initialized to instances of TextIOWrapper.
        #
        # To use methods from TextIOWrapper, use an isinstance check to ensure that
        # the streams have not been overridden:
        #
        # if isinstance(sys.stdout, io.TextIOWrapper):
        #    sys.stdout.reconfigure(...)
        sys.stdout.reconfigure(encoding="utf-8")
    colorama.just_fix_windows_console()

    path = pathlib.Path(args.path)
    if not path.exists():
        logging.error("%s does not exist", path)
        return 1

    with path.open("rb") as f:
        # because we store all the strings in memory
        # in order to tag and reason about them
        # then our input file must be reasonably sized
        # so we just load it directly into memory.
        # no need to mmap or play any games.
        buf = f.read()

    slice = Slice.from_bytes(buf)

    # build the layout tree that describes the structures and ranges of the file.
    layout = compute_pe_layout(slice)

    # recursively populate the `.strings: List[ExtractedString]` field of each layout node. 
    extract_layout_strings(layout)

    # recursively apply tags to the strings in the layout tree.
    # the `.strings` field now contains TaggedStrings (not ExtractedStrings).
    taggers = load_databases()
    layout.tag_strings(taggers)

    # TODO: figure out how to mark structures

    # remove tags from libraries that have too few matches (five, by default).
    remove_false_positive_lib_strings(layout)

    tag_rules: TagRules = {
        "#capa": "highlight",
        "#common": "mute",
        "#code": "hide",
        "#reloc": "hide",
        # lib strings are muted (default)
    }
    # hide (remove) strings according to the above rules
    hide_strings_by_rules(layout, tag_rules)

    console = Console()
    render_strings(console, layout, tag_rules)

    return 0

if __name__ == "__main__":
    sys.exit(main())
