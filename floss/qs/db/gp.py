import gzip
import pathlib
import datetime
from typing import List, Literal, Mapping
from collections import defaultdict
from dataclasses import dataclass

import msgspec

Encoding = Literal["ascii"] | Literal["utf-16"] | Literal["unknown"]
# header | gap | overlay
# or section name
Location = Literal["header"] | Literal["gap"] | Literal["overlay"] | str


class Metadata(msgspec.Struct):
    type: str | None = "metadata"
    version: str | None = "1.0"
    timestamp: str | None = datetime.datetime.now().isoformat()
    note: str | None = ""  # manual notes to explain the data source(s)


class StringGlobalPrevalence(msgspec.Struct):
    string: str
    encoding: Encoding
    global_count: int
    location: Location | None


@dataclass
class StringGlobalPrevalenceDatabase:
    meta: Metadata
    metadata_by_string: Mapping[str, List[StringGlobalPrevalence]]

    def __len__(self) -> int:
        return len(self.metadata_by_string)

    def insert(self, str_gp: StringGlobalPrevalence):
        # TODO combine if existing data?
        self.metadata_by_string[str_gp.string].append(str_gp)

    def query(self, string):
        return self.metadata_by_string.get(string, [])

    @classmethod
    def new_db(cls, note: str = None):
        return cls(meta=Metadata(note=note), metadata_by_string=defaultdict(list))

    @classmethod
    def from_file(cls, path: pathlib.Path, compress: bool = True) -> "StringGlobalPrevalenceDatabase":
        metadata_by_string: Mapping[str, List[StringGlobalPrevalence]] = defaultdict(list)

        if compress:
            lines = gzip.decompress(path.read_bytes()).split(b"\n")
        else:
            lines = path.read_bytes().split(b"\n")

        decoder = msgspec.json.Decoder(type=StringGlobalPrevalence)
        for line in lines[1:]:
            if not line:
                continue
            s = decoder.decode(line)

            metadata_by_string[s.string].append(s)

        return cls(
            meta=msgspec.json.Decoder(type=Metadata).decode(lines[0]),
            metadata_by_string=metadata_by_string,
        )

    def to_file(self, outfile: str, compress: bool = True):
        if compress:
            with gzip.open(outfile, "w") as f:
                f.write(msgspec.json.encode(self.meta) + b"\n")
                for k, v in sorted(self.metadata_by_string.items(), key=lambda x: x[1][0].global_count, reverse=True):
                    # TODO needs fixing to write most common to least common
                    for e in v:
                        f.write(msgspec.json.encode(e) + b"\n")
        else:
            with open(outfile, "w", encoding="utf-8") as f:
                f.write(msgspec.json.encode(self.meta).decode("utf-8") + "\n")
                for k, v in sorted(self.metadata_by_string.items(), key=lambda x: x[1][0].global_count, reverse=True):
                    for e in v:
                        f.write(msgspec.json.encode(e).decode("utf-8") + "\n")
