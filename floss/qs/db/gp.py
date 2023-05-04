import gzip
import pathlib
from typing import Dict, Literal, Mapping, Sequence, Set, Tuple
from collections import defaultdict
from dataclasses import dataclass

import msgspec


Encoding = Literal["ascii"] | Literal["utf-16"]
# header | gap | overlay
# or section name
Location = Literal["header"] | Literal["gap"] | Literal["overlay"] | str


class StringGlobalPrevalence(msgspec.Struct):
    string: str
    encoding: Encoding
    global_count: int
    location: Location | None


@dataclass
class StringGlobalPrevalenceDatabase:
    metadata_by_string: Mapping[Tuple[str, Encoding], Sequence[StringGlobalPrevalence]]

    def __len__(self) -> int:
        return len(self.metadata_by_string)

    @classmethod
    def from_file(cls, path: pathlib.Path) -> "StringGlobalPrevalenceDatabase":
        metadata_by_string: Mapping[str, Set[StringGlobalPrevalence]] = defaultdict(list)

        decoder = msgspec.json.Decoder(type=StringGlobalPrevalence)
        for line in gzip.decompress(path.read_bytes()).split(b"\n"):
            if not line:
                continue
            s = decoder.decode(line)

            metadata_by_string[(s.string, s.encoding)].append(s)

        return cls(
            metadata_by_string=metadata_by_string,
        )
