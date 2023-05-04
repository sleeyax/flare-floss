import gzip
import pathlib
from typing import Dict
from dataclasses import dataclass

import msgspec


class OpenSourceString(msgspec.Struct):
    string: str
    library_name: str
    library_version: str
    file_path: str
    function_name: str
    line_number: int | None = None


@dataclass
class OpenSourceStringDatabase:
    metadata_by_string: Dict[str, OpenSourceString]

    def __len__(self) -> int:
        return len(self.metadata_by_string)

    @classmethod
    def from_file(cls, path: pathlib.Path) -> "OpenSourceStringDatabase":
        metadata_by_string: Dict[str, OpenSourceString] = {}
        decoder = msgspec.json.Decoder(type=OpenSourceString)
        for line in gzip.decompress(path.read_bytes()).split(b"\n"):
            if not line:
                continue
            s = decoder.decode(line)
            metadata_by_string[s.string] = s

        return cls(metadata_by_string=metadata_by_string)