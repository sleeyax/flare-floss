import gzip
import pathlib
from typing import Dict

import msgspec


class OpenSourceString(msgspec.Struct):
    string: str
    library_name: str
    library_version: str
    file_path: str
    function_name: str
    line_number: int | None = None


class OpenSourceStringDatabase:
    metadata_by_string: Dict[str, OpenSourceString]

    @classmethod
    def from_file(cls, path: pathlib.Path) -> "OpenSourceStringDatabase":
        metadata_by_string: Dict[str, OpenSourceString] = {}
        decoder = msgspec.json.Decoder(type=OpenSourceString)
        for line in gzip.decompress(path.read_bytes()).split(b"\n"):
            s = decoder.decode(line)
            metadata_by_string[s.string] = s

        return cls(metadata_by_string=metadata_by_string)