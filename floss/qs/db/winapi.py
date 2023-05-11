import pathlib
import gzip
from typing import Set
from dataclasses import dataclass


@dataclass
class WindowsApiStringDatabase:
    dll_names: Set[str]
    api_names: Set[str]

    def __len__(self) -> int:
        return len(self.dll_names) + len(self.api_names)

    @classmethod
    def from_dir(cls, path: pathlib.Path) -> "WindowsApiStringDatabase":
        dll_names: Set[str] = set()
        api_names: Set[str] = set()

        for line in gzip.decompress((path / "dlls.txt.gz").read_bytes()).decode("utf-8").splitlines():
            if not line:
                continue
            dll_names.add(line)

        for line in gzip.decompress((path / "apis.txt.gz").read_bytes()).decode("utf-8").splitlines():
            if not line:
                continue
            api_names.add(line)

        return cls(dll_names=dll_names, api_names=api_names)
