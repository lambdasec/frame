"""Which JavaScript files are third-party libraries or generated bundles (`data/third-party-js.toml`),
compiled to the frontend's tests. Loaded strictly."""

from __future__ import annotations

import re
from functools import lru_cache
from pathlib import Path
from typing import NamedTuple, Pattern, Tuple

try:                                        # Python 3.11+
    import tomllib
except ModuleNotFoundError:                 # pragma: no cover - 3.10
    import tomli as tomllib                 # type: ignore[no-redef]

PATH = Path(__file__).parent / "data" / "third-party-js.toml"
_KEYS = {"directories", "minified_markers", "minified_suffixes", "minified_line_length", "library_names",
         "versioned_library_names", "version_in_name"}


class ThirdPartyJS(NamedTuple):
    directory: Pattern
    minified_markers: Tuple[str, ...]
    minified_suffixes: Tuple[str, ...]
    minified_line_length: int
    library_name: Pattern
    version_in_name: bool

    def is_third_party(self, filename: str, source: str) -> bool:
        fn = (filename or "").replace("\\", "/")
        low = fn.lower()
        if any(m in low for m in self.minified_markers) or low.endswith(self.minified_suffixes):
            return True
        if self.directory.search("/" + fn.strip("/") + "/"):
            return True
        base = fn.rsplit("/", 1)[-1]
        if (self.version_in_name and re.search(r"[-_.]\d+\.\d+", base)) or self.library_name.search(base):
            return True
        return any(len(line) > self.minified_line_length for line in (source or "").splitlines())


def _strings(name, key, value):
    if not isinstance(value, list) or not value or not all(isinstance(v, str) and v for v in value):
        raise ValueError(f"{name}: {key} must be a non-empty list of strings")
    return tuple(value)


@lru_cache(maxsize=None)
def load(path: Path = PATH) -> ThirdPartyJS:
    name = Path(path).name
    data = tomllib.loads(Path(path).read_text(encoding="utf-8"))
    if set(data) != _KEYS:
        raise ValueError(f"{name}: needs exactly {sorted(_KEYS)}")
    if not isinstance(data["minified_line_length"], int) or not isinstance(data["version_in_name"], bool):
        raise ValueError(f"{name}: minified_line_length is a number, version_in_name true or false")
    dirs = "|".join(re.escape(d) for d in _strings(name, "directories", data["directories"]))
    libs = "|".join(re.escape(n) for n in _strings(name, "library_names", data["library_names"]))
    versioned = "|".join(re.escape(n) + r"(?=[-_.]?\d|\.js$|\.min\b|$)"
                         for n in _strings(name, "versioned_library_names", data["versioned_library_names"]))
    return ThirdPartyJS(
        directory=re.compile(rf"/(?:{dirs})/", re.I),
        minified_markers=_strings(name, "minified_markers", data["minified_markers"]),
        minified_suffixes=_strings(name, "minified_suffixes", data["minified_suffixes"]),
        minified_line_length=data["minified_line_length"],
        library_name=re.compile(rf"(?:^|[-_.])(?:{libs}|{versioned})(?:[-_.]|\d|$)", re.I),
        version_in_name=data["version_in_name"])


__all__ = ["PATH", "ThirdPartyJS", "load"]
