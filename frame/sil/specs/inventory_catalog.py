"""What `frame inventory` names beyond what it reads elsewhere (`data/inventory.toml`): dependency
declarations `frame deps` does not read on their own, and the LLM / MCP SDK import prefixes.
Loaded strictly."""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Dict, NamedTuple, Tuple

try:                                        # Python 3.11+
    import tomllib
except ModuleNotFoundError:                 # pragma: no cover - 3.10
    import tomli as tomllib                 # type: ignore[no-redef]

PATH = Path(__file__).parent / "data" / "inventory.toml"
_KINDS = ("manifest", "lockfile")


class InventoryCatalog(NamedTuple):
    unread_files: Dict[str, Tuple[str, str]]    # file name -> (ecosystem, kind)
    llm_sdks: Tuple[str, ...]
    mcp_server_sdks: Tuple[str, ...]


@lru_cache(maxsize=None)
def load(path: Path = PATH) -> InventoryCatalog:
    name = Path(path).name
    data = tomllib.loads(Path(path).read_text(encoding="utf-8"))
    if set(data) != {"dependency_file", "ai"}:
        raise ValueError(f"{name}: needs exactly [[dependency_file]] and [ai]")
    files: Dict[str, Tuple[str, str]] = {}
    for i, e in enumerate(data["dependency_file"]):
        if not isinstance(e, dict) or set(e) != {"name", "ecosystem", "kind"} or e.get("kind") not in _KINDS \
                or not all(isinstance(e[k], str) and e[k] for k in e) or e["name"] in files:
            raise ValueError(f"{name}: dependency_file {i + 1} needs name, ecosystem and kind "
                             f"({' or '.join(_KINDS)}), each name once")
        files[e["name"]] = (e["ecosystem"], e["kind"])
    ai = data["ai"]
    if not isinstance(ai, dict) or set(ai) != {"llm_sdks", "mcp_server_sdks"} \
            or not all(isinstance(v, list) and v and all(isinstance(x, str) and x for x in v) for v in ai.values()):
        raise ValueError(f"{name}: [ai] needs exactly llm_sdks and mcp_server_sdks, non-empty lists")
    return InventoryCatalog(files, tuple(ai["llm_sdks"]), tuple(ai["mcp_server_sdks"]))


__all__ = ["PATH", "InventoryCatalog", "load"]
