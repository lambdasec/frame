"""
Inline suppressions and project configuration for the security scanner.

Two mechanisms let a team adopt the scanner without drowning in findings it
has already triaged:

1. Inline comments. A finding is dropped when its line, or the comment-only
   line directly above it, carries a ``frame: ignore`` marker::

       cursor.execute(query)  # frame: ignore[CWE-89] reviewed, query is static
       // frame: ignore
       eval(userInput);

   ``frame: ignore`` alone suppresses every finding on that line;
   ``frame: ignore[CWE-89, 79]`` suppresses only the listed CWEs (the ``CWE-``
   prefix is optional) or finding types (e.g. ``sql_injection``).

2. A project config file, ``.frame.toml`` or a ``[tool.frame]`` table in
   ``pyproject.toml``, discovered by walking up from the scan target::

       min_severity = "medium"
       fail_on = "high"
       disable = ["CWE-798", "weak_hash"]
       exclude = ["vendor", "third_party"]

   Command-line flags always take precedence over the config file.
"""

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, List, Optional, Set, Tuple

try:  # Python 3.11+
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - exercised on 3.10 only
    import tomli as tomllib  # type: ignore[no-redef]

_MARKER = re.compile(r"frame:\s*ignore(?:\[([^\]]*)\])?", re.IGNORECASE)
_COMMENT_START = ("#", "//", "/*", "*", "--")
_SEVERITIES = ("critical", "high", "medium", "low", "info")
_FAIL_ON = _SEVERITIES[:4] + ("any", "none")
CONFIG_FILENAMES = (".frame.toml", "pyproject.toml")


def _normalize_rule(token: str) -> str:
    """Canonical form of a rule token: lowercase, bare numbers become CWE ids."""
    t = token.strip().lower()
    if t.isdigit():
        return f"cwe-{t}"
    if t.startswith("cwe") and t[3:].lstrip("-_ ").isdigit():
        return f"cwe-{t[3:].lstrip('-_ ')}"
    return t


def _parse_rules(raw: Optional[str]) -> Optional[Set[str]]:
    """``None`` means "all rules"; otherwise the set of normalized rule tokens."""
    if raw is None or not raw.strip():
        return None
    return {_normalize_rule(p) for p in raw.split(",") if p.strip()}


def _line_marker(line: str) -> Tuple[bool, Optional[Set[str]]]:
    m = _MARKER.search(line)
    if not m:
        return False, None
    return True, _parse_rules(m.group(1))


def _rules_of(vuln) -> Set[str]:
    rules = set()
    cwe = getattr(vuln, "cwe_id", None)
    if cwe:
        rules.add(_normalize_rule(str(cwe)))
    vtype = getattr(vuln, "type", None)
    if vtype is not None:
        rules.add(_normalize_rule(str(getattr(vtype, "value", vtype))))
    return rules


def matches_rules(vuln, rules: Optional[Iterable[str]]) -> bool:
    """Does ``vuln`` match any rule token (CWE id or finding type)?"""
    if rules is None:
        return True
    wanted = {_normalize_rule(r) for r in rules}
    return bool(_rules_of(vuln) & wanted)


def split_suppressed(vulns: List, source_code: str) -> Tuple[List, List]:
    """Partition ``vulns`` into ``(kept, suppressed)`` using inline markers."""
    if not vulns or "frame" not in source_code.lower():
        return list(vulns), []
    lines = source_code.splitlines()

    def rules_for(lineno: int) -> List[Optional[Set[str]]]:
        found: List[Optional[Set[str]]] = []
        if 1 <= lineno <= len(lines):
            ok, rules = _line_marker(lines[lineno - 1])
            if ok:
                found.append(rules)
        if 2 <= lineno <= len(lines) + 1:
            above = lines[lineno - 2]
            if above.lstrip().startswith(_COMMENT_START):
                ok, rules = _line_marker(above)
                if ok:
                    found.append(rules)
        return found

    kept, suppressed = [], []
    for v in vulns:
        line = getattr(v, "line", 0) or 0
        hit = False
        for rules in rules_for(line):
            if rules is None or (_rules_of(v) & rules):
                hit = True
                break
        (suppressed if hit else kept).append(v)
    return kept, suppressed


@dataclass
class ScanConfig:
    """Project-level scan settings loaded from ``.frame.toml``/``pyproject.toml``."""
    min_severity: Optional[str] = None
    fail_on: Optional[str] = None
    disable: List[str] = field(default_factory=list)
    exclude: List[str] = field(default_factory=list)
    source: Optional[str] = None


class ConfigError(ValueError):
    """Raised for a malformed config file."""


def _from_table(table: dict, source: str) -> ScanConfig:
    known = {"min_severity", "fail_on", "disable", "exclude"}
    unknown = set(table) - known
    if unknown:
        raise ConfigError(
            f"{source}: unknown key(s) {sorted(unknown)}; expected {sorted(known)}")
    cfg = ScanConfig(source=source)
    sev = table.get("min_severity")
    if sev is not None:
        if str(sev).lower() not in _SEVERITIES:
            raise ConfigError(f"{source}: min_severity must be one of {_SEVERITIES}")
        cfg.min_severity = str(sev).lower()
    fail = table.get("fail_on")
    if fail is not None:
        if str(fail).lower() not in _FAIL_ON:
            raise ConfigError(f"{source}: fail_on must be one of {_FAIL_ON}")
        cfg.fail_on = str(fail).lower()
    for key in ("disable", "exclude"):
        val = table.get(key, [])
        if not isinstance(val, list) or not all(isinstance(x, str) for x in val):
            raise ConfigError(f"{source}: {key} must be a list of strings")
        setattr(cfg, key, list(val))
    return cfg


def load_config_file(path: Path) -> Optional[ScanConfig]:
    """Load one config file; ``None`` if a pyproject has no ``[tool.frame]``."""
    try:
        data = tomllib.loads(Path(path).read_text(encoding="utf-8"))
    except tomllib.TOMLDecodeError as e:
        raise ConfigError(f"{path}: invalid TOML: {e}") from e
    if Path(path).name == "pyproject.toml":
        table = data.get("tool", {}).get("frame")
        if table is None:
            return None
    else:
        table = data
    return _from_table(table, str(path))


def find_config(start: Path) -> Optional[ScanConfig]:
    """Walk up from ``start`` to the nearest directory with a usable config."""
    start = Path(start).resolve()
    directory = start if start.is_dir() else start.parent
    for d in (directory, *directory.parents):
        for name in CONFIG_FILENAMES:
            candidate = d / name
            if candidate.is_file():
                cfg = load_config_file(candidate)
                if cfg is not None:
                    return cfg
    return None
