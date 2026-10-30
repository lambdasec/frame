"""Hardcoded credentials by name, as data (`specs/data/secret-names.toml`): the target names that say a
literal is a credential, and the value shapes that say it holds none. Loaded strictly: an unknown
key, a missing one, or a pattern that does not compile is an error naming the entry. The rules
that use them are `FrameScanner._hardcoded_secret_checks`."""

from __future__ import annotations

import re
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import FrozenSet, List, Pattern, Tuple

try:                                        # Python 3.11+
    import tomllib
except ModuleNotFoundError:                 # pragma: no cover - 3.10
    import tomli as tomllib                 # type: ignore[no-redef]

PATH = Path(__file__).parent / "specs" / "data" / "secret-names.toml"
_WORDS = ("name_descriptors", "leading_descriptors", "metadata_heads", "http_auth_names", "password_words",
          "structural_words")
_VALUE = {"connection_string", "placeholders", "pem_with_body", "known_credential", "credential_prefixes",
          "not_secret"}


@dataclass(frozen=True)
class SecretNames:
    name_rules: List[Tuple[Pattern, str, str]]       # (target-name pattern, CWE, label), first match wins
    connection_string: Pattern
    placeholders: FrozenSet[str]
    pem_with_body: Pattern
    known_credential: Pattern
    credential_prefix: Pattern
    not_secret: List[Pattern]
    name_descriptors: FrozenSet[str]
    leading_descriptors: FrozenSet[str]
    metadata_heads: FrozenSet[str]
    http_auth_names: FrozenSet[str]
    password_words: FrozenSet[str]
    structural_words: FrozenSet[str]


def name_words(name: str) -> List[str]:
    """An identifier's words, lower case: camelCase and separators split
    ('SSHAuthPrivateKey' -> ['ssh', 'auth', 'private', 'key'], 'new_session_token' -> [..., 'token'])."""
    t = re.sub(r'([A-Z]+)([A-Z][a-z])', r'\1_\2', name)
    t = re.sub(r'([a-z0-9])([A-Z])', r'\1_\2', t)
    return [x for x in re.split(r'[^A-Za-z0-9]+', t.lower()) if x]


def _compile(pattern, where: str, flags: int = 0) -> Pattern:
    if not isinstance(pattern, str):
        raise ValueError(f"{where}: pattern must be a string")
    try:
        return re.compile(pattern, flags)
    except re.error as e:
        raise ValueError(f"{where}: pattern does not compile: {e}") from e


def _entries(items, where: str, keys) -> List[dict]:
    for i, e in enumerate(items):
        if not isinstance(e, dict) or set(e) != set(keys):
            raise ValueError(f"{where} {i + 1}: needs exactly {sorted(keys)}")
    return list(items)


@lru_cache(maxsize=None)
def load(path: Path = PATH) -> SecretNames:
    name = Path(path).name
    data = tomllib.loads(Path(path).read_text(encoding="utf-8"))
    if set(data) != {"name_rule", "value", "words"}:
        raise ValueError(f"{name}: needs exactly name_rule, value and words; has {sorted(data)}")
    value, words = data["value"], data["words"]
    if set(value) != _VALUE:
        raise ValueError(f"{name}: [value] needs exactly {sorted(_VALUE)}; has {sorted(value)}")
    if set(words) != set(_WORDS) or not all(isinstance(w, list) and all(isinstance(x, str) for x in w)
                                            for w in words.values()):
        raise ValueError(f"{name}: [words] needs exactly {list(_WORDS)}, each a list of strings")
    rules = [(_compile(r["pattern"], f"{name}: name_rule {i + 1}"), r["cwe"], r["label"])
             for i, r in enumerate(_entries(data["name_rule"], f"{name}: name_rule", ("pattern", "cwe", "label")))]
    if not rules or any(not cwe.startswith("CWE-") for _, cwe, _ in rules):
        raise ValueError(f"{name}: name rules need a CWE-<n> each")
    known = _entries(value["known_credential"], f"{name}: known_credential", ("pattern", "description"))
    for i, k in enumerate(known):
        _compile(k["pattern"], f"{name}: known_credential {i + 1}")
    prefixes = value["credential_prefixes"]
    if set(prefixes) != {"patterns"} or not prefixes["patterns"]:
        raise ValueError(f"{name}: [value.credential_prefixes] needs patterns")
    shapes = _entries(value["not_secret"], f"{name}: not_secret", ("pattern", "description"))
    return SecretNames(
        name_rules=rules,
        connection_string=_compile(value["connection_string"], f"{name}: connection_string"),
        placeholders=frozenset(value["placeholders"]),
        pem_with_body=_compile(value["pem_with_body"], f"{name}: pem_with_body", re.DOTALL),
        known_credential=_compile("|".join(k["pattern"] for k in known), f"{name}: known_credential"),
        credential_prefix=_compile(r"\b(?:" + "|".join(prefixes["patterns"]) + ")", f"{name}: credential_prefixes"),
        not_secret=[_compile(s["pattern"], f"{name}: not_secret {i + 1}") for i, s in enumerate(shapes)],
        **{w: frozenset(words[w]) for w in _WORDS})


__all__ = ["PATH", "SecretNames", "load", "name_words"]
