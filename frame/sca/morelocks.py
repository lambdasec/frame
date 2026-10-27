"""Readers for Ruby (Bundler), PHP (Composer), Dart (pub) and Elixir (Mix) dependencies --
read for dependencies only, as with Go, Rust and Swift: Frame does not scan their source.

    Gemfile.lock    GEM specs and their nested requirements (edges), DEPENDENCIES (direct);
                    platform suffixes (`-x86_64-linux`) are not part of the version
    Gemfile         dev / test groups (`group :development, :test do ... end`, `group: :test`)
    composer.lock   packages and packages-dev, `require` edges; platform packages (php, ext-*)
                    are not dependencies
    pubspec.lock    hosted packages with pub's own direct main / direct dev / transitive labels
    mix.lock        Hex packages and their requirements, read as Elixir terms (not evaluated)
    mix.exs         the deps list: `only: [:dev, :test]` is development only

A git, path or SDK dependency is not a registry package and is left out.
"""

from __future__ import annotations

import json
import re
from typing import Any, Dict, List, Optional, Tuple

from frame.sca.model import HEX, PACKAGIST, PUB, RUBYGEMS, DependencyFile, Package, normalize_name


def _error(path: str, e: Exception):
    from frame.sca.lockfiles import LockfileError
    return LockfileError(f"{path}: {e}")


# ---------------------------------------------------------------------------------------------
# Ruby

_GEM_SPEC = re.compile(r"^    ([^\s(]+) \(([^)]+)\)$")
_GEM_DEP = re.compile(r"^      ([^\s(]+)(?: \(([^)]+)\))?$")
_DIRECT = re.compile(r"^  ([^\s(!]+)(!)?(?: \(([^)]+)\))?$")


def parse_gemfile_lock(path: str, text: str) -> DependencyFile:
    df = DependencyFile(path, RUBYGEMS, "lockfile")
    section, cur = "", None
    keys: Dict[str, str] = {}
    pending: List[Tuple[str, str, str]] = []
    direct: Dict[str, bool] = {}
    path_deps: List[str] = []                                 # the project's own gemspec (PATH)
    git_deps: List[str] = []                                  # gems fetched from git
    for line in text.splitlines():
        if line and not line.startswith(" "):
            section, cur = line.strip(), None
            continue
        if section in ("PATH", "GIT"):
            d = _GEM_DEP.match(line)
            if d:
                (path_deps if section == "PATH" else git_deps).append(d.group(1))
            continue
        if section == "GEM":
            m = _GEM_SPEC.match(line)
            if m:
                version = m.group(2).split("-", 1)[0]        # `1.13.10-x86_64-linux`: the platform
                cur = df.add(Package(RUBYGEMS, m.group(1), version)).key
                keys[m.group(1)] = cur
                continue
            d = _GEM_DEP.match(line)
            if d and cur:
                pending.append((cur, d.group(1), d.group(2) or ""))
        elif section == "DEPENDENCIES":
            m = _DIRECT.match(line)
            if m and not m.group(2):                          # `name!`: a git / path gem
                direct[m.group(1)] = False
                if m.group(3):
                    df.require("", m.group(1), m.group(3))
    for parent, name, req in pending:
        if name in keys:
            df.edge(parent, keys[name])
            if req:
                df.require(parent, name, req)
    for name in path_deps:                                    # a gemspec's runtime dependencies
        direct.setdefault(name, False)
    if direct:
        df.mark_direct(direct)
    df.prod_roots.update(keys[n] for n in git_deps if n in keys)
    return df


def gemfile_groups(text: str) -> Dict[str, bool]:
    """Gem names of a Gemfile -> development only (every group it is in is a dev / test one).
    A line scanner for the Gemfile conventions: `group ... do` / `end` blocks and `group:` /
    `groups:` options."""
    out: Dict[str, bool] = {}
    stack: List[bool] = []                                    # per open block: a dev/test group?
    dev_groups = {"development", "test", "dev"}
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        g = re.match(r"^group\s+(.+?)\s+do\b", line)
        if g:
            names = set(re.findall(r":(\w+)", g.group(1)))
            stack.append(bool(names) and names <= dev_groups)
            continue
        if re.match(r"^(?:\w+.*\s)?do(\s*\|.*\|)?$", line) or re.match(r"^(if|unless|case|platforms?|source)\b.*\bdo\b", line):
            stack.append(any(stack))
            continue
        if line == "end":
            if stack:
                stack.pop()
            continue
        m = re.match(r"""^gem\s+["']([^"']+)["'](.*)$""", line)
        if m:
            opt = re.search(r"groups?:\s*(\[[^\]]*\]|:\w+)", m.group(2))
            dev = any(stack)
            if opt:
                names = set(re.findall(r":(\w+)", opt.group(1)))
                dev = bool(names) and names <= dev_groups
            out[m.group(1)] = out.get(m.group(1), True) and dev
    return out


def parse_gemfile(path: str, text: str) -> DependencyFile:
    df = DependencyFile(path, RUBYGEMS, "manifest")
    groups = gemfile_groups(text)
    for raw in text.splitlines():
        m = re.match(r"""^\s*gem\s+["']([^"']+)["']((?:\s*,\s*["'][^"']+["'])*)""", raw.split("#", 1)[0])
        if not m:
            continue
        reqs = re.findall(r"""["']([^"']+)["']""", m.group(2))
        exact = reqs[0] if len(reqs) == 1 and re.fullmatch(r"=?\s*\d[\w.]*", reqs[0]) else None
        df.add(Package(RUBYGEMS, m.group(1), exact.lstrip("= ") if exact else None, direct=True,
                       dev=groups.get(m.group(1), False), spec="" if exact else ", ".join(reqs)))
    return df


# ---------------------------------------------------------------------------------------------
# PHP

def _platform(name: str) -> bool:
    return "/" not in name                                    # php, ext-json, lib-icu, composer-plugin-api


def parse_composer_lock(path: str, text: str) -> DependencyFile:
    df = DependencyFile(path, PACKAGIST, "lockfile")
    try:
        data = json.loads(text)
    except ValueError as e:
        raise _error(path, e) from e
    keys: Dict[str, str] = {}
    for section, dev in (("packages", False), ("packages-dev", True)):
        for p in data.get(section) or []:
            if isinstance(p, dict) and p.get("name") and p.get("version"):
                from frame.sca.licenses import composer_license
                keys[p["name"].lower()] = df.add(Package(PACKAGIST, p["name"], str(p["version"]), dev=dev,
                                                         license=composer_license(p.get("license")))).key
    for section in ("packages", "packages-dev"):
        for p in data.get(section) or []:
            parent = keys.get(str(p.get("name", "")).lower())
            for dep, spec in (p.get("require") or {}).items():
                if _platform(dep) or dep.lower() not in keys:
                    continue
                df.edge(parent, keys[dep.lower()])
                df.require(parent, dep, spec)
    return df


def composer_json_direct(text: str) -> Dict[str, bool]:
    try:
        data = json.loads(text)
    except ValueError:
        return {}
    out: Dict[str, bool] = {}
    for section, dev in (("require", False), ("require-dev", True)):
        for name in data.get(section) or {}:
            if not _platform(name):
                out[name] = out.get(name, True) and dev
    return out


def parse_composer_json(path: str, text: str) -> DependencyFile:
    df = DependencyFile(path, PACKAGIST, "manifest")
    try:
        data = json.loads(text)
    except ValueError as e:
        raise _error(path, e) from e
    for section, dev in (("require", False), ("require-dev", True)):
        for name, spec in (data.get(section) or {}).items():
            if _platform(name):
                continue
            exact = spec if re.fullmatch(r"v?\d+(\.\d+){1,3}", str(spec)) else None
            df.add(Package(PACKAGIST, name, exact, direct=True, dev=dev, spec="" if exact else str(spec)))
            df.require("", name, str(spec))
    return df


# ---------------------------------------------------------------------------------------------
# Dart

def parse_pubspec_lock(path: str, text: str) -> DependencyFile:
    from frame.sca import _yaml
    df = DependencyFile(path, PUB, "lockfile")
    try:
        data = _yaml.loads(text)
    except _yaml.YamlError as e:
        raise _error(path, e) from e
    for name, meta in (data.get("packages") or {}).items():
        if not isinstance(meta, dict) or meta.get("source") != "hosted" or not meta.get("version"):
            continue                                          # git / path / sdk packages
        kind = str(meta.get("dependency", ""))
        direct = kind.startswith("direct")
        df.add(Package(PUB, name, str(meta["version"]).strip('"'), direct=direct, dev=kind == "direct dev"))
    return df


def parse_pubspec_yaml(path: str, text: str) -> DependencyFile:
    from frame.sca import _yaml
    df = DependencyFile(path, PUB, "manifest")
    try:
        data = _yaml.loads(text)
    except _yaml.YamlError as e:
        raise _error(path, e) from e
    for section, dev in (("dependencies", False), ("dev_dependencies", True)):
        for name, spec in (data.get(section) or {}).items():
            if isinstance(spec, dict):
                if "sdk" in spec or "path" in spec or "git" in spec:
                    continue
                spec = spec.get("version", "")
            spec = str(spec or "any")
            exact = spec if re.fullmatch(r"\d+\.\d+\.\d+[\w.+-]*", spec) else None
            df.add(Package(PUB, name, exact, direct=True, dev=dev, spec="" if exact else spec))
            df.require("", name, spec)
    return df


# ---------------------------------------------------------------------------------------------
# Elixir terms (mix.lock, the deps list of mix.exs), read without evaluating anything

_TOKEN = re.compile(r'''\s+|\#[^\n]*|(?P<str>"(?:\\.|[^"\\])*")|(?P<kw>[a-z_][\w?!]*):(?!:)|
    (?P<atom>:(?:"(?:\\.|[^"\\])*"|[A-Za-z_][\w?!@]*))|(?P<op>%\{|=>|[{}\[\],])|
    (?P<word>[\w.@/?!-]+)|(?P<other>.)''', re.X)


def _tokens(text: str) -> List[Tuple[str, str]]:
    out = []
    for m in _TOKEN.finditer(text):
        kind = m.lastgroup
        if kind:
            out.append((kind, m.group(kind)))
    return out


def _term(toks: List[Tuple[str, str]], i: int) -> Tuple[Any, int]:
    kind, val = toks[i]
    if kind == "str":
        return json.loads(val) if "\\u" not in val else val[1:-1], i + 1
    if kind == "atom":
        return ("atom", val[1:].strip('"')), i + 1
    if kind == "op" and val in ("{", "[", "%{"):
        close = {"{": "}", "[": "]", "%{": "}"}[val]
        items, i = [], i + 1
        while i < len(toks) and toks[i][1] != close:
            if toks[i][1] == ",":
                i += 1
                continue
            if toks[i][0] == "str" and i + 1 < len(toks) and toks[i + 1] == ("other", ":"):
                key = json.loads(toks[i][1])                  # quoted keyword key `"phoenix": value`
                v, i = _term(toks, i + 2)
                items.append(("kw", key, v))
                continue
            if toks[i][0] == "kw":                            # keyword pair `key: value`
                key = toks[i][1]
                v, i = _term(toks, i + 1)
                items.append(("kw", key, v))
                continue
            k, i = _term(toks, i)
            if i < len(toks) and toks[i][1] == "=>":
                v, i = _term(toks, i + 1)
                items.append(("pair", k, v))
            else:
                items.append(k)
        node = {"{": "tuple", "[": "list", "%{": "map"}[val]
        return (node, items), i + 1
    return ("word", val), i + 1


def _atom(x) -> Optional[str]:
    return x[1] if isinstance(x, tuple) and len(x) == 2 and x[0] == "atom" else None


def _kw(items, key) -> Any:
    for it in items:
        if isinstance(it, tuple) and len(it) == 3 and it[0] == "kw" and it[1] == key:
            return it[2]
    return None


def parse_mix_lock(path: str, text: str) -> DependencyFile:
    df = DependencyFile(path, HEX, "lockfile")
    toks = _tokens(text)
    start = next((i for i, t in enumerate(toks) if t == ("op", "%{")), None)
    if start is None:
        raise _error(path, ValueError("not a mix.lock (no %{ map)"))
    try:
        (_, items), _ = _term(toks, start)
    except (IndexError, ValueError) as e:
        raise _error(path, e) from e
    entries: Dict[str, tuple] = {}
    for it in items:
        if isinstance(it, tuple) and it[0] in ("pair", "kw"):
            key = it[1] if isinstance(it[1], str) else it[1][1] if isinstance(it[1], tuple) else None
            value = it[2]
            if key and isinstance(value, tuple) and value[0] == "tuple":
                entries[str(key)] = value[1]
    keys: Dict[str, str] = {}
    for app, fields in entries.items():
        if _atom(fields[0]) != "hex" or len(fields) < 3 or not isinstance(fields[2], str):
            continue                                          # git / path dependencies
        package = _atom(fields[1]) or app
        keys[app] = df.add(Package(HEX, package, fields[2])).key
    for app, fields in entries.items():
        parent = keys.get(app)
        if parent is None or len(fields) < 6 or not isinstance(fields[5], tuple):
            continue
        for dep in fields[5][1]:
            if not (isinstance(dep, tuple) and dep[0] == "tuple"):
                continue
            parts = dep[1]
            name = _atom(parts[0]) if parts else None
            opts = parts[2][1] if len(parts) > 2 and isinstance(parts[2], tuple) else []
            if _atom(_kw(opts, "optional")) == "true" or _kw(opts, "optional") == ("word", "true"):
                continue                                  # optional: installed only if the project asks
            if name in keys:
                df.edge(parent, keys[name])
                if len(parts) > 1 and isinstance(parts[1], str):
                    df.require(parent, df.packages[keys[name]].name, parts[1])
    return df


def mix_exs_deps(text: str) -> List[Tuple[str, str, bool]]:
    """(app, requirement, dev only) for each entry of the project's deps list."""
    m = re.search(r"\bdefp?\s+deps\b[^\n]*\bdo\b", text)
    if not m:
        return []
    toks = _tokens(text[m.end():])
    start = next((i for i, t in enumerate(toks) if t == ("op", "[")), None)
    if start is None:
        return []
    try:
        (_, items), _ = _term(toks, start)
    except (IndexError, ValueError):
        return []
    out = []
    for it in items:
        if not (isinstance(it, tuple) and it[0] == "tuple" and it[1]):
            continue
        parts = it[1]
        app = _atom(parts[0])
        if not app:
            continue
        req = parts[1] if len(parts) > 1 and isinstance(parts[1], str) else ""
        only = _kw(parts, "only")
        envs = {_atom(x) for x in only[1]} if isinstance(only, tuple) and only[0] == "list" else \
            ({_atom(only)} if only is not None else set())
        out.append((app, req, bool(envs) and "prod" not in envs))
    return out


def mix_exs_direct(text: str) -> Dict[str, bool]:
    return {app: dev for app, _, dev in mix_exs_deps(text)}


def parse_mix_exs(path: str, text: str) -> DependencyFile:
    df = DependencyFile(path, HEX, "manifest")
    for app, req, dev in mix_exs_deps(text):
        exact = req.lstrip("= ") if re.fullmatch(r"(==\s*)?\d+\.\d+\.\d+[\w.+-]*", req) else None
        df.add(Package(HEX, app, exact, direct=True, dev=dev, spec="" if exact else req))
        if req:
            df.require("", app, req)
    return df


__all__ = ["parse_gemfile_lock", "gemfile_groups", "parse_gemfile", "parse_composer_lock", "composer_json_direct",
           "parse_composer_json", "parse_pubspec_lock", "parse_pubspec_yaml", "parse_mix_lock", "mix_exs_direct",
           "parse_mix_exs", "normalize_name"]
