"""Licences of dependencies and a licence policy.

Evidence, never fetched and never guessed:
  - the lockfile: npm `package-lock.json` (`license`), `composer.lock` (`license`, a list is a
    choice: OR);
  - installed metadata of the same version, under the lockfile's directory: `node_modules`
    (`package.json` `license`, also pnpm's `.pnpm/<name>@<version>` store), and a project
    virtualenv's `*.dist-info/METADATA` (`License-Expression`, else a `License` field that is
    itself a valid SPDX expression; trove classifiers are not mapped).
A package with none of these has an unknown licence, and the policy says so.

Policy (`[licenses]` in `.frame.toml` / `[tool.frame.licenses]`): `deny` and `allow` are SPDX
ids or globs (`GPL-*`, `AGPL-*`). Expressions are evaluated as SPDX defines them: `A OR B`
is acceptable if either is, `A AND B` only if both are, `A WITH E` is licence A with an
exception (a deny entry may name `A WITH E` exactly). A licence that is not an SPDX id (and not
`LicenseRef-...`) is unknown unless a deny entry names it.
"""

from __future__ import annotations

import fnmatch
import glob
import json
import re
from dataclasses import dataclass, field
from email.parser import HeaderParser
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple, Union

from frame.sca.model import NPM, PYPI, DependencyFile, Package, normalize_name

OK, VIOLATION, UNKNOWN = "ok", "violation", "unknown"


class SpdxError(ValueError):
    pass


# ---------------------------------------------------------------------------------------------
# SPDX license expressions (SPDX 2.3, Annex D)

@dataclass(frozen=True)
class Leaf:
    id: str                         # with a trailing "+" when written so
    exception: str = ""

    def __str__(self) -> str:
        return f"{self.id} WITH {self.exception}" if self.exception else self.id


@dataclass(frozen=True)
class Op:
    op: str                         # "AND" | "OR"
    args: Tuple["Expr", ...]


Expr = Union[Leaf, Op]

_TOKEN = re.compile(r"\s*(\(|\)|[A-Za-z0-9.+:-]+)")


def _tokens(text: str) -> List[str]:
    out, i = [], 0
    text = text.strip()
    while i < len(text):
        m = _TOKEN.match(text, i)
        if not m:
            raise SpdxError(f"unexpected {text[i:i + 10]!r}")
        out.append(m.group(1))
        i = m.end()
        while i < len(text) and text[i].isspace():
            i += 1
    return out


def parse_expression(text: str) -> Expr:
    """`MIT`, `(MIT OR Apache-2.0)`, `GPL-2.0-or-later WITH Classpath-exception-2.0 AND BSD-3-Clause`.
    AND binds tighter than OR; operators are case-insensitive here (npm writes `or`)."""
    toks = _tokens(text)
    pos = 0

    def peek() -> Optional[str]:
        return toks[pos] if pos < len(toks) else None

    def take() -> str:
        nonlocal pos
        if pos >= len(toks):
            raise SpdxError("unexpected end")
        pos += 1
        return toks[pos - 1]

    def primary() -> Expr:
        t = take()
        if t == "(":
            e = disj()
            if take() != ")":
                raise SpdxError("missing )")
            return e
        if t == ")" or t.upper() in ("AND", "OR", "WITH"):
            raise SpdxError(f"unexpected {t}")
        if (peek() or "").upper() == "WITH":
            take()
            exc = take()
            if exc in ("(", ")"):
                raise SpdxError("bad exception")
            return Leaf(t, exc)
        return Leaf(t)

    def conj() -> Expr:
        args = [primary()]
        while (peek() or "").upper() == "AND":
            take()
            args.append(primary())
        return args[0] if len(args) == 1 else Op("AND", tuple(args))

    def disj() -> Expr:
        args = [conj()]
        while (peek() or "").upper() == "OR":
            take()
            args.append(conj())
        return args[0] if len(args) == 1 else Op("OR", tuple(args))

    if not toks:
        raise SpdxError("empty")
    e = disj()
    if pos != len(toks):
        raise SpdxError(f"unexpected {toks[pos]}")
    return e


def leaves(e: Expr) -> List[Leaf]:
    return [e] if isinstance(e, Leaf) else [x for a in e.args for x in leaves(a)]


def _known(leaf: Leaf) -> bool:
    from frame.sca.sbom import _spdx_ids
    ids = _spdx_ids()
    return leaf.id.startswith(("LicenseRef-", "DocumentRef-")) or leaf.id in ids or \
        (leaf.id.endswith("+") and leaf.id[:-1] in ids)


def is_spdx(text: str) -> bool:
    try:
        return all(_known(lf) for lf in leaves(parse_expression(text)))
    except SpdxError:
        return False


# ---------------------------------------------------------------------------------------------
# policy

@dataclass
class Policy:
    deny: List[str] = field(default_factory=list)
    allow: List[str] = field(default_factory=list)
    unknown: str = "report"             # "report" | "fail"
    include_dev: bool = False
    source: str = ""

    @property
    def active(self) -> bool:
        return bool(self.deny or self.allow)


def _matches(patterns: Iterable[str], leaf: Leaf) -> Optional[str]:
    names = [str(leaf).lower(), leaf.id.lower()]
    for pat in patterns:
        if any(fnmatch.fnmatchcase(n, pat.lower()) for n in names):
            return pat
    return None


def _leaf_verdict(leaf: Leaf, policy: Policy) -> Tuple[str, str]:
    hit = _matches(policy.deny, leaf)
    if hit:
        return VIOLATION, f"{leaf} is denied ({hit})"
    if not _known(leaf):
        return UNKNOWN, f"{leaf.id} is not an SPDX licence id"
    if policy.allow and not _matches(policy.allow, leaf):
        return VIOLATION, f"{leaf} is not in the allow list"
    return OK, ""


def _verdict(e: Expr, policy: Policy) -> Tuple[str, str]:
    if isinstance(e, Leaf):
        return _leaf_verdict(e, policy)
    parts = [_verdict(a, policy) for a in e.args]
    states = [s for s, _ in parts]
    reasons = "; ".join(r for _, r in parts if r)
    if e.op == "OR":
        if OK in states:
            return OK, ""
        return (UNKNOWN if UNKNOWN in states else VIOLATION), reasons
    if VIOLATION in states:
        return VIOLATION, "; ".join(r for s, r in parts if s == VIOLATION)
    return (UNKNOWN if UNKNOWN in states else OK), reasons


def evaluate(license_text: str, policy: Policy) -> Tuple[str, str]:
    """(ok | violation | unknown, why)."""
    t = (license_text or "").strip()
    if not t:
        return UNKNOWN, "no licence information"
    try:
        e = parse_expression(t)
    except SpdxError:
        leaf = Leaf(t)                       # not an expression: deny may still name it
        hit = _matches(policy.deny, leaf)
        return (VIOLATION, f"{t} is denied ({hit})") if hit else (UNKNOWN, f"{t!r} is not an SPDX expression")
    return _verdict(e, policy)


# ---------------------------------------------------------------------------------------------
# evidence from installed packages

def composer_license(value) -> str:
    if isinstance(value, str):
        return value
    if isinstance(value, list):
        items = [v for v in value if isinstance(v, str) and v.strip()]
        if len(items) == 1:
            return items[0]
        return " OR ".join(f"({v})" if re.search(r"\s(AND|OR)\s", v, re.I) else v for v in items)
    return ""


def _npm_license(meta: dict) -> str:
    lic = meta.get("license")
    if isinstance(lic, str):
        return lic
    if isinstance(lic, dict) and isinstance(lic.get("type"), str):
        return lic["type"]
    lics = meta.get("licenses")                       # the deprecated array form: a choice
    if isinstance(lics, list):
        return composer_license([x.get("type") if isinstance(x, dict) else x for x in lics])
    return ""


def _installed_npm(d: Path, pkg: Package) -> str:
    store = d / "node_modules" / ".pnpm"
    prefix = f"{pkg.name.replace('/', '+')}@{pkg.version}"      # pnpm adds "(peer@x)" or "_hash" suffixes
    cands = [d / "node_modules" / pkg.name / "package.json"]
    if store.is_dir():
        cands += [e / "node_modules" / pkg.name / "package.json" for e in sorted(store.glob(f"{glob.escape(prefix)}*"))
                  if e.name == prefix or e.name[len(prefix)] in "(_"]
    for c in cands:
        try:
            meta = json.loads(c.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        if isinstance(meta, dict) and meta.get("version") == pkg.version:
            return _npm_license(meta)
    return ""


_VENVS = (".venv", "venv", "env", ".env")


def _site_packages(d: Path) -> List[Path]:
    out: List[Path] = []
    for v in _VENVS:
        out += sorted((d / v).glob("lib/python*/site-packages")) + [p for p in [d / v / "Lib" / "site-packages"] if p.is_dir()]
    return out


def _dist_infos(d: Path) -> Dict[Tuple[str, str], str]:
    """(normalised name, version) -> licence, from every dist-info under the project's venvs."""
    out: Dict[Tuple[str, str], str] = {}
    for sp in _site_packages(d):
        for meta in sp.glob("*.dist-info/METADATA"):
            try:
                headers = HeaderParser().parsestr(meta.read_text(encoding="utf-8", errors="replace"), headersonly=True)
            except Exception:
                continue
            name, version = headers.get("Name"), headers.get("Version")
            if not name or not version:
                continue
            lic = (headers.get("License-Expression") or "").strip()
            if not lic:
                raw = (headers.get("License") or "").strip()
                lic = raw if raw and "\n" not in raw and is_spdx(raw) else ""
            if lic:
                out[(normalize_name(PYPI, name), version)] = lic
    return out


def enrich(files: List[DependencyFile], root: Path) -> None:
    """Fill `Package.license` (and `license_source`) from installed metadata of the same
    version, where the lockfile did not say."""
    root = Path(root)
    venv_cache: Dict[Path, Dict[Tuple[str, str], str]] = {}
    for df in files:
        d = (root / df.path).parent
        for p in df.packages.values():
            if p.license or not p.version:
                continue
            lic = ""
            if df.ecosystem == NPM:
                lic = _installed_npm(d, p)
            elif df.ecosystem == PYPI:
                if d not in venv_cache:
                    venv_cache[d] = _dist_infos(d)
                lic = venv_cache[d].get((normalize_name(PYPI, p.name), p.version), "")
            if lic:
                p.license, p.license_source = lic, "installed"


# ---------------------------------------------------------------------------------------------

@dataclass
class LicenseFinding:
    package: Package
    path: str
    status: str
    reason: str

    def to_dict(self) -> dict:
        p = self.package
        return {"path": self.path, "ecosystem": p.ecosystem, "package": p.name, "version": p.version,
                "license": p.license, "license_source": p.license_source or ("lockfile" if p.license else ""),
                "dev": p.dev, "status": self.status, "reason": self.reason}


def check(files: List[DependencyFile], policy: Policy) -> List[LicenseFinding]:
    """One entry per package (and manifest), dev-only packages skipped unless `include_dev`."""
    out: List[LicenseFinding] = []
    for df in files:
        for p in df.packages.values():
            if p.dev and not policy.include_dev:
                continue
            status, why = evaluate(p.license, policy)
            out.append(LicenseFinding(p, df.path, status, why))
    out.sort(key=lambda f: ({VIOLATION: 0, UNKNOWN: 1, OK: 2}[f.status], f.path, f.package.name))
    return out


def failing(findings: List[LicenseFinding], policy: Policy) -> bool:
    return any(f.status == VIOLATION or (f.status == UNKNOWN and policy.unknown == "fail") for f in findings)


def format_text(findings: List[LicenseFinding], policy: Policy) -> str:
    lines = []
    viol = [f for f in findings if f.status == VIOLATION]
    unknown = [f for f in findings if f.status == UNKNOWN]
    for f in viol:
        lines.append(f"  VIOLATION  {f.package.name}@{f.package.version}  {f.package.license}  [{f.path}]: {f.reason}")
    if unknown:
        lines.append(f"  {len(unknown)} package(s) with an unknown licence"
                     + (" (fails: unknown = \"fail\")" if policy.unknown == "fail" else "")
                     + (":" if len(unknown) <= 20 else " (first 20):"))
        for f in unknown[:20]:
            lines.append(f"    {f.package.ecosystem} {f.package.name}@{f.package.version}: {f.reason}")
    ok = len(findings) - len(viol) - len(unknown)
    head = f"Licences: {len(findings)} packages, {ok} acceptable, {len(viol)} violation(s), {len(unknown)} unknown"
    if not policy.active:
        head += " (no policy: add [licenses] deny/allow to .frame.toml)"
    return "\n".join([head] + lines)
