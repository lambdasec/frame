"""Vulnerable functions from fix commits: for an advisory that links the commit that fixed it,
the public functions that commit changed, as Frame canonical call ids (`frame kb mine-functions`).

    1. the advisory's GitHub commit links (`/commit/<sha>`, `/pull/N/commits/<sha>`)
    2. the commit's files and patches, and each changed source file at the parent commit
    3. the functions that enclose a changed line (tree-sitter; tests and non-source skipped)
    4. a canonical id only where one is certain:
         Java / C#   package or namespace . class . method   (public or protected / public)
         Python      the module path from the package's import name in the repository path
         JavaScript  `<package>.<name>` when the file exports that function
    5. public functions only. A changed internal function is lifted to the public functions of
       the same file that call it directly (transitively); `lifted_from` names it. A fix that only
       changes internals nothing public calls directly yields nothing: it needs curating.

Entries are `{"id", "source": "fix-commit", "commit", ["lifted_from"]}`. Nothing is guessed:
a file Frame cannot place in its package, or a name it cannot prove public, is left out.
"""

from __future__ import annotations

import gzip
import json
import os
import re
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Set, Tuple

from frame.sca.model import MAVEN, NPM, NUGET, PYPI, normalize_name

_COMMIT_URL = re.compile(r"https?://github\.com/([\w.-]+)/([\w.-]+)/(?:pull/\d+/)?commits?/([0-9a-f]{7,40})")
_LANG = {".py": "python", ".js": "javascript", ".mjs": "javascript", ".cjs": "javascript",
         ".java": "java", ".cs": "csharp"}
_ECO_LANG = {PYPI: "python", NPM: "javascript", MAVEN: "java", NUGET: "csharp"}
_TEST_PATH = re.compile(r"(^|/)(tests?|__tests__|spec|specs|test-?data|benchmarks?|examples?|docs?)(/|$)|"
                        r"(^|/)[^/]*(_test|Test|Tests|\.test|\.spec)\.[a-z]+$", re.I)


class MineError(Exception):
    pass


class RateLimited(MineError):
    """GitHub's API quota is spent: stop, and resume from the last advisory fully processed."""


def commit_links(record: dict) -> List[Tuple[str, str, str]]:
    out = []
    for ref in record.get("references") or []:
        m = _COMMIT_URL.match(str(ref.get("url", "")))
        if m and (m.group(1), m.group(2), m.group(3)) not in out:
            out.append((m.group(1), m.group(2), m.group(3)))
    return out


# ---------------------------------------------------------------------------------------------
# where commits come from

class GitHubSource:
    """The GitHub REST API (`GITHUB_TOKEN` / `GH_TOKEN` when set), cached on disk."""

    def __init__(self, cache: Path, token: Optional[str] = None):
        self.cache = Path(cache)
        self.token = token or os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")

    def _get(self, url: str, raw: bool) -> bytes:
        req = urllib.request.Request(url, headers={
            "Accept": "application/vnd.github.raw" if raw else "application/vnd.github+json",
            "User-Agent": "frame-kb-mine"})
        if self.token:
            req.add_header("Authorization", f"Bearer {self.token}")
        try:
            with urllib.request.urlopen(req, timeout=60) as resp:
                return resp.read()
        except urllib.error.HTTPError as e:
            remaining = e.headers.get("X-RateLimit-Remaining") if e.headers else None
            if e.code == 429 or (e.code == 403 and remaining == "0"):
                raise RateLimited(f"GitHub API rate limit (resets at {e.headers.get('X-RateLimit-Reset', '?')})") from e
            raise MineError(f"{url}: HTTP {e.code}") from e
        except (urllib.error.URLError, OSError) as e:
            raise MineError(f"{url}: {e}") from e

    def _cached(self, key: str, fetch) -> bytes:
        p = self.cache / key
        if p.is_file():
            return gzip.decompress(p.read_bytes())
        data = fetch()
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(gzip.compress(data, mtime=0))
        return data

    def commit(self, owner: str, repo: str, sha: str) -> dict:
        data = self._cached(f"{owner}__{repo}__{sha[:12]}/commit.json.gz", lambda: self._get(
            f"https://api.github.com/repos/{owner}/{repo}/commits/{sha}", raw=False))
        c = json.loads(data)
        return {"sha": c["sha"], "parents": [p["sha"] if isinstance(p, dict) else p for p in c.get("parents", [])],
                "files": [{"filename": f["filename"], "status": f.get("status", ""), "patch": f.get("patch", "")}
                          for f in c.get("files", [])]}

    def file(self, owner: str, repo: str, ref: str, path: str) -> Optional[str]:
        try:
            data = self._cached(f"{owner}__{repo}__{ref[:12]}/files/{path}.gz", lambda: self._get(
                f"https://api.github.com/repos/{owner}/{repo}/contents/{path}?ref={ref}", raw=True))
        except RateLimited:
            raise
        except MineError:
            return None
        return data.decode("utf-8", "replace")


class RecordedSource:
    """Commits recorded on disk (`<owner>__<repo>__<sha12>/commit.json` and `files/<path>.gz`
    at the parent): for tests, and for air-gapped mining."""

    def __init__(self, root: Path):
        self.root = Path(root)

    def commit(self, owner: str, repo: str, sha: str) -> dict:
        p = self.root / f"{owner}__{repo}__{sha[:12]}" / "commit.json"
        if not p.is_file():
            raise MineError(f"no recorded commit {owner}/{repo}@{sha[:12]}")
        return json.loads(p.read_text())

    def file(self, owner: str, repo: str, ref: str, path: str) -> Optional[str]:
        for d in self.root.glob(f"{owner}__{repo}__*"):
            c = json.loads((d / "commit.json").read_text())
            if c["parents"] and c["parents"][0] == ref:
                f = d / "files" / (path + ".gz")
                if f.is_file():
                    return gzip.decompress(f.read_bytes()).decode("utf-8", "replace")
        return None


# ---------------------------------------------------------------------------------------------
# what a patch changed

def changed_old_lines(patch: str) -> Set[int]:
    """Lines of the old file a unified-diff patch touches: removed lines, and for an insertion
    the old lines on either side of it."""
    out: Set[int] = set()
    old = 0
    for line in patch.splitlines():
        m = re.match(r"^@@ -(\d+)(?:,(\d+))? \+\d+(?:,\d+)? @@", line)
        if m:
            old = int(m.group(1))
            continue
        if not old:
            continue
        if line.startswith("-"):
            out.add(old)
            old += 1
        elif line.startswith("+"):
            out.update({old - 1, old})
        else:
            old += 1
    return {n for n in out if n > 0}


@dataclass
class Fn:
    name: str                      # qualified within the file: Class.method / function
    start: int                     # 1-based, inclusive
    end: int
    public: bool
    body: str = ""
    container: str = ""            # package / namespace (Java, C#)


def _parser(lang: str):
    import tree_sitter
    if lang == "python":
        import tree_sitter_python as g
    elif lang == "javascript":
        import tree_sitter_javascript as g
    elif lang == "java":
        import tree_sitter_java as g
    else:
        import tree_sitter_c_sharp as g
    language = tree_sitter.Language(g.language())
    try:
        return tree_sitter.Parser(language)
    except TypeError:                                  # older bindings
        p = tree_sitter.Parser()
        p.set_language(language)
        return p


def _t(n) -> str:
    return n.text.decode("utf-8", "replace") if n is not None else ""


def functions(text: str, lang: str) -> List[Fn]:
    root = _parser(lang).parse(text.encode("utf-8")).root_node
    out: List[Fn] = []
    container = ""

    def mods(n) -> str:
        return " ".join(_t(c) for c in n.children if c.type in ("modifiers", "modifier"))

    def visit(n, scope: List[str]):
        nonlocal container
        t = n.type
        if lang == "java" and t == "package_declaration":
            container = _t(n).replace("package", "", 1).strip().rstrip(";").strip()
        if lang == "csharp" and t in ("namespace_declaration", "file_scoped_namespace_declaration"):
            container = _t(n.child_by_field_name("name"))
        name_node = n.child_by_field_name("name")
        if lang == "python":
            if t == "class_definition":
                for c in n.children:
                    visit(c, scope + [_t(name_node)])
                return
            if t == "function_definition":
                nm = _t(name_node)
                qual = ".".join(scope + [nm])
                out.append(Fn(qual, n.start_point[0] + 1, n.end_point[0] + 1,
                              not any(p.startswith("_") for p in scope + [nm]), _t(n)))
                return                                   # nested functions belong to this one
        elif lang == "javascript":
            fn_name = None
            if t in ("function_declaration", "generator_function_declaration"):
                fn_name = _t(name_node)
            elif t == "variable_declarator" and n.child_by_field_name("value") is not None and \
                    n.child_by_field_name("value").type in ("function", "function_expression", "arrow_function"):
                fn_name = _t(name_node)
            elif t == "method_definition":
                fn_name = ".".join(scope + [_t(name_node)])
            if t in ("class_declaration",):
                for c in n.children:
                    visit(c, scope + [_t(name_node)])
                return
            if fn_name:
                out.append(Fn(fn_name, n.start_point[0] + 1, n.end_point[0] + 1, True, _t(n)))
                for c in n.children:                     # lodash defines its API inside one IIFE
                    visit(c, scope)
                return
        else:
            if t in ("class_declaration", "interface_declaration", "enum_declaration", "record_declaration",
                     "struct_declaration"):
                vis = mods(n)
                public = ("public" in vis) if lang == "csharp" else ("public" in vis or "protected" in vis)
                for c in n.children:
                    visit_member(c, scope + [_t(name_node)], public and all(scope_public))
                return
        for c in n.children:
            visit(c, scope)

    scope_public: List[bool] = [True]

    def visit_member(n, scope: List[str], cls_public: bool):
        t = n.type
        if t in ("method_declaration", "constructor_declaration"):
            vis = mods(n)
            public = ("public" in vis) if lang == "csharp" else ("public" in vis or "protected" in vis)
            name = "<init>" if t == "constructor_declaration" and lang == "java" else _t(n.child_by_field_name("name"))
            out.append(Fn(".".join(scope + [name]), n.start_point[0] + 1, n.end_point[0] + 1,
                          public and cls_public, _t(n), container))
            return
        if t in ("class_declaration", "interface_declaration", "enum_declaration", "record_declaration",
                 "struct_declaration"):
            vis = mods(n)
            public = ("public" in vis) if lang == "csharp" else ("public" in vis or "protected" in vis)
            for c in n.children:
                visit_member(c, scope + [_t(n.child_by_field_name("name"))], cls_public and public)
            return
        for c in n.children:
            visit_member(c, scope, cls_public)

    visit(root, [])
    for f in out:
        if not f.container:
            f.container = container
    return out


def _js_exports(text: str) -> Set[str]:
    """Names a JS file makes public, read from the syntax tree: `exports.N = ...`,
    `module.exports.N = ...`, `X.N = N` (lodash's `lodash.template = template`), `export
    function N`, `export { N }`, `export const N = ...`, `module.exports = { N, M: ... }`."""
    root = _parser("javascript").parse(text.encode("utf-8")).root_node
    names: Set[str] = set()
    stack = [root]
    while stack:
        n = stack.pop()
        stack.extend(n.children)
        if n.type == "assignment_expression":
            left, right = n.child_by_field_name("left"), n.child_by_field_name("right")
            if left is None or right is None:
                continue
            if left.type == "member_expression":
                obj, prop = _t(left.child_by_field_name("object")), _t(left.child_by_field_name("property"))
                if obj in ("exports", "module.exports") or (right.type == "identifier" and _t(right) == prop):
                    names.add(prop)
            if _t(left) == "module.exports" and right.type == "object":
                for c in right.named_children:
                    if c.type == "shorthand_property_identifier":
                        names.add(_t(c))
                    elif c.type == "pair":
                        names.add(_t(c.child_by_field_name("key")).strip("'\""))
        elif n.type == "export_statement":
            decl = n.child_by_field_name("declaration")
            if decl is not None and decl.child_by_field_name("name") is not None:
                names.add(_t(decl.child_by_field_name("name")))
            elif decl is not None:
                names.update(_t(d.child_by_field_name("name")) for d in decl.named_children
                             if d.type == "variable_declarator")
            for c in n.named_children:
                if c.type == "export_clause":
                    for spec in c.named_children:
                        names.add(_t(spec.child_by_field_name("alias") or spec.child_by_field_name("name")))
    return {x for x in names if x}


def npm_entry_files(package_json: Optional[str]) -> Set[str]:
    """The files a package's own `package.json` makes its public entry (`main`, `module`, the
    `.` export, `browser` when a string); `index.js` when it names none. Only their exports are
    the package's API: `require('qs').merge` does not exist even though `lib/utils.js` exports
    `merge`."""
    entries: List[str] = []
    try:
        data = json.loads(package_json) if package_json else {}
    except ValueError:
        data = {}
    for key in ("main", "module", "browser"):
        if isinstance(data.get(key), str):
            entries.append(data[key])
    exp = data.get("exports")
    dot = exp.get(".", exp) if isinstance(exp, dict) else exp
    stack = [dot]
    while stack:
        x = stack.pop()
        if isinstance(x, str):
            entries.append(x)
        elif isinstance(x, dict):
            stack.extend(x.values())
    if not entries:
        entries.append("index.js")
    out = set()
    for e in entries:
        e = e[2:] if e.startswith("./") else e.lstrip("/")
        if not Path(e).suffix:
            out.update({e + ".js", e + "/index.js"})
        out.add(e)
    return out


def _python_module(path: str, import_names: Iterable[str]) -> Optional[str]:
    parts = Path(path).with_suffix("").parts
    for top in sorted({n.split(".")[0] for n in import_names}, key=len, reverse=True):
        if top in parts:
            i = len(parts) - 1 - parts[::-1].index(top)          # the innermost occurrence
            mod = list(parts[i:])
            if mod[-1] == "__init__":
                mod = mod[:-1]
            return ".".join(mod)
    return None


def canonical(ecosystem: str, package: str, path: str, fn: Fn, file_text: str) -> Optional[str]:
    if ecosystem in (MAVEN, NUGET):
        return f"{fn.container}.{fn.name}" if fn.container else None
    if ecosystem == PYPI:
        from frame.sca.reachability import module_names
        mod = _python_module(path, module_names(PYPI, package))
        return f"{mod}.{fn.name}" if mod else None
    if ecosystem == NPM:
        short = fn.name.rsplit(".", 1)[-1]
        return f"{package}.{short}" if short in _js_exports(file_text) else None
    return None


def _lift(fns: List[Fn], changed: List[Fn], depth: int = 12) -> Dict[str, str]:
    """Public functions of the file that call a changed internal one directly (transitively):
    public name -> the internal function it reaches. Each function is visited once, so the
    depth only bounds a chain, never a cycle; real chains are longer than three (AntiSamy's
    processStyleTag reaches the public scan through four private callers)."""
    out: Dict[str, str] = {}
    frontier = {f.name.rsplit(".", 1)[-1]: f.name for f in changed if not f.public}
    seen = set(frontier)
    for _ in range(depth):
        nxt = {}
        for g in fns:
            short = g.name.rsplit(".", 1)[-1]
            for callee, origin in frontier.items():
                if g.name == origin or not re.search(rf"(?<![\w$]){re.escape(callee)}\s*\(", g.body):
                    continue
                if g.public:
                    out.setdefault(g.name, origin)
                elif short not in seen:
                    seen.add(short)
                    nxt[short] = origin
        if not nxt:
            break
        frontier = nxt
    return out


@dataclass
class Mined:
    advisory: str
    modified: str = ""                                          # the OSV record's `modified`
    entries: List[dict] = field(default_factory=list)
    internal_only: List[str] = field(default_factory=list)    # changed functions nothing public reaches
    outside_functions: List[str] = field(default_factory=list)  # files changed outside any function
    skipped: List[str] = field(default_factory=list)

    @property
    def needs_curation(self) -> bool:
        return not self.entries and bool(self.internal_only or self.outside_functions)


def mine_record(record: dict, ecosystem: str, package: str, source) -> Mined:
    res = Mined(record["id"], str(record.get("modified") or ""))
    lang = _ECO_LANG.get(ecosystem)
    if lang is None:
        return res
    seen: Set[str] = set()
    for owner, repo, sha in commit_links(record):
        try:
            commit = source.commit(owner, repo, sha)
        except RateLimited:
            raise
        except MineError as e:
            res.skipped.append(str(e))
            continue
        if not commit.get("parents"):
            continue
        parent = commit["parents"][0]
        url = f"https://github.com/{owner}/{repo}/commit/{commit['sha']}"
        entry = npm_entry_files(source.file(owner, repo, parent, "package.json")) if ecosystem == NPM else None
        for f in commit["files"]:
            path = f["filename"]
            if _LANG.get(Path(path).suffix) != lang or _TEST_PATH.search(path) or f.get("status") == "added":
                continue
            text = source.file(owner, repo, parent, path)
            if text is None:
                res.skipped.append(f"{path}: not available at {parent[:12]}")
                continue
            lines = changed_old_lines(f.get("patch", ""))
            fns = functions(text, lang)
            changed = [fn for fn in fns if any(fn.start <= n <= fn.end for n in lines)]
            if any(not any(fn.start <= n <= fn.end for fn in fns) for n in lines):
                res.outside_functions.append(path)             # module- or class-level code changed
            # the innermost enclosing function is the changed one (JS defines functions in an IIFE)
            changed = [fn for fn in changed
                       if not any(o is not fn and fn.start <= o.start and o.end <= fn.end for o in changed)]
            lifted = _lift(fns, changed)
            names = [(fn, None) for fn in changed if fn.public] + \
                    [(next(g for g in fns if g.name == pub), origin) for pub, origin in lifted.items()]
            if entry is not None and path not in entry:
                # exported from an internal module, not the package's entry: not its API
                res.internal_only.extend(f"{path}:{fn.name} (not the package entry)" for fn, _ in names)
                continue
            for fn, origin in names:
                cid = canonical(ecosystem, package, path, fn, text)
                if cid and cid not in seen:
                    seen.add(cid)
                    e = {"id": cid, "source": "fix-commit", "commit": url}
                    if origin:
                        e["lifted_from"] = origin
                    res.entries.append(e)
            public_names = {fn.name for fn in changed if fn.public}
            for fn in changed:
                if not fn.public and fn.name not in lifted.values() and fn.name not in public_names:
                    res.internal_only.append(f"{path}:{fn.name}")
    return res


@dataclass
class Progress:
    processed: int = 0
    rate_limited: str = ""                     # why the run stopped early, if it did
    resume_after: str = ""                     # `modified` of the last advisory fully processed


def mine(records: Iterable[dict], ecosystems: Iterable[str], source, limit: Optional[int] = None,
         existing: Optional[Dict[str, Dict[str, List[dict]]]] = None, since: Optional[str] = None,
         progress: Optional[Progress] = None) -> Tuple[Dict[str, Dict[str, List[dict]]], List[Mined]]:
    """{ecosystem: {advisory id: entries}}, merged over `existing` (curated entries win: an
    advisory that already has functions keeps them and gains only new ids). With `since`, only
    records modified after it, oldest first; `progress` says how far the run got, so a run cut
    short by GitHub's rate limit resumes exactly there (`resume_after` as the next `since`)."""
    out: Dict[str, Dict[str, List[dict]]] = {e: dict((existing or {}).get(e, {})) for e in ecosystems}
    report: List[Mined] = []
    prog = progress if progress is not None else Progress()
    if since is not None:
        records = sorted((r for r in records if isinstance(r, dict) and str(r.get("modified") or "") > since),
                         key=lambda r: (str(r.get("modified") or ""), r.get("id", "")))
    n = 0
    for rec in records:
        if not isinstance(rec, dict) or rec.get("withdrawn") or not commit_links(rec):
            continue
        for aff in rec.get("affected") or []:
            eco = (aff.get("package") or {}).get("ecosystem", "").split(":", 1)[0]
            name = (aff.get("package") or {}).get("name")
            if eco not in out or not name:
                continue
            if limit is not None and n >= limit:
                return out, report
            n += 1
            try:
                m = mine_record(rec, eco, normalize_name(eco, name) if eco == NPM else name, source)
            except RateLimited as e:
                prog.rate_limited = str(e)                    # this advisory is not done: resume at it
                return out, report
            report.append(m)
            prog.processed += 1
            prog.resume_after = max(prog.resume_after, m.modified)
            if m.entries:
                have = out[eco].setdefault(rec["id"], [])
                ids = {x["id"] for x in have}
                have.extend(e for e in m.entries if e["id"] not in ids)
            break
    return out, report
