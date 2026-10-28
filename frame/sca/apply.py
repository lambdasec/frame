"""Apply an upgrade plan (`plan.py`) to a project: edit the manifests, optionally re-lock
through the package manager, then verify by re-reading the graph and re-matching advisories.

Edits are textual and minimal: only the version (or a new override entry) changes, so a
file's formatting, comments and order survive. Every edit is shown as a unified diff; nothing
is written without `write=True`. A plan entry Frame cannot edit safely is reported as manual,
never approximated.
"""

from __future__ import annotations

import difflib
import json
import re
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Dict, List, Optional, Tuple

from frame.sca.model import GO, MAVEN, NPM, NUGET, PYPI, normalize_name
from frame.sca.ranges import satisfies

TIMEOUT = 900


@dataclass
class Change:
    path: str                    # relative to the project root
    before: str
    after: str
    reason: str

    def diff(self) -> str:
        return "".join(difflib.unified_diff(self.before.splitlines(True), self.after.splitlines(True),
                                            f"a/{self.path}", f"b/{self.path}"))


@dataclass
class Outcome:
    changes: List[Change] = field(default_factory=list)
    manual: List[str] = field(default_factory=list)          # plan entries left to a person, and why
    relocked: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    # with a verify command: "passed" | "rolled-back" (it passed before and failed after: every
    # edit and re-locked file restored) | "failing-before" (it already failed: proves nothing)
    verify: str = ""
    verify_output: str = ""
    adaptation: object = None             # adapt.Adaptation when --adapt ran


class _Files:
    """Edits accumulate per file so several plan entries can touch one manifest."""

    def __init__(self, root: Path):
        self.root = root
        self.text: Dict[str, str] = {}
        self.original: Dict[str, str] = {}
        self.reasons: Dict[str, List[str]] = {}

    def get(self, rel: str) -> Optional[str]:
        if rel not in self.text:
            p = self.root / rel
            if not p.is_file():
                return None
            self.text[rel] = self.original[rel] = p.read_text(encoding="utf-8")
        return self.text[rel]

    def set(self, rel: str, new: str, reason: str) -> None:
        if new != self.text.get(rel):
            self.text[rel] = new
            self.reasons.setdefault(rel, []).append(reason)

    def changes(self) -> List[Change]:
        return [Change(rel, self.original[rel], self.text[rel], "; ".join(self.reasons[rel]))
                for rel in sorted(self.text) if self.text[rel] != self.original[rel]]


# ---------------------------------------------------------------------------------------------
# npm

def _npm_spec_like(old: str, target: str) -> str:
    """Keep the author's style: `^1.2.3` -> `^target`, `~` -> `~target`, an exact pin -> exact."""
    old = old.strip()
    if old.startswith("^"):
        return "^" + target
    if old.startswith("~"):
        return "~" + target
    if re.fullmatch(r"=?v?\d+\.\d+\.\d+[\w.+-]*", old):
        return target
    return "^" + target


def _json_indent(text: str) -> int:
    m = re.search(r"\n([ \t]+)\"", text)
    return len(m.group(1).expandtabs(4)) if m else 2


def _npm_edit(files: _Files, home: str, lockname: str, p: dict) -> Optional[str]:
    rel = f"{home}/package.json" if home else "package.json"
    text = files.get(rel)
    if text is None:
        return f"{p['package']}: no package.json beside {p['path']}"
    data = json.loads(text)
    name, target = p["package"], p["target"]
    if p["action"] == "raise-requirement":
        for section in ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies"):
            deps = data.get(section) or {}
            if name in deps:
                deps[name] = _npm_spec_like(str(deps[name]), target)
        reason = f"{name}: require {target}"
    else:                                                    # override
        if lockname == "yarn.lock":
            data.setdefault("resolutions", {})[name] = target
        elif lockname == "pnpm-lock.yaml":
            data.setdefault("pnpm", {}).setdefault("overrides", {})[name] = target
        else:
            data.setdefault("overrides", {})[name] = target
        reason = f"{name}: override to {target}"
    new = json.dumps(data, indent=_json_indent(text), ensure_ascii=False) + ("\n" if text.endswith("\n") else "")
    files.set(rel, new, reason)
    return None


# ---------------------------------------------------------------------------------------------
# Python

def _raise_pep440(spec: str, target: str) -> Optional[str]:
    """`==1.2` -> `==target`; otherwise move (or add) the lower bound to `target`. None when
    an upper bound would still exclude it."""
    spec = spec.strip()
    if re.fullmatch(r"===?\s*[\w.!+*-]+", spec):
        return f"=={target}"
    clauses = [c.strip() for c in spec.split(",") if c.strip()]
    kept = [c for c in clauses if not re.match(r"^(>=|>|~=|==)", c)]
    new = ",".join([f">={target}"] + kept)
    return new if satisfies(PYPI, target, new) else None


_REQ_LINE = re.compile(r"^(\s*)([A-Za-z0-9][A-Za-z0-9._-]*)(\[[^\]]*\])?(\s*)([^;#\s][^;#]*?)?(\s*(?:;[^#]*)?(?:#.*)?)$")


def _python_requirements_edit(files: _Files, rel: str, p: dict) -> Optional[str]:
    text = files.get(rel)
    if text is None:
        return f"{p['package']}: {rel} not found"
    n, target = normalize_name(PYPI, p["package"]), p["target"]
    lines, hit = text.splitlines(True), False
    for i, line in enumerate(lines):
        body, nl = (line[:-1], "\n") if line.endswith("\n") else (line, "")
        m = _REQ_LINE.match(body)
        if not m or normalize_name(PYPI, m.group(2)) != n:
            continue
        new_spec = _raise_pep440(m.group(5) or "", target)
        if new_spec is None:
            return f"{p['package']}: the upper bound in {rel} excludes {target}"
        lines[i] = f"{m.group(1)}{m.group(2)}{m.group(3) or ''}{new_spec}{m.group(6) or ''}{nl}"
        hit = True
    if not hit:                                              # transitive: a requirement of its own
        if text and not text.endswith("\n"):
            lines.append("\n")
        lines.append(f"{p['package']}>={target}  # frame: {', '.join(p['fixes'][:3])}\n")
    files.set(rel, "".join(lines), f"{p['package']}: >={target}")
    return None


def _pyproject_edit(files: _Files, rel: str, p: dict, has_uv_lock: bool) -> Optional[str]:
    text = files.get(rel)
    if text is None:
        return f"{p['package']}: {rel} not found"
    n, target = normalize_name(PYPI, p["package"]), p["target"]
    if p["action"] == "override" or not p["direct"]:
        if not has_uv_lock:
            return f"{p['package']}: add a constraint `{p['package']}>={target}` (no override table for this tool)"
        line = f'"{p["package"]}>={target}"'
        if "[tool.uv]" in text and "constraint-dependencies" in text:
            new = re.sub(r"(constraint-dependencies\s*=\s*\[)", rf"\1{line}, ", text, count=1)
        elif "[tool.uv]" in text:
            new = text.replace("[tool.uv]", f"[tool.uv]\nconstraint-dependencies = [{line}]", 1)
        else:
            new = text.rstrip("\n") + f"\n\n[tool.uv]\nconstraint-dependencies = [{line}]\n"
        files.set(rel, new, f"{p['package']}: constraint >={target}")
        return None
    changed = _edit_dependency_sections(text, n, target)
    if changed == text:
        return f"{p['package']}: no requirement for it found in {rel} that can be raised to {target}"
    files.set(rel, changed, f"{p['package']}: require {target}")
    return None


_PEP621_ARRAYS = {"project": {"dependencies"}, "project.optional-dependencies": None, "dependency-groups": None}
_POETRY_TABLE = re.compile(r"^tool\.poetry\.(?:dependencies|dev-dependencies|group\.[^.]+\.dependencies)$")


def _edit_dependency_sections(text: str, n: str, target: str) -> str:
    """Raise `n`'s requirement only inside dependency declarations: PEP 621 arrays
    (`[project] dependencies`, optional dependencies, dependency groups) and Poetry's
    dependency tables. Nothing else in the file (keywords, descriptions) is touched."""
    def pep621_item(m):
        q, body = ('"', m.group(1)) if m.group(1) is not None else ("'", m.group(2))
        r = re.match(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)(\[[^\]]*\])?\s*([^;]*?)\s*(;.*)?$", body)
        if not r or normalize_name(PYPI, r.group(1)) != n:
            return m.group(0)
        spec = _raise_pep440(r.group(3) or "", target)
        if spec is None:
            return m.group(0)
        return f"{q}{r.group(1)}{r.group(2) or ''}{spec}{('; ' + r.group(4)[1:].strip()) if r.group(4) else ''}{q}"

    def poetry_value(old: str) -> Optional[str]:
        if old.startswith("^"):
            return "^" + target
        if old.startswith("~") and not old.startswith("~="):
            return "~" + target
        return _raise_pep440(old, target)

    lines = text.splitlines(True)
    section, in_array = "", False
    for i, line in enumerate(lines):
        stripped = line.strip()
        header = re.match(r"^\[([^\[\]]+)\]\s*$", stripped)
        if header and not in_array:
            section = header.group(1).strip()
            continue
        keys = _PEP621_ARRAYS.get(section, ...)
        key = re.match(r"^([A-Za-z0-9_.\"-]+)\s*=", stripped)
        if keys is not ... and (in_array or (key and (keys is None or key.group(1).strip('"') in keys)
                                              and "[" in stripped.split("=", 1)[1])):
            lines[i] = re.sub(r'"([A-Za-z0-9][^"\n]*)"|\'([A-Za-z0-9][^\'\n]*)\'', pep621_item, line)
            opened = stripped.count("[") - stripped.count("]")
            in_array = (in_array or opened > 0) and not stripped.endswith("]") and "]" not in stripped.split("#")[0][-1:]
            if key and "[" in stripped.split("=", 1)[1] and stripped.rstrip().endswith("]"):
                in_array = False
            continue
        if _POETRY_TABLE.match(section) and key and normalize_name(PYPI, key.group(1).strip('"')) == n:
            m = re.match(r'^(\s*[^=]+=\s*)"([^"]+)"(.*)$', line.rstrip("\n"))
            m2 = re.match(r'^(.*version\s*=\s*)"([^"]+)"(.*)$', line.rstrip("\n"))
            hit = m or m2
            if hit:
                new_v = poetry_value(hit.group(2))
                if new_v is not None:
                    lines[i] = f'{hit.group(1)}"{new_v}"{hit.group(3)}' + ("\n" if line.endswith("\n") else "")
    return "".join(lines)


# ---------------------------------------------------------------------------------------------
# Maven

def _pom_edit(files: _Files, rel: str, p: dict) -> Optional[str]:
    text = files.get(rel)
    if text is None:
        return f"{p['package']}: {rel} not found"
    group, artifact = p["package"].split(":", 1)
    target = p["target"]
    dep = re.compile(r"<dependency>\s*(?:(?!</dependency>).)*?<groupId>\s*" + re.escape(group) +
                     r"\s*</groupId>\s*(?:(?!</dependency>).)*?<artifactId>\s*" + re.escape(artifact) +
                     r"\s*</artifactId>(?:(?!</dependency>).)*?</dependency>", re.S)
    for m in dep.finditer(text):
        block = m.group(0)
        v = re.search(r"<version>\s*([^<]+?)\s*</version>", block)
        if not v:
            continue
        prop = re.fullmatch(r"\$\{([^}]+)\}", v.group(1))
        if prop:
            new = re.sub(rf"(<{re.escape(prop.group(1))}>)\s*[^<]*(</{re.escape(prop.group(1))}>)",
                         rf"\g<1>{target}\g<2>", text, count=1)
            if new == text:
                return f"{p['package']}: property ${{{prop.group(1)}}} is not defined in {rel}"
            files.set(rel, new, f"{p['package']}: {prop.group(1)} = {target}")
            return None
        new_block = block[:v.start(1)] + target + block[v.end(1):]
        files.set(rel, text[:m.start()] + new_block + text[m.end():], f"{p['package']}: {target}")
        return None
    entry = (f"<dependency>\n<groupId>{group}</groupId>\n<artifactId>{artifact}</artifactId>\n"
             f"<version>{target}</version>\n</dependency>")
    if "<dependencyManagement>" in text:
        new = re.sub(r"(<dependencyManagement>\s*<dependencies>)", lambda m: m.group(1) + "\n" + entry, text, count=1)
    elif "<dependencies>" in text:
        new = text.replace("<dependencies>", f"<dependencyManagement>\n<dependencies>\n{entry}\n</dependencies>\n"
                                             f"</dependencyManagement>\n<dependencies>", 1)
    else:
        return f"{p['package']}: no <dependencies> in {rel} to manage it from"
    files.set(rel, new, f"{p['package']}: managed at {target}")
    return None


# ---------------------------------------------------------------------------------------------
# NuGet

def _nuget_edit(files: _Files, home: Path, root: Path, p: dict) -> Optional[str]:
    name, target = p["package"], p["target"]
    projs = sorted((root / home).glob("*.csproj"))
    if not projs:
        return f"{name}: no .csproj in {home or '.'}"
    rel = projs[0].relative_to(root).as_posix()
    text = files.get(rel)
    ref = re.compile(r'(<PackageReference\s+Include="' + re.escape(name) + r'"[^>]*?\s(?:VersionOverride|Version)=")'
                     r'([^"]+)(")', re.I)
    if ref.search(text):
        files.set(rel, ref.sub(lambda m: m.group(1) + target + m.group(3), text, count=1), f"{name}: {target}")
        return None
    for d in [projs[0].parent, *projs[0].parent.parents]:              # central package management
        props = d / "Directory.Packages.props"
        if props.is_file():
            prel = props.relative_to(root).as_posix()
            ptext = files.get(prel)
            pv = re.compile(r'(<PackageVersion\s+Include="' + re.escape(name) + r'"[^>]*?\sVersion=")([^"]+)(")', re.I)
            if pv.search(ptext):
                files.set(prel, pv.sub(lambda m: m.group(1) + target + m.group(3), ptext, count=1), f"{name}: {target}")
                return None
            break
        if d == root:
            break
    item = re.search(r"(\n?[ \t]*)<PackageReference\b", text)
    line = f'<PackageReference Include="{name}" Version="{target}" />'
    if item:
        new = text[:item.start()] + item.group(1) + line + text[item.start():]
    else:
        new = text.replace("</Project>", f"  <ItemGroup>\n    {line}\n  </ItemGroup>\n</Project>", 1)
    files.set(rel, new, f"{name}: direct reference at {target}")
    return None


# ---------------------------------------------------------------------------------------------
# Go

def _go_edit(files: _Files, rel: str, p: dict) -> Optional[str]:
    text = files.get(rel)
    mod, target = p["package"], p["target"]
    pat = re.compile(r"(?m)^(\s*(?:require\s+)?" + re.escape(mod) + r"\s+)v[^\s/]+")
    if not pat.search(text):
        return f"{mod}: not required in {rel}"
    files.set(rel, pat.sub(lambda m: m.group(1) + "v" + target, text, count=1), f"{mod}: v{target}")
    return None


# ---------------------------------------------------------------------------------------------
# Gradle

def _gradle_edit(files: _Files, root: Path, rel: str, p: dict) -> Optional[str]:
    """A literal `g:a:OLD` written once in the build script, else the version catalog: the one
    edit after which re-reading the catalog gives this library the target and leaves every other
    library as it was (a `version.ref` shared with other libraries is not edited)."""
    from frame.sca.gradle import find_catalog, read_catalog
    pkg, cur, target = p["package"], p["current"], p["target"]
    manual = f"{pkg}: its version in {rel} is not one Frame can edit safely (add a constraint by hand)"
    text = files.get(rel)
    if text is None:
        return f"{pkg}: {rel} not found"
    lit = re.compile(r"""(["'])""" + re.escape(f"{pkg}:{cur}") + r"""(["':@])""")
    hits = len(lit.findall(text))
    if hits == 1:
        files.set(rel, lit.sub(lambda m: f"{m.group(1)}{pkg}:{target}{m.group(2)}", text), f"{pkg}: {target}")
        return None
    if hits > 1:
        return manual
    cat = find_catalog((root / rel).parent, root)
    if cat is None:
        return manual
    crel = cat.relative_to(root).as_posix()
    ctext = files.get(crel)
    try:
        before, _ = read_catalog(ctext)
    except ValueError:
        return manual
    if not any(m == pkg and v == cur for m, v in before.values()):
        return manual
    want = {a: ((m, target) if m == pkg else (m, v)) for a, (m, v) in before.items()}
    passing = []
    for old, new in ((f'"{cur}"', f'"{target}"'), (f'"{pkg}:{cur}"', f'"{pkg}:{target}"')):
        for m in re.finditer(re.escape(old), ctext):
            cand = ctext[:m.start()] + new + ctext[m.end():]
            try:
                after, _ = read_catalog(cand)
            except ValueError:
                continue
            if after == want and cand not in passing:
                passing.append(cand)
    if len(passing) != 1:
        return manual
    files.set(crel, passing[0], f"{pkg}: {target}")
    return None


# ---------------------------------------------------------------------------------------------

def _home(path: str) -> str:
    parts = Path(path).parent.parts
    if parts and parts[-1] == "obj":
        parts = parts[:-1]
    return "/".join(parts)


def edits(plans: List[dict], root: Path) -> Tuple[_Files, List[str]]:
    root = Path(root).resolve()
    files, manual = _Files(root), []
    for p in plans:
        if p["action"] == "no-fix" or not p["target"]:
            continue
        if p["action"] == "update-lockfile":
            continue                                         # nothing to edit: re-locking does it
        if p["action"] == "upgrade-os-package":
            manual.append(f"{p['package']} {p['current']} -> {p['target']}: an OS package of {p['path'].split(':/')[0]}; "
                          "upgrade it in the Dockerfile (apt-get / apk upgrade) or rebuild on a newer base image")
            continue
        home = _home(p["path"])
        rel_in = (lambda n: f"{home}/{n}" if home else n)
        name = Path(p["path"]).name
        eco = p["ecosystem"]
        problem: Optional[str]
        if eco == NPM:
            problem = _npm_edit(files, home, name, p)
        elif eco == PYPI:
            if name.endswith(".txt"):
                problem = _python_requirements_edit(files, p["path"], p)
            elif (root / rel_in("pyproject.toml")).is_file():
                problem = _pyproject_edit(files, rel_in("pyproject.toml"), p, (root / rel_in("uv.lock")).is_file())
            else:
                problem = f"{p['package']}: no manifest Frame can edit beside {p['path']}"
        elif eco == MAVEN:
            pom = rel_in("pom.xml")
            build = next((rel_in(n) for n in ("build.gradle.kts", "build.gradle") if (root / rel_in(n)).is_file()), None)
            if name in ("build.gradle", "build.gradle.kts"):
                build = p["path"]
            problem = _pom_edit(files, pom, p) if (root / pom).is_file() else \
                _gradle_edit(files, root, build, p) if build else f"{p['package']}: no pom.xml or Gradle build beside {p['path']}"
        elif eco == NUGET:
            problem = _nuget_edit(files, Path(home), root, p)
        elif eco == GO:
            problem = _go_edit(files, rel_in("go.mod"), p)
        else:
            problem = f"{p['package']}: editing {eco} manifests is not supported yet"
        if problem:
            manual.append(problem)
    return files, manual


# ---------------------------------------------------------------------------------------------
# re-locking (opt-in: runs the package manager)

def _relock_commands(lockname: str, plans: List[dict]) -> Optional[List[List[str]]]:
    names = sorted({p["package"] for p in plans if p["target"]})
    pinned = [f"{p['package']}@{p['target']}" for p in plans if p["target"]]
    return {
        "package-lock.json": [["npm", "install", "--package-lock-only", "--ignore-scripts", "--no-audit", "--no-fund"],
                              ["npm", "update", *names, "--package-lock-only", "--ignore-scripts", "--no-audit",
                               "--no-fund"]],
        "npm-shrinkwrap.json": [["npm", "install", "--package-lock-only", "--ignore-scripts", "--no-audit", "--no-fund"]],
        "pnpm-lock.yaml": [["pnpm", "install", "--lockfile-only", "--ignore-scripts"],
                           ["pnpm", "update", *names, "--lockfile-only", "--ignore-scripts"]],
        "yarn.lock": [["yarn", "install", "--mode", "update-lockfile"]],
        "poetry.lock": [["poetry", "lock"], ["poetry", "update", *names, "--lock"]],
        "uv.lock": [["uv", "lock", *[a for n in names for a in ("--upgrade-package", n)]]],
        "Cargo.lock": [["cargo", "update", "-p", s.split("@")[0], "--precise", s.split("@")[1]] for s in pinned],
        "go.mod": [["go", "mod", "tidy"]],
    }.get(lockname)


def relock(plans: List[dict], root: Path) -> Tuple[List[str], List[str]]:
    """Re-lock each lockfile the plan touches with its own package manager."""
    done, warnings = [], []
    by_file: Dict[str, List[dict]] = {}
    for p in plans:
        if p["target"]:
            by_file.setdefault(p["path"], []).append(p)
    for path, ps in sorted(by_file.items()):
        cmds = _relock_commands(Path(path).name, ps)
        if not cmds:
            continue
        cwd = (Path(root) / path).parent
        if shutil.which(cmds[0][0]) is None:
            warnings.append(f"{path}: re-locking needs {cmds[0][0]} on PATH")
            continue
        if Path(path).name == "Cargo.lock":
            # one `cargo update -p X --precise V` per package: a dependency can move only after the
            # package that requires it, so a step that fails is retried while the others progress
            pending, failed = list(cmds), {}
            while pending:
                progressed, rest = False, []
                for cmd in pending:
                    ok, msg = _run_relock(cmd, cwd)
                    if ok:
                        progressed = True
                        failed.pop(tuple(cmd), None)
                    else:
                        failed[tuple(cmd)] = msg
                        rest.append(cmd)
                pending = rest if progressed else []
            if failed:
                warnings.extend(f"{path}: {msg}" for msg in failed.values())
            else:
                done.append(path)
            continue
        for cmd in cmds:
            ok, msg = _run_relock(cmd, cwd)
            if not ok:
                warnings.append(f"{path}: {msg}")
                break
        else:
            done.append(path)
    return done, warnings


def _run_relock(cmd: List[str], cwd: Path) -> Tuple[bool, str]:
    try:
        proc = subprocess.run(cmd, cwd=str(cwd), capture_output=True, text=True, timeout=TIMEOUT)
    except (OSError, subprocess.TimeoutExpired) as e:
        return False, f"{' '.join(cmd[:2])} could not run ({e})"
    if proc.returncode != 0:
        tail = (proc.stderr or proc.stdout).strip().splitlines()
        return False, f"{' '.join(cmd[:2])} failed: {tail[-1][:200] if tail else proc.returncode}"
    return True, ""


def _run_verify(command: str, root: Path) -> Tuple[bool, str]:
    try:
        proc = subprocess.run(command, shell=True, cwd=str(root), capture_output=True, text=True,  # nosec: the user's own command
                              timeout=TIMEOUT)
    except subprocess.TimeoutExpired:
        return False, f"timed out after {TIMEOUT}s"
    tail = "\n".join((proc.stdout + proc.stderr).strip().splitlines()[-20:])
    return proc.returncode == 0, tail


def _snapshot(plans: List[dict], changes: List[Change], root: Path) -> Dict[Path, Optional[bytes]]:
    """Every file applying and re-locking may write: the edited manifests and, in each
    plan's directory, the lockfiles a package manager regenerates."""
    from frame.sca.lockfiles import LOCKFILES
    paths = {root / c.path for c in changes}
    for p in plans:
        d = (root / p["path"]).parent
        paths.add(root / p["path"])
        paths.update(d / name for name in LOCKFILES if (d / name).is_file())
    return {p: (p.read_bytes() if p.is_file() else None) for p in paths}


def apply_plan(plans: List[dict], root: Path, write: bool = False, relock_: bool = False,
               verify: Optional[str] = None, adapt_fn: Optional[Callable[[str], object]] = None) -> Outcome:
    """Edit (and with `relock_`, re-lock). With `verify`, the project's own build or test
    command runs before and after: if it passed before and fails after, every file the
    upgrade touched is restored."""
    root = Path(root).resolve()
    files, manual = edits(plans, root)
    out = Outcome(changes=files.changes(), manual=manual)
    if not write:
        return out
    before_ok = None
    saved = _snapshot(plans, out.changes, root)
    if verify:
        before_ok, _ = _run_verify(verify, root)
    for c in out.changes:
        (root / c.path).write_text(c.after, encoding="utf-8")
    if relock_:
        out.relocked, out.warnings = relock(plans, root)
    if verify:
        after_ok, out.verify_output = _run_verify(verify, root)
        if after_ok:
            out.verify = "passed"
        elif before_ok:
            if adapt_fn is not None:                       # let the code adapt to the upgrade first
                out.adaptation = adapt_fn(out.verify_output)
            if getattr(out.adaptation, "status", "") == "adapted":
                out.verify, out.verify_output = "adapted", out.adaptation.output
                return out
            for p, data in saved.items():                  # a failed adaptation restored its own edits
                if data is None:
                    if p.exists():
                        p.unlink()
                else:
                    p.write_bytes(data)
            out.verify = "rolled-back"
        else:
            out.verify = "failing-before"
    return out
