"""`frame deps --resolve`: ask the project's own build tools for the resolved graph.

Opt-in, because it runs them: Maven and Gradle execute the project's build configuration
(plugins, `build.gradle` code), and pip downloads packages to resolve them. Nothing here runs
during a scan. Each runner returns DependencyFiles (or a warning when the tool is missing or
fails); the files' `path` is the manifest the result stands for.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Callable, Dict, List, Optional, Sequence, Tuple

from frame.sca.jvm import parse_gradle_report, parse_maven_tree
from frame.sca.model import PYPI, DependencyFile, Package, normalize_name

TIMEOUT = 900                                   # seconds per build tool run
Result = Tuple[Optional[DependencyFile], Optional[str]]      # (graph, warning)


def _run(cmd: Sequence[str], cwd: Path) -> subprocess.CompletedProcess:
    return subprocess.run(list(cmd), cwd=str(cwd), capture_output=True, text=True, timeout=TIMEOUT,
                          env={**os.environ, "MAVEN_OPTS": os.environ.get("MAVEN_OPTS", "")})


def _tail(proc: subprocess.CompletedProcess) -> str:
    lines = (proc.stderr or proc.stdout or "").strip().splitlines()
    return lines[-1][:200] if lines else f"exit status {proc.returncode}"


def resolve_maven(project_dir: Path, rel_pom: str) -> Result:
    mvn = shutil.which("mvn") or shutil.which("mvn.cmd")
    wrapper = project_dir / "mvnw"
    cmd0 = str(wrapper) if wrapper.is_file() and os.access(wrapper, os.X_OK) else mvn
    if cmd0 is None:
        return None, f"{rel_pom}: --resolve needs Maven (mvn) on PATH or an executable ./mvnw"
    with tempfile.TemporaryDirectory() as tmp:
        out = Path(tmp) / "tree.txt"
        try:
            proc = _run([cmd0, "-B", "-q", "dependency:tree", f"-DoutputFile={out}", "-DappendOutput=true",
                         "-DoutputType=text"], project_dir)
        except (OSError, subprocess.TimeoutExpired) as e:
            return None, f"{rel_pom}: Maven could not run ({e})"
        if proc.returncode != 0 or not out.is_file():
            return None, f"{rel_pom}: mvn dependency:tree failed: {_tail(proc)}"
        df = parse_maven_tree(rel_pom, out.read_text(encoding="utf-8", errors="replace"))
    return df, None


def _gradle_projects(cmd0: str, project_dir: Path) -> List[str]:
    try:
        proc = _run([cmd0, "-q", "projects"], project_dir)
    except (OSError, subprocess.TimeoutExpired):
        return []
    return re.findall(r"[Pp]roject '(:[^']+)'", proc.stdout or "")


def resolve_gradle(project_dir: Path, rel_build: str) -> Result:
    wrapper = project_dir / "gradlew"
    cmd0 = str(wrapper) if wrapper.is_file() and os.access(wrapper, os.X_OK) else shutil.which("gradle")
    if cmd0 is None:
        return None, f"{rel_build}: --resolve needs Gradle on PATH or an executable ./gradlew"
    tasks = ["dependencies"] + [f"{p}:dependencies" for p in _gradle_projects(cmd0, project_dir)]
    try:
        proc = _run([cmd0, "-q", "--console=plain", *tasks], project_dir)
    except (OSError, subprocess.TimeoutExpired) as e:
        return None, f"{rel_build}: Gradle could not run ({e})"
    if proc.returncode != 0:
        return None, f"{rel_build}: gradle dependencies failed: {_tail(proc)}"
    return parse_gradle_report(rel_build, proc.stdout or ""), None


def _pip_command() -> List[str]:
    return [sys.executable, "-m", "pip"]


def parse_pip_report(path: str, text: str) -> DependencyFile:
    """`pip install --dry-run --report`: every distribution pip would install, which ones were
    requested, and their `Requires-Dist` (edges to the ones in the same report)."""
    df = DependencyFile(path, PYPI, "resolved")
    data = json.loads(text)
    keys: Dict[str, str] = {}
    entries = [e for e in data.get("install", []) if isinstance(e, dict)]
    for e in entries:
        meta = e.get("metadata") or {}
        if meta.get("name") and meta.get("version"):
            keys[normalize_name(PYPI, meta["name"])] = df.add(
                Package(PYPI, meta["name"], str(meta["version"]), direct=bool(e.get("requested")))).key
    for e in entries:
        meta = e.get("metadata") or {}
        parent = keys.get(normalize_name(PYPI, meta.get("name", "")))
        for req in meta.get("requires_dist") or []:
            m = re.match(r"\s*([A-Za-z0-9][A-Za-z0-9._-]*)", req)
            child = keys.get(normalize_name(PYPI, m.group(1))) if m else None
            if parent and child:
                df.edge(parent, child)
    return df


def resolve_python(project_dir: Path, rel_manifest: str, requirements: Optional[Path] = None,
                   specs: Sequence[str] = ()) -> Result:
    """Resolve a requirements file (or the dependency strings of a pyproject) with pip's
    resolver, without installing. Only wheels are considered (`--only-binary :all:`), so no
    package's build code runs; a dependency available only as a source archive fails to resolve
    and is reported as a warning."""
    if requirements is None and not specs:
        return None, None
    with tempfile.TemporaryDirectory() as tmp:
        report = Path(tmp) / "report.json"
        cmd = [*_pip_command(), "install", "--dry-run", "--ignore-installed", "--quiet", "--disable-pip-version-check",
               "--only-binary", ":all:", "--report", str(report)]
        cmd += ["-r", str(requirements)] if requirements is not None else list(specs)
        try:
            proc = _run(cmd, project_dir)
        except (OSError, subprocess.TimeoutExpired) as e:
            return None, f"{rel_manifest}: pip could not run ({e})"
        if proc.returncode != 0 or not report.is_file():
            return None, f"{rel_manifest}: pip could not resolve it: {_tail(proc)}"
        try:
            return parse_pip_report(rel_manifest, report.read_text(encoding="utf-8")), None
        except ValueError as e:
            return None, f"{rel_manifest}: unreadable pip report ({e})"


RESOLVERS: Dict[str, Callable[..., Result]] = {
    "maven": resolve_maven, "gradle": resolve_gradle, "python": resolve_python,
}
