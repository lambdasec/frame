"""Real-tool tests for `frame deps`: ground truth comes from the package managers themselves.

Each `Case` copies a fixture project (`projects/`) to a temporary directory, has the real tool
generate the lockfile or report Frame reads, and asks the same tool what it resolved
(`npm ls`, `mvn dependency:list`, `cargo metadata`, a Gradle init script, ...). Frame's reading
of the generated files must then match that answer: the same (name, version) set, the same
direct dependencies and the same dev-only packages, wherever the tool distinguishes them.

Live runs (`tests/test_sca_real_tools.py`, `FRAME_SCA_REAL=1`) use the tools on PATH; with
`FRAME_SCA_REAL_DOCKER=1`, the JVM, .NET and Go tools run in their official images instead.
`python -m tests.sca_real.refresh` reruns every case and rewrites the offline corpus
(`tests/fixtures/sca/real/`), which `tests/test_sca_real_corpus.py` checks with no tools.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Dict, List, Optional, Sequence, Set, Tuple

from frame.sca import read_dependencies
from frame.sca.lockfiles import _swift_name
from frame.sca.model import CARGO, GO, HEX, MAVEN, NPM, NUGET, PACKAGIST, PUB, PYPI, RUBYGEMS, SWIFT, normalize_name
from frame.sca.resolve import parse_pip_report

HERE = Path(__file__).resolve().parent
PROJECTS = HERE / "projects"
CORPUS = HERE.parent / "fixtures" / "sca" / "real"
SECBENCH = HERE.parents[1] / "benchmarks" / "cache" / "secbench_real" / "pkgs"
TIMEOUT = 1200

NV = Tuple[str, str]


def docker_mode() -> bool:
    return os.environ.get("FRAME_SCA_REAL_DOCKER", "") not in ("", "0")


class ToolError(RuntimeError):
    pass


# ---------------------------------------------------------------------------------------------
# running tools

_CACHES = {   # docker image -> named volume for its download cache (keeps reruns fast)
    "maven": ("frame-sca-m2", "/root/.m2"),
    "gradle": ("frame-sca-gradle", "/home/gradle/.gradle"),
    "golang": ("frame-sca-go", "/go/pkg/mod"),
    "mcr.microsoft.com/dotnet/sdk": ("frame-sca-nuget", "/root/.nuget"),
    "ruby": ("frame-sca-gems", "/usr/local/bundle"),
    "composer": ("frame-sca-composer", "/tmp/composer-cache"),
    "dart": ("frame-sca-pub", "/root/.pub-cache"),
    "elixir": ("frame-sca-hex", "/root/.hex"),
}


def docker_prefix(image: str, cwd: Path) -> List[str]:
    cmd = ["docker", "run", "--rm", "-v", f"{cwd}:{cwd}", "-w", str(cwd)]
    # the temporary directory under both of its spellings (macOS: /var/folders is a symlink to
    # /private/var/folders), since paths passed to the tool may use either
    raw = Path(tempfile.gettempdir())
    tmp = raw.resolve()
    for alias in {tmp, raw}:
        if alias != cwd and alias not in cwd.parents:
            cmd += ["-v", f"{tmp}:{alias}"]
        elif alias != tmp:
            cmd += ["-v", f"{tmp}:{alias}"]
    for key, (vol, path) in _CACHES.items():
        if image.startswith(key):
            cmd += ["-v", f"{vol}:{path}"]
    if image.startswith("gradle"):
        cmd += ["-e", "GRADLE_USER_HOME=/home/gradle/.gradle"]
    return cmd + [image]


def run(cmd: Sequence[str], cwd: Path, image: Optional[str] = None, env: Optional[Dict[str, str]] = None,
        stdout_file: Optional[Path] = None) -> str:
    full = list(cmd)
    if image and docker_mode():
        full = docker_prefix(image, cwd.resolve()) + full
    e = {**os.environ, "COREPACK_ENABLE_DOWNLOAD_PROMPT": "0", "CI": "1", **(env or {})}
    proc = subprocess.run(full, cwd=str(cwd), capture_output=True, text=True, timeout=TIMEOUT, env=e)
    if proc.returncode != 0:
        tail = "\n".join((proc.stderr or proc.stdout or "").strip().splitlines()[-15:])
        raise ToolError(f"{' '.join(full)} (exit {proc.returncode}):\n{tail}")
    if stdout_file is not None:
        stdout_file.write_text(proc.stdout)
    return proc.stdout


def corepack(pm: str) -> List[str]:
    return ["corepack", pm]


# ---------------------------------------------------------------------------------------------
# ground truth and comparison

@dataclass
class Truth:
    packages: Set[NV]
    direct: Optional[Set[str]] = None          # normalised names; None: the tool does not say
    dev: Optional[Set[NV]] = None              # dev-only packages; None: the tool does not say
    relation: str = "equal"                    # "equal" | "truth-within-frame" (see note)
    note: str = ""

    def to_json(self) -> dict:
        return {"packages": sorted(map(list, self.packages)),
                "direct": sorted(self.direct) if self.direct is not None else None,
                "dev": sorted(map(list, self.dev)) if self.dev is not None else None,
                "relation": self.relation, "note": self.note}

    @classmethod
    def from_json(cls, d: dict) -> "Truth":
        return cls(packages={tuple(x) for x in d["packages"]},
                   direct=set(d["direct"]) if d.get("direct") is not None else None,
                   dev={tuple(x) for x in d["dev"]} if d.get("dev") is not None else None,
                   relation=d.get("relation", "equal"), note=d.get("note", ""))


def frame_view(files, ecosystem: str) -> Tuple[Set[NV], Set[str], Set[NV]]:
    pkgs: Set[NV] = set()
    direct: Set[str] = set()
    dev_flags: Dict[NV, bool] = {}
    for f in files:
        for p in f.packages.values():
            if p.ecosystem != ecosystem or not p.version:
                continue
            nv = (normalize_name(ecosystem, p.name), p.version)
            pkgs.add(nv)
            if p.direct:
                direct.add(nv[0])
            dev_flags[nv] = dev_flags.get(nv, True) and p.dev
    return pkgs, direct, {nv for nv, d in dev_flags.items() if d}


def compare(truth: Truth, files, ecosystem: str) -> List[str]:
    pkgs, direct, dev = frame_view(files, ecosystem)
    problems: List[str] = []
    if truth.relation == "equal":
        if pkgs != truth.packages:
            problems.append(f"packages: missing {sorted(truth.packages - pkgs)[:12]}, "
                            f"extra {sorted(pkgs - truth.packages)[:12]}")
    elif truth.relation == "truth-within-frame":
        if not truth.packages <= pkgs:
            problems.append(f"packages the tool builds with but Frame lacks: {sorted(truth.packages - pkgs)[:12]}")
    else:
        problems.append(f"unknown relation {truth.relation}")
    if truth.direct is not None and direct != truth.direct:
        problems.append(f"direct: missing {sorted(truth.direct - direct)}, extra {sorted(direct - truth.direct)}")
    if truth.dev is not None and dev != truth.dev:
        problems.append(f"dev only: missing {sorted(truth.dev - dev)[:12]}, extra {sorted(dev - truth.dev)[:12]}")
    return problems


def _nv(eco: str, name: str, version: str) -> NV:
    return normalize_name(eco, name), version


# ---------------------------------------------------------------------------------------------
# cases

@dataclass
class Case:
    name: str
    ecosystem: str
    project: Optional[str]                       # directory under projects/ (None: `source` is set)
    tools: Tuple[str, ...]                       # executables needed when not running in docker
    generate: Callable[[Path], None]
    truth: Callable[[Path], Truth]
    keep: Tuple[str, ...]                        # files (globs) Frame reads, kept for the corpus
    image: Optional[str] = None                  # docker image for FRAME_SCA_REAL_DOCKER=1
    resolve: bool = False                        # also check `read_dependencies(resolve=True)`
    source: Optional[Path] = None                # a real project to copy instead of projects/<project>
    pip_report: bool = False                     # the corpus keeps a pip report (resolve cases)
    frame_dirs: Tuple[str, ...] = (".",)         # subdirectories read separately (all must match)
    extra: Dict[str, str] = field(default_factory=dict)

    def required_tools(self) -> Tuple[str, ...]:
        return ("docker",) if (self.image and docker_mode()) else self.tools

    def missing_tools(self) -> List[str]:
        return [t for t in self.required_tools() if shutil.which(t) is None]


def prepare(case: Case, dest: Path) -> Path:
    src = case.source if case.source is not None else PROJECTS / case.project
    work = dest / case.name
    shutil.copytree(src, work, ignore=shutil.ignore_patterns("node_modules", ".yarn", "target", "build",
                                                              ".gradle", "obj", "bin", ".build"))
    if case.name.startswith("gradle"):
        shutil.copy(PROJECTS / "gradle-truth.gradle", work / "frame-truth.gradle")
    return work


# --- npm family ------------------------------------------------------------------------------

def _npm_tree(node: dict, out: Set[NV]) -> None:
    for name, meta in (node.get("dependencies") or {}).items():
        if isinstance(meta, dict) and meta.get("version"):
            out.add(_nv(NPM, name, meta["version"]))
            _npm_tree(meta, out)


def _package_json_names(work: Path) -> Set[str]:
    data = json.loads((work / "package.json").read_text())
    return {n for s in ("dependencies", "devDependencies", "optionalDependencies") for n in (data.get(s) or {})}


def npm_generate(work: Path) -> None:
    run(["npm", "install", "--package-lock-only", "--ignore-scripts", "--no-audit", "--no-fund"], work)


def npm_truth(work: Path) -> Truth:
    every: Set[NV] = set()
    prod: Set[NV] = set()
    _npm_tree(json.loads(run(["npm", "ls", "--all", "--json", "--package-lock-only"], work)), every)
    _npm_tree(json.loads(run(["npm", "ls", "--all", "--json", "--package-lock-only", "--omit=dev"], work)), prod)
    return Truth(every, direct=_package_json_names(work), dev=every - prod)


YARN1 = "yarn@1.22.22"
YARN4 = "yarn@4.5.3"


def yarn1_generate(work: Path) -> None:
    run(corepack(YARN1) + ["install", "--ignore-scripts", "--non-interactive", "--no-progress"], work)


def _yarn1_tree(nodes: list, out: Set[NV]) -> None:
    for n in nodes or []:
        if not n.get("shadow"):              # a shadow entry names a range resolved elsewhere in the tree
            name, _, version = n["name"].rpartition("@")
            out.add(_nv(NPM, name, version))
        _yarn1_tree(n.get("children"), out)


def yarn1_truth(work: Path) -> Truth:
    every: Set[NV] = set()
    for line in run(corepack(YARN1) + ["list", "--json", "--no-progress"], work).splitlines():
        doc = json.loads(line)
        if doc.get("type") == "tree":
            _yarn1_tree(doc["data"]["trees"], every)
    return Truth(every, direct=_package_json_names(work),
                 note="yarn classic does not say which packages are dev only")


def yarn4_generate(work: Path) -> None:
    (work / ".yarnrc.yml").write_text("nodeLinker: node-modules\nenableTelemetry: false\n")
    run(corepack(YARN4) + ["install", "--mode=skip-build"], work, env={"YARN_ENABLE_IMMUTABLE_INSTALLS": "false"})


def yarn4_truth(work: Path) -> Truth:
    every: Set[NV] = set()
    for line in run(corepack(YARN4) + ["info", "--all", "--recursive", "--json"], work).splitlines():
        doc = json.loads(line)
        value = doc.get("value", "")
        if "@workspace:" in value:
            continue
        name = value[: value.find("@", 1)]
        every.add(_nv(NPM, name, doc["children"]["Version"]))
    return Truth(every, direct=_package_json_names(work),
                 note="yarn berry's info does not say which packages are dev only")


def _pnpm_collect(tree: dict, out: Set[NV]) -> None:
    for name, meta in (tree or {}).items():
        v = meta.get("version", "")
        if v and not v.startswith(("link:", "file:")):
            out.add(_nv(NPM, name, v))
        _pnpm_collect(meta.get("dependencies"), out)


def pnpm_generate(pm: str) -> Callable[[Path], None]:
    def gen(work: Path) -> None:
        run(corepack(pm) + ["install", "--ignore-scripts", "--config.confirmModulesPurge=false"], work)
    return gen


def pnpm_truth(pm: str) -> Callable[[Path], Truth]:
    def truth(work: Path) -> Truth:
        every: Set[NV] = set()
        prod: Set[NV] = set()
        for doc in json.loads(run(corepack(pm) + ["list", "--depth", "Infinity", "--json"], work)):
            for section in ("dependencies", "devDependencies", "optionalDependencies"):
                _pnpm_collect(doc.get(section), every)
        for doc in json.loads(run(corepack(pm) + ["list", "--prod", "--depth", "Infinity", "--json"], work)):
            for section in ("dependencies", "optionalDependencies"):
                _pnpm_collect(doc.get(section), prod)
        return Truth(every, direct=_package_json_names(work), dev=every - prod)
    return truth


# --- Python ----------------------------------------------------------------------------------

def _venv_python(venv: Path) -> Path:
    return venv / ("Scripts" if os.name == "nt" else "bin") / ("python.exe" if os.name == "nt" else "python")


def pip_generate(work: Path) -> None:
    """The report Frame's --resolve reads, from the same real pip command (kept for the corpus)."""
    run([sys.executable, "-m", "pip", "install", "--dry-run", "--ignore-installed", "--quiet",
         "--disable-pip-version-check", "--only-binary", ":all:", "--report", str(work / "pip-report.json"),
         "-r", "requirements.txt"], work)


def pip_truth(work: Path) -> Truth:
    """A real install into a fresh virtual environment, then pip's own list of it."""
    venv = work.parent / f"{work.name}-venv"
    run([sys.executable, "-m", "venv", str(venv)], work)
    py = str(_venv_python(venv))
    run([py, "-m", "pip", "install", "--quiet", "--disable-pip-version-check", "--only-binary", ":all:",
         "-r", "requirements.txt"], work)
    listed = json.loads(run([py, "-m", "pip", "list", "--format", "json", "--disable-pip-version-check",
                             "--exclude", "pip", "--exclude", "setuptools"], work))
    every = {_nv(PYPI, d["name"], d["version"]) for d in listed}
    names = set()
    for line in (work / "requirements.txt").read_text().splitlines():
        m = re.match(r"\s*([A-Za-z0-9][A-Za-z0-9._-]*)", line)
        if m:
            names.add(normalize_name(PYPI, m.group(1)))
    return Truth(every, direct=names)


# Poetry with its official export plugin, run through uvx so every machine uses the same
# versions. `poetry show` lists only what applies to the running interpreter; `poetry export`
# keeps every locked package with its markers, which is what a lockfile (and Frame) describes.
POETRY = ["uvx", "--from", "poetry==2.1.3", "--with", "poetry-plugin-export==1.9.0", "poetry"]


def poetry_generate(work: Path) -> None:
    run(POETRY + ["lock", "--no-interaction"], work)


def _poetry_show(work: Path, *extra: str) -> Set[NV]:
    out: Set[NV] = set()
    for line in run(POETRY + ["show", "--no-ansi", "--no-interaction", *extra], work).splitlines():
        tok = line.split()
        if len(tok) < 2:
            continue
        version = tok[2] if tok[1] == "(!)" and len(tok) > 2 else tok[1]
        out.add(_nv(PYPI, tok[0], version))
    return out


def poetry_truth(work: Path) -> Truth:
    base = POETRY + ["export", "--format", "requirements.txt", "--without-hashes", "--no-interaction"]
    every = _requirements_pins(run(base + ["--all-groups"], work))
    prod = _requirements_pins(run(base + ["--only", "main"], work))
    top = {n for n, _ in _poetry_show(work, "--top-level")}
    return Truth(every, direct=top, dev=every - prod)


def _requirements_pins(text: str) -> Set[NV]:
    out: Set[NV] = set()
    for line in text.splitlines():
        m = re.match(r"^([A-Za-z0-9][A-Za-z0-9._-]*)==([^\s;\\]+)", line.strip())
        if m:
            out.add(_nv(PYPI, m.group(1), m.group(2)))
    return out


def uv_generate(work: Path) -> None:
    run(["uv", "lock"], work)


def uv_truth(work: Path) -> Truth:
    base = ["uv", "export", "--format", "requirements-txt", "--no-hashes", "--no-emit-project", "--frozen",
            "--no-header"]
    every = _requirements_pins(run(base + ["--all-groups"], work))
    prod = _requirements_pins(run(base + ["--no-dev"], work))
    direct = set()
    for line in run(["uv", "tree", "--depth", "1", "--frozen", "--all-groups"], work).splitlines():
        m = re.match(r"^[├└]── ([A-Za-z0-9][A-Za-z0-9._-]*) v", line)
        if m:
            direct.add(normalize_name(PYPI, m.group(1)))
    return Truth(every, direct=direct, dev=every - prod)


def pdm_generate(work: Path) -> None:
    run(["uvx", "pdm", "lock", "-G", ":all"], work, env={"PDM_CHECK_UPDATE": "false"})


def pdm_truth(work: Path) -> Truth:
    env = {"PDM_CHECK_UPDATE": "false"}
    # markers kept: without them pdm drops what does not apply to the running interpreter
    base = ["uvx", "pdm", "export", "-f", "requirements", "--without-hashes"]
    every = _requirements_pins(run(base + ["-G", ":all"], work, env=env))
    prod = _requirements_pins(run(base + ["--prod"], work, env=env))
    return Truth(every, direct={"flask", "requests", "pytest"}, dev=every - prod,
                 note="direct = the names pyproject.toml declares (pdm does not list them)")


def pipenv_generate(work: Path) -> None:
    run(["uvx", "pipenv", "lock"], work, env={"PIPENV_VENV_IN_PROJECT": "1", "PIPENV_YES": "1",
                                             "PIPENV_NOSPIN": "1", "PIPENV_VERBOSITY": "-1"})


def pipenv_truth(work: Path) -> Truth:
    env = {"PIPENV_VENV_IN_PROJECT": "1", "PIPENV_VERBOSITY": "-1"}
    prod = _requirements_pins(run(["uvx", "pipenv", "requirements"], work, env=env))
    every = _requirements_pins(run(["uvx", "pipenv", "requirements", "--dev"], work, env=env))
    return Truth(every, direct={"flask", "requests", "pytest"}, dev=every - prod,
                 note="direct = the names the Pipfile declares")


# --- Maven -----------------------------------------------------------------------------------

MAVEN_IMAGE = "maven:3-eclipse-temurin-21"
_MVN_LIST = re.compile(r"^\s*([\w.\-]+):([\w.\-]+):[\w.\-]+(?::[\w.\-]+)?:([\w.\-+]+):(compile|runtime|provided|test|system|import)\b")


def mvn_generate(work: Path) -> None:
    run(["mvn", "-B", "-q", "dependency:tree", f"-DoutputFile={work / 'maven_dep_tree.txt'}",
         "-DappendOutput=true"], work, image=MAVEN_IMAGE)


def mvn_generate_json(work: Path) -> None:
    run(["mvn", "-B", "-q", "org.apache.maven.plugins:maven-dependency-plugin:3.8.1:tree", "-DoutputType=json",
         f"-DoutputFile={work / 'maven_dep_tree.json'}", "-DappendOutput=true"], work, image=MAVEN_IMAGE)


def _mvn_list(work: Path, *extra: str) -> List[Tuple[NV, str]]:
    out_file = work / f"frame-list-{len(extra)}.txt"
    if out_file.exists():
        out_file.unlink()
    run(["mvn", "-B", "-q", "dependency:list", f"-DoutputFile={out_file}", "-DappendOutput=true",
         "-DoutputAbsoluteArtifactFilename=false", *extra], work, image=MAVEN_IMAGE)
    rows = []
    for line in out_file.read_text().splitlines():
        m = _MVN_LIST.match(line)
        if m:
            rows.append(((f"{m.group(1)}:{m.group(2)}", m.group(3)), m.group(4)))
    out_file.unlink()
    return rows


def mvn_truth(work: Path) -> Truth:
    rows = _mvn_list(work)
    every = {nv for nv, _ in rows}
    prod = {nv for nv, scope in rows if scope != "test"}
    direct = {nv[0] for nv, _ in _mvn_list(work, "-DexcludeTransitive=true")}
    return Truth(every, direct=direct, dev=every - prod)


# --- Gradle ----------------------------------------------------------------------------------

GRADLE_IMAGE = "gradle:8-jdk21"


def gradle_cmd() -> List[str]:
    return ["gradle", "-q", "--console=plain", "--no-daemon"]


def gradle_generate(write_locks: bool) -> Callable[[Path], None]:
    def gen(work: Path) -> None:
        extra = ["--write-locks"] if write_locks else []
        run(gradle_cmd() + ["dependencies", ":lib:dependencies", *extra], work, image=GRADLE_IMAGE,
            stdout_file=work / "gradle-dependencies.txt")
    return gen


def gradle_truth(work: Path) -> Truth:
    out = run(gradle_cmd() + ["--init-script", "frame-truth.gradle", "frameTruth"], work, image=GRADLE_IMAGE)
    every: Set[NV] = set()
    prod: Set[NV] = set()
    direct: Set[str] = set()
    for line in out.splitlines():
        tok = line.split()
        if len(tok) == 3 and tok[0] == "FRAME":
            g, a, v = tok[2].split(":")
            every.add((f"{g}:{a}", v))
            if tok[1] == "main":
                prod.add((f"{g}:{a}", v))
        elif len(tok) == 2 and tok[0] == "FRAMEDIRECT":
            g, a, _ = tok[1].split(":")
            direct.add(f"{g}:{a}")
    return Truth(every, direct=direct, dev=every - prod)


def gradle_lock_truth(work: Path) -> Truth:
    t = gradle_truth(work)
    return Truth(t.packages, direct=None, dev=t.dev,
                 note="a gradle.lockfile does not say which modules are direct")


# --- .NET ------------------------------------------------------------------------------------

DOTNET_IMAGE = "mcr.microsoft.com/dotnet/sdk:8.0"
_DOTNET_ENV = {"DOTNET_CLI_TELEMETRY_OPTOUT": "1", "DOTNET_NOLOGO": "1", "DOTNET_SKIP_FIRST_TIME_EXPERIENCE": "1"}


def _dotnet_project(work: Path) -> List[str]:
    """The project to name on the command line when it is not in the working directory."""
    if any(work.glob("*.csproj")):
        return []
    return [str(next(work.rglob("*.csproj")).relative_to(work))]


def dotnet_generate(lock: bool) -> Callable[[Path], None]:
    def gen(work: Path) -> None:
        run(["dotnet", "restore", *_dotnet_project(work)] + (["--use-lock-file"] if lock else []), work,
            image=DOTNET_IMAGE, env=_DOTNET_ENV)
    return gen


def dotnet_truth(work: Path) -> Truth:
    data = json.loads(run(["dotnet", "list", *_dotnet_project(work), "package", "--include-transitive",
                           "--format", "json"], work, image=DOTNET_IMAGE, env=_DOTNET_ENV))
    every: Set[NV] = set()
    direct: Set[str] = set()
    for proj in data.get("projects", []):
        for fw in proj.get("frameworks", []):
            for p in fw.get("topLevelPackages", []):
                every.add(_nv(NUGET, p["id"], p["resolvedVersion"]))
                direct.add(normalize_name(NUGET, p["id"]))
            for p in fw.get("transitivePackages", []):
                every.add(_nv(NUGET, p["id"], p["resolvedVersion"]))
    return Truth(every, direct=direct, note="dotnet list does not say which packages are dev only")


def dotnet_manifest_truth(work: Path) -> Truth:
    """What the project files alone say: the top-level packages, at the versions NuGet chose
    for them (central versions and VersionOverride applied by NuGet itself)."""
    t = dotnet_truth(work)
    data = json.loads(run(["dotnet", "list", *_dotnet_project(work), "package", "--format", "json"], work,
                          image=DOTNET_IMAGE, env=_DOTNET_ENV))
    top = {_nv(NUGET, p["id"], p["resolvedVersion"]) for proj in data.get("projects", [])
           for fw in proj.get("frameworks", []) for p in fw.get("topLevelPackages", [])}
    return Truth(top, direct=t.direct, note="a .csproj names only its own references")


# --- Go, Rust, Swift -------------------------------------------------------------------------

GO_IMAGE = "golang:1.22"


def go_generate(work: Path) -> None:
    run(["go", "mod", "tidy"], work, image=GO_IMAGE, env={"GOFLAGS": "-mod=mod", "GOTOOLCHAIN": "local"})


def go_truth(work: Path) -> Truth:
    env = {"GOTOOLCHAIN": "local"}
    mod = json.loads(run(["go", "mod", "edit", "-json"], work, image=GO_IMAGE, env=env))
    replace = {r["Old"]["Path"]: r["New"] for r in mod.get("Replace") or []}
    every: Set[NV] = set()
    direct: Set[str] = set()
    for r in mod.get("Require") or []:
        new = replace.get(r["Path"])
        if new is not None and not new.get("Version"):
            continue
        path, version = (new["Path"], new["Version"]) if new else (r["Path"], r["Version"])
        every.add((path, version.lstrip("v")))
        if not r.get("Indirect"):
            direct.add(path)
    # the modules the build and the tests actually load must all be in Frame's list
    tmpl = ("{{with .Module}}{{if not .Main}}{{if .Replace}}{{.Replace.Path}} {{.Replace.Version}}"
            "{{else}}{{.Path}} {{.Version}}{{end}}{{end}}{{end}}")
    built = {tuple(line.split()) for line in run(["go", "list", "-deps", "-test", "-f", tmpl, "./..."], work,
                                                 image=GO_IMAGE, env=env).splitlines() if line.strip()}
    built = {(p, v.lstrip("v")) for p, v in built}
    missing = built - every
    if missing:
        raise ToolError(f"go list loads modules go.mod does not require: {sorted(missing)}")
    return Truth(every, direct=direct,
                 note="go.mod (Go 1.17+) lists every module the build needs; checked against `go list -deps -test`")


def cargo_generate(work: Path) -> None:
    run(["cargo", "generate-lockfile"], work)


def cargo_truth(work: Path) -> Truth:
    meta = json.loads(run(["cargo", "metadata", "--format-version", "1", "--locked"], work))
    by_id = {p["id"]: p for p in meta["packages"]}
    members = set(meta["workspace_members"])
    every = {(p["name"], p["version"]) for p in meta["packages"] if p["id"] not in members}
    nodes = {n["id"]: n for n in meta["resolve"]["nodes"]}
    direct: Set[str] = set()
    prod: Set[str] = set()
    stack = []
    for m in members:
        for d in nodes[m]["deps"]:
            direct.add(by_id[d["pkg"]]["name"])
            if any(k.get("kind") in (None, "build") for k in d["dep_kinds"]):
                stack.append(d["pkg"])
    while stack:
        pid = stack.pop()
        if pid in prod:
            continue
        prod.add(pid)
        for d in nodes[pid]["deps"]:
            if any(k.get("kind") in (None, "build") for k in d["dep_kinds"]):
                stack.append(d["pkg"])
    prod_nv = {(by_id[i]["name"], by_id[i]["version"]) for i in prod}
    return Truth(every, direct=direct, dev=every - prod_nv)


def swift_generate(work: Path) -> None:
    run(["swift", "package", "resolve"], work)


def swift_truth(work: Path) -> Truth:
    data = json.loads(run(["swift", "package", "show-dependencies", "--format", "json"], work))
    every: Set[NV] = set()

    def walk(deps):
        for d in deps or []:
            if d.get("version") and d["version"] != "unspecified":
                every.add((_swift_name(d["url"]), d["version"]))
            walk(d.get("dependencies"))
    walk(data.get("dependencies"))
    return Truth(every, note="Package.resolved does not say which packages are direct")


# --- Ruby, PHP, Dart, Elixir -----------------------------------------------------------------

RUBY_IMAGE, COMPOSER_IMAGE, DART_IMAGE, ELIXIR_IMAGE = "ruby:3.3", "composer:2", "dart:stable", "elixir:1.17"


def bundler_generate(work: Path) -> None:
    run(["bundle", "lock", "--add-platform", "x86_64-linux", "ruby"], work, image=RUBY_IMAGE)


# Bundler's own reading of the lockfile and the Gemfile: the specs from rubygems sources, the
# direct dependencies, and what the non-development groups reach through the specs' requirements
_BUNDLER_TRUTH = r"""
require "bundler"; require "json"
lock = Bundler::LockfileParser.new(Bundler.read_file("Gemfile.lock"))
gems = lock.specs.select { |s| s.source.is_a?(Bundler::Source::Rubygems) }
all = gems.map { |s| [s.name, s.version.to_s] }.uniq
dsl = Bundler::Dsl.new; dsl.eval_gemfile("Gemfile")
direct = dsl.dependencies.map(&:name) & gems.map(&:name)
dev = [:development, :test]
stack = dsl.dependencies.reject { |d| (d.groups - dev).empty? }.map(&:name)
by_name = lock.specs.group_by(&:name); reached = {}
while (n = stack.pop)
  next if reached[n]; reached[n] = true
  (by_name[n] || []).each { |s| s.dependencies.each { |d| stack << d.name } }
end
puts JSON.dump({all: all, direct: direct, dev: all.reject { |n, _| reached[n] }})
"""


def bundler_truth(work: Path) -> Truth:
    data = json.loads(run(["ruby", "-e", _BUNDLER_TRUTH], work, image=RUBY_IMAGE))
    every = {_nv(RUBYGEMS, n, v) for n, v in data["all"]}
    return Truth(every, direct={normalize_name(RUBYGEMS, n) for n in data["direct"]},
                 dev={_nv(RUBYGEMS, n, v) for n, v in data["dev"]},
                 note="Bundler's LockfileParser and Dsl; dev = not reached from a non-dev group")


_COMPOSER_ENV = {"COMPOSER_CACHE_DIR": "/tmp/composer-cache"}


def composer_generate(work: Path) -> None:
    run(["composer", "update", "--no-install", "--no-scripts", "--no-plugins", "--no-interaction"], work,
        image=COMPOSER_IMAGE, env=_COMPOSER_ENV)


def _composer_show(work: Path, *extra: str) -> List[dict]:
    out = run(["composer", "show", "--locked", "--format=json", "--no-plugins", *extra], work,
              image=COMPOSER_IMAGE, env=_COMPOSER_ENV)
    return json.loads(out).get("locked", [])


def composer_truth(work: Path) -> Truth:
    every = {_nv(PACKAGIST, p["name"], p["version"]) for p in _composer_show(work)}
    prod = {_nv(PACKAGIST, p["name"], p["version"]) for p in _composer_show(work, "--no-dev")}
    direct = {normalize_name(PACKAGIST, p["name"]) for p in _composer_show(work, "--direct")}
    return Truth(every, direct=direct, dev=every - prod, note="composer show --locked (--no-dev, --direct)")


def pub_generate(work: Path) -> None:
    run(["dart", "pub", "get"], work, image=DART_IMAGE)


def pub_truth(work: Path) -> Truth:
    data = json.loads(run(["dart", "pub", "deps", "--json"], work, image=DART_IMAGE))
    pkgs = [p for p in data.get("packages", []) if p.get("kind") != "root" and p.get("source") == "hosted"]
    every = {_nv(PUB, p["name"], p["version"]) for p in pkgs}
    return Truth(every, direct={p["name"] for p in pkgs if p.get("kind") in ("direct", "dev")},
                 dev={_nv(PUB, p["name"], p["version"]) for p in pkgs if p.get("kind") == "dev"},
                 note="dart pub deps --json; pub labels only direct dev dependencies dev")


def mix_generate(work: Path) -> None:
    run(["sh", "-c", "mix local.hex --force >/dev/null && mix deps.get"], work, image=ELIXIR_IMAGE)


# Mix's own reading: Mix.Dep.Lock for packages and their (non-optional) requirements, the project
# config for the deps list and its `only:` environments
_MIX_TRUTH = r"""
lock = Mix.Dep.Lock.read()
for {app, t} <- lock, elem(t, 0) == :hex do
  IO.puts("pkg #{app} #{elem(t, 1)} #{elem(t, 2)}")
  for {dep, _req, opts} <- elem(t, 5), !Keyword.get(opts, :optional, false), do: IO.puts("edge #{app} #{dep}")
end
for d <- Mix.Project.config()[:deps] do
  {app, opts} = case d do
    {a, _req, o} when is_list(o) -> {a, o}
    {a, o} when is_list(o) -> {a, o}
    {a, _req} -> {a, []}
  end
  only = opts |> Keyword.get(:only, []) |> List.wrap()
  IO.puts("direct #{app} #{if only != [] and :prod not in only, do: "dev", else: "prod"}")
end
"""


def mix_truth(work: Path) -> Truth:
    (work / "frame_truth.exs").write_text(_MIX_TRUTH)
    out = run(["sh", "-c", "mix local.hex --force >/dev/null && "
                           "mix run --no-start --no-compile --no-deps-check frame_truth.exs"], work, image=ELIXIR_IMAGE)
    pkgs: Dict[str, NV] = {}
    edges: Dict[str, List[str]] = {}
    direct: Dict[str, str] = {}
    for line in out.splitlines():
        parts = line.split()
        if parts[:1] == ["pkg"]:
            pkgs[parts[1]] = _nv(HEX, parts[2], parts[3])
        elif parts[:1] == ["edge"]:
            edges.setdefault(parts[1], []).append(parts[2])
        elif parts[:1] == ["direct"]:
            direct[parts[1]] = parts[2]
    stack = [a for a, kind in direct.items() if kind == "prod"]
    reached: Set[str] = set()
    while stack:
        a = stack.pop()
        if a not in reached:
            reached.add(a)
            stack.extend(edges.get(a, []))
    every = set(pkgs.values())
    return Truth(every, direct={pkgs[a][0] for a in direct if a in pkgs},
                 dev={nv for a, nv in pkgs.items() if a not in reached},
                 note="Mix.Dep.Lock.read and the project's deps; optional requirements are not followed")


# --- real lockfiles from published packages --------------------------------------------------

def secbench_npm_truth(work: Path) -> Truth:
    """A lockfileVersion 1 file: `npm ls --package-lock-only` rebuilds only its top level from
    it, so the truth is what `npm ci` actually installs from the lockfile, listed from disk."""
    # --force: an old lockfile can pin a platform-only package (fsevents, macOS) as required,
    # and npm ci refuses it elsewhere; the lockfile still lists it, and so does Frame.
    # --ignore-scripts keeps it from being built.
    run(["npm", "ci", "--force", "--ignore-scripts", "--no-audit", "--no-fund"], work)
    every: Set[NV] = set()
    prod: Set[NV] = set()
    _npm_tree(json.loads(run(["npm", "ls", "--all", "--json"], work)), every)
    _npm_tree(json.loads(run(["npm", "ls", "--all", "--json", "--omit=dev"], work)), prod)
    return Truth(every, direct=_package_json_names(work), dev=every - prod,
                 note="a published package's own v1 lockfile, against what npm ci installs from it")


def secbench_yarn_generate(work: Path) -> None:
    run(corepack(YARN1) + ["install", "--frozen-lockfile", "--ignore-scripts", "--non-interactive",
                           "--no-progress", "--ignore-engines"], work)


CASES: List[Case] = [
    Case("npm-lock", NPM, "npm", ("npm",), npm_generate, npm_truth, ("package.json", "package-lock.json")),
    Case("yarn-classic", NPM, "npm", ("corepack",), yarn1_generate, yarn1_truth, ("package.json", "yarn.lock")),
    Case("yarn-berry", NPM, "npm", ("corepack",), yarn4_generate, yarn4_truth, ("package.json", "yarn.lock")),
    Case("pnpm-9", NPM, "npm", ("corepack",), pnpm_generate("pnpm@9.12.3"), pnpm_truth("pnpm@9.12.3"),
         ("package.json", "pnpm-lock.yaml")),
    Case("pnpm-8", NPM, "npm", ("corepack",), pnpm_generate("pnpm@8.15.9"), pnpm_truth("pnpm@8.15.9"),
         ("package.json", "pnpm-lock.yaml")),
    Case("pip-resolve", PYPI, "python-pip", (), pip_generate, pip_truth, ("requirements.txt", "pip-report.json"),
         resolve=True, pip_report=True),
    Case("poetry", PYPI, "python-poetry", ("uvx",), poetry_generate, poetry_truth, ("pyproject.toml", "poetry.lock")),
    Case("uv", PYPI, "python-uv", ("uv",), uv_generate, uv_truth, ("pyproject.toml", "uv.lock")),
    Case("pdm", PYPI, "python-pdm", ("uvx",), pdm_generate, pdm_truth, ("pyproject.toml", "pdm.lock")),
    Case("pipenv", PYPI, "python-pipenv", ("uvx",), pipenv_generate, pipenv_truth, ("Pipfile", "Pipfile.lock")),
    Case("maven-tree", MAVEN, "maven", ("mvn",), mvn_generate, mvn_truth,
         ("pom.xml", "api/pom.xml", "web/pom.xml", "maven_dep_tree.txt"), image=MAVEN_IMAGE, resolve=True),
    Case("maven-tree-json", MAVEN, "maven", ("mvn",), mvn_generate_json, mvn_truth,
         ("pom.xml", "api/pom.xml", "web/pom.xml", "maven_dep_tree.json"), image=MAVEN_IMAGE),
    Case("gradle-groovy", MAVEN, "gradle-groovy", ("gradle",), gradle_generate(False), gradle_truth,
         ("settings.gradle", "build.gradle", "lib/build.gradle", "gradle-dependencies.txt"),
         image=GRADLE_IMAGE, resolve=True),
    Case("gradle-kotlin", MAVEN, "gradle-kotlin", ("gradle",), gradle_generate(True), gradle_truth,
         ("settings.gradle.kts", "build.gradle.kts", "lib/build.gradle.kts", "gradle-dependencies.txt"),
         image=GRADLE_IMAGE),
    Case("gradle-lockfile", MAVEN, "gradle-kotlin", ("gradle",), gradle_generate(True), gradle_lock_truth,
         ("settings.gradle.kts", "build.gradle.kts", "lib/build.gradle.kts", "gradle.lockfile", "lib/gradle.lockfile"),
         image=GRADLE_IMAGE),
    Case("dotnet-lock", NUGET, "dotnet", ("dotnet",), dotnet_generate(True), dotnet_truth,
         ("App.csproj", "packages.lock.json"), image=DOTNET_IMAGE),
    Case("dotnet-assets", NUGET, "dotnet", ("dotnet",), dotnet_generate(False), dotnet_truth,
         ("App.csproj", "obj/project.assets.json"), image=DOTNET_IMAGE),
    Case("dotnet-central-manifest", NUGET, "dotnet-central", ("dotnet",), dotnet_generate(False),
         dotnet_manifest_truth, ("Directory.Packages.props", "src/Api/Api.csproj"), image=DOTNET_IMAGE),
    Case("dotnet-central-assets", NUGET, "dotnet-central", ("dotnet",), dotnet_generate(False), dotnet_truth,
         ("Directory.Packages.props", "src/Api/Api.csproj", "src/Api/obj/project.assets.json"), image=DOTNET_IMAGE),
    Case("go", GO, "go", ("go",), go_generate, go_truth, ("go.mod",), image=GO_IMAGE),
    Case("cargo", CARGO, "rust", ("cargo",), cargo_generate, cargo_truth, ("Cargo.toml", "Cargo.lock")),
    Case("swift", SWIFT, "swift", ("swift",), swift_generate, swift_truth, ("Package.resolved",)),
    Case("bundler", RUBYGEMS, "ruby", ("ruby", "bundle"), bundler_generate, bundler_truth,
         ("Gemfile", "Gemfile.lock"), image=RUBY_IMAGE),
    Case("composer", PACKAGIST, "php", ("composer",), composer_generate, composer_truth,
         ("composer.json", "composer.lock"), image=COMPOSER_IMAGE),
    Case("pub", PUB, "dart", ("dart",), pub_generate, pub_truth, ("pubspec.yaml", "pubspec.lock"), image=DART_IMAGE),
    Case("mix", HEX, "elixir", ("mix",), mix_generate, mix_truth, ("mix.exs", "mix.lock"), image=ELIXIR_IMAGE),
    # lockfiles real projects published (MIT; package.json and lockfile only, from the SecBench.js
    # packages): Frame reads them as shipped, the tool installs from them as shipped
    Case("real-npm-v1-fast-json-patch", NPM, "real-npm-v1-fast-json-patch", ("npm",), lambda w: None,
         secbench_npm_truth, ("package.json", "package-lock.json")),
    Case("real-yarn-v1-sahmat", NPM, "real-yarn-v1-sahmat", ("corepack",), secbench_yarn_generate, yarn1_truth,
         ("package.json", "yarn.lock")),
    Case("real-yarn-v1-whereis", NPM, "real-yarn-v1-whereis", ("corepack",), secbench_yarn_generate, yarn1_truth,
         ("package.json", "yarn.lock")),
]
BY_NAME = {c.name: c for c in CASES}


# ---------------------------------------------------------------------------------------------

def frame_files(case: Case, project: Path):
    """What Frame reads from the kept files (copied alone into a clean directory, so nothing
    the tool left behind, such as node_modules, can change the result)."""
    clean = project.parent / f"{project.name}-frame"
    if clean.exists():
        shutil.rmtree(clean)
    for pattern in case.keep:
        for src in project.glob(pattern):
            dst = clean / src.relative_to(project)
            dst.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(src, dst)
    if case.pip_report:
        return [parse_pip_report("requirements.txt", (clean / "pip-report.json").read_text())], clean
    return read_dependencies(clean).files, clean


def run_case(case: Case, tmp: Path) -> Tuple[Truth, Path, List[str]]:
    """Generate, take the tool's truth, compare Frame's plain read (and --resolve). Returns the
    truth, the clean directory of kept files, and the problems found."""
    work = prepare(case, tmp)
    case.generate(work)
    truth = case.truth(work)
    files, clean = frame_files(case, work)
    problems = [f"plain read: {p}" for p in compare(truth, files, case.ecosystem)]
    if case.resolve:
        fresh = prepare(case, tmp / "resolve")
        for leftover in ("pip-report.json", "maven_dep_tree.txt", "gradle-dependencies.txt"):
            if (fresh / leftover).exists():
                (fresh / leftover).unlink()
        with _tool_shims(case):
            report = read_dependencies(fresh, resolve=True)
        if report.warnings:
            problems.append(f"--resolve warnings: {report.warnings}")
        problems += [f"--resolve: {p}" for p in compare(truth, report.files, case.ecosystem)]
    return truth, clean, problems


class _tool_shims:
    """In docker mode, put `mvn` / `gradle` wrappers on PATH that run the official image, so
    `--resolve` (which looks the tools up on PATH) runs them for real."""

    def __init__(self, case: Case):
        self.case = case
        self.old_path: Optional[str] = None
        self.dir: Optional[tempfile.TemporaryDirectory] = None

    def __enter__(self):
        if not (docker_mode() and self.case.image):
            return self
        self.dir = tempfile.TemporaryDirectory()
        tool = {MAVEN_IMAGE: "mvn", GRADLE_IMAGE: "gradle"}.get(self.case.image)
        if tool:
            shim = Path(self.dir.name) / tool
            shim.write_text(f"#!{sys.executable}\nimport os, sys\nsys.path[:0] = [{str(HERE.parent)!r}, "
                            f"{str(HERE.parents[1])!r}]\n"
                            "from sca_real.harness import docker_prefix\nfrom pathlib import Path\n"
                            f"cmd = docker_prefix({self.case.image!r}, Path.cwd().resolve()) + [{tool!r}] + sys.argv[1:]\n"
                            "os.execvp(cmd[0], cmd)\n")
            shim.chmod(0o755)
            self.old_path = os.environ.get("PATH", "")
            os.environ["PATH"] = self.dir.name + os.pathsep + self.old_path
        return self

    def __exit__(self, *exc):
        if self.old_path is not None:
            os.environ["PATH"] = self.old_path
        if self.dir is not None:
            self.dir.cleanup()
