"""Configuration mitigations: a setting that stops a vulnerability without an upgrade
(fastjson's safeMode, Log4j's formatMsgNoLookups), and whether the project applies it.

The data is curated per advisory, from the advisory's own text and the library's source or
documentation, never from memory: `data/mitigations/<Ecosystem>.json` in Frame, plus
`mitigations/<Ecosystem>.json.gz` in the advisories dataset (which wins for the same advisory).
Each entry says which versions the setting exists in, and whether it is `complete` (the advisory
or the library says it stops this vulnerability) or partial, with the caveat.

Whether it is applied is read, never guessed, from where a running application gets it:
  - JVM system properties: `-Dkey=value` in a Dockerfile's CMD / ENTRYPOINT, in the JVM option
    variables (JAVA_TOOL_OPTIONS, JDK_JAVA_OPTIONS, _JAVA_OPTIONS, and the JAVA_OPTS convention)
    set by a Dockerfile, Compose, Kubernetes, a systemd unit or a shell script, in a `java`
    command line, or `System.setProperty("key", "value")` in Java source;
  - environment variables: Dockerfile ENV, Compose `environment`, Kubernetes container `env`,
    systemd `Environment=`, `.env` files, `export` in shell scripts;
  - properties files with the name the library reads (`fastjson.properties`);
  - Spring Boot properties (`spring-property`), as Spring's relaxed binding reads them:
    `application*.properties` / `application*.yml` / `bootstrap*` (YAML flattened to dotted
    keys), a `-D` system property, a `--key=value` argument on a `java` command line, or an
    environment variable (`MANAGEMENT_CLOUDFOUNDRY_ENABLED`: dots as `_`, dashes dropped);
  - a call (`ParserConfig.getGlobalInstance().setSafeMode(true)`), from the Java syntax tree.
Build-time settings (`.mvn/jvm.config`, `gradle.properties`, `RUN mvn -D...`) configure the
build's JVM, not the application's, and do not count.

A mitigation found is evidence with a location. It does not make Frame state `not_affected`:
a Dockerfile does not prove that is how the service runs. Record that decision in
`.frame/vex.toml` (justification `inline_mitigations_already_exist`).
"""

from __future__ import annotations

import gzip
import json
import re
import shlex
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Dict, Iterable, Iterator, List, Optional, Set, Tuple
from typing import TYPE_CHECKING

if TYPE_CHECKING:                                     # pragma: no cover
    from frame.sca.apply import Change

KINDS = ("jvm-property", "env", "properties-file", "java-call", "spring-property")
JVM_OPTION_VARS = ("JAVA_TOOL_OPTIONS", "JDK_JAVA_OPTIONS", "_JAVA_OPTIONS", "JAVA_OPTS")


class MitigationError(ValueError):
    pass


def mitigations_path(ecosystem: str) -> str:
    return f"mitigations/{ecosystem}.json.gz"


# ---------------------------------------------------------------------------------------------
# data

def check(data, origin: str) -> Dict[str, List[dict]]:
    """{advisory id: [entry]}, strictly validated."""
    if not isinstance(data, dict):
        raise MitigationError(f"{origin}: expected {{advisory id: [mitigation]}}")
    keys = {"package", "versions", "complete", "summary", "caveat", "ways", "references"}
    for adv, entries in data.items():
        if not isinstance(entries, list) or not entries:
            raise MitigationError(f"{origin}: {adv}: a non-empty list of mitigations")
        for e in entries:
            if not isinstance(e, dict) or set(e) - keys:
                raise MitigationError(f"{origin}: {adv}: unknown keys {sorted(set(e) - keys) if isinstance(e, dict) else e}")
            for k in ("package", "versions", "summary"):
                if not isinstance(e.get(k), str) or not e[k]:
                    raise MitigationError(f"{origin}: {adv}: `{k}` is required")
            if not isinstance(e.get("complete"), bool):
                raise MitigationError(f"{origin}: {adv}: `complete` must be true or false")
            if not e["complete"] and not e.get("caveat"):
                raise MitigationError(f"{origin}: {adv}: a partial mitigation needs a `caveat`")
            if not isinstance(e.get("references"), list) or not e["references"]:
                raise MitigationError(f"{origin}: {adv}: `references` (the evidence) is required")
            ways = e.get("ways")
            if not isinstance(ways, list) or not ways:
                raise MitigationError(f"{origin}: {adv}: `ways` is required")
            for w in ways:
                if not isinstance(w, dict) or w.get("kind") not in KINDS:
                    raise MitigationError(f"{origin}: {adv}: a way's kind must be one of {KINDS}")
                need = {"jvm-property": ("key", "value"), "env": ("key", "value"),
                        "properties-file": ("file", "key", "value"),
                        "java-call": ("receiver", "method", "args"),
                        "spring-property": ("key", "value")}[w["kind"]]
                if any(k not in w for k in need):
                    raise MitigationError(f"{origin}: {adv}: a {w['kind']} way needs {need}")
    return data


@lru_cache(maxsize=None)
def builtin(ecosystem: str) -> Dict[str, List[dict]]:
    p = Path(__file__).parent / "data" / "mitigations" / f"{ecosystem}.json"
    if not p.is_file():
        return {}
    return check(json.loads(p.read_text(encoding="utf-8")), str(p))


def load(ecosystem: str, revision_dir: Optional[Path]) -> Dict[str, List[dict]]:
    out = dict(builtin(ecosystem))
    f = revision_dir / mitigations_path(ecosystem) if revision_dir is not None else None
    if f is not None and f.is_file():
        out.update(check(json.loads(gzip.decompress(f.read_bytes())).get("mitigations", {}), str(f)))
    return out


# ---------------------------------------------------------------------------------------------
# what the project sets

@dataclass(frozen=True)
class Setting:
    kind: str                  # "jvm-property" | "env" | "properties-file" | "java-call" | "spring-property"
    key: str                   # property / variable name; for a properties file "<file>:<key>"; for a call "<receiver>.<method>"
    value: str
    location: str              # "path:line"
    via: str = ""              # how: "Dockerfile CMD", "JAVA_TOOL_OPTIONS", "System.setProperty", ...


def _d_props(tokens: Iterable[str], loc: str, via: str) -> Iterator[Setting]:
    for t in tokens:
        m = re.fullmatch(r"-D([\w.\-]+)=(.*)", t)
        if m:
            yield Setting("jvm-property", m.group(1), m.group(2), loc, via)
        m = re.fullmatch(r"--([A-Za-z][\w.\-\[\]]*)=(.*)", t)   # a Spring Boot command-line argument
        if m:
            yield Setting("spring-property", m.group(1), m.group(2), loc, f"{via} argument")


def _split(text: str) -> List[str]:
    try:
        return shlex.split(text, comments=False, posix=True)
    except ValueError:
        return text.split()


def _env_settings(key: str, value: str, loc: str, via: str) -> Iterator[Setting]:
    yield Setting("env", key, value, loc, via)
    if key in JVM_OPTION_VARS:
        yield from _d_props(_split(value), loc, key)


def _is_java_command(tokens: List[str]) -> bool:
    return any(Path(t).name in ("java", "java.exe") for t in tokens[:4])


def read_dockerfile(rel: str, text: str) -> Iterator[Setting]:
    logical, start = "", 0
    lines = text.splitlines()
    for i, raw in enumerate(lines + [""], 1):
        line = raw.rstrip()
        if not logical:
            start = i
            if not line.strip() or line.lstrip().startswith("#"):
                continue
        if line.endswith("\\"):
            logical += line[:-1] + " "
            continue
        logical += line
        stmt, logical = logical.strip(), ""
        if not stmt:
            continue
        instr, _, rest = stmt.partition(" ")
        instr, rest = instr.upper(), rest.strip()
        loc = f"{rel}:{start}"
        if instr == "ENV":
            toks = _split(rest)
            if toks and "=" not in toks[0]:              # ENV KEY value with spaces
                yield from _env_settings(toks[0], rest[len(rest.split(None, 1)[0]):].strip().strip('"\''), loc, "Dockerfile ENV")
            else:
                for t in toks:
                    if "=" in t:
                        k, v = t.split("=", 1)
                        yield from _env_settings(k, v, loc, "Dockerfile ENV")
        elif instr in ("CMD", "ENTRYPOINT"):
            if rest.startswith("["):
                try:
                    toks = [str(x) for x in json.loads(rest)]
                except ValueError:
                    toks = _split(rest)
            else:
                toks = _split(rest)
            yield from _d_props(toks, loc, f"Dockerfile {instr}")


def _yaml_docs(text: str) -> List:
    try:
        import yaml
    except ImportError:                                  # pragma: no cover - the scan extra installs it
        return []
    loader = getattr(yaml, "CSafeLoader", yaml.SafeLoader)
    try:
        return [d for d in yaml.load_all(text, Loader=loader) if d is not None]
    except yaml.YAMLError:
        return []


def _line_of(text: str, needle: str) -> int:
    i = text.find(needle)
    return text.count("\n", 0, i) + 1 if i >= 0 else 1


def _container_settings(rel: str, text: str, c: dict, via: str) -> Iterator[Setting]:
    env = c.get("env") if "env" in c else c.get("environment")
    pairs: List[Tuple[str, str]] = []
    if isinstance(env, dict):
        pairs = [(str(k), "" if v is None else str(v)) for k, v in env.items()]
    elif isinstance(env, list):
        for e in env:
            if isinstance(e, dict) and "name" in e and "value" in e:          # Kubernetes
                pairs.append((str(e["name"]), str(e["value"])))
            elif isinstance(e, str) and "=" in e:                             # Compose list form
                k, v = e.split("=", 1)
                pairs.append((k, v))
    for k, v in pairs:
        yield from _env_settings(k, v, f"{rel}:{_line_of(text, k)}", via)
    for key in ("command", "args", "entrypoint"):
        val = c.get(key)
        toks = [str(x) for x in val] if isinstance(val, list) else _split(val) if isinstance(val, str) else []
        for t in toks:
            if t.startswith("-D"):
                yield from _d_props([t], f"{rel}:{_line_of(text, t)}", f"{via} {key}")


def _walk_containers(node) -> Iterator[dict]:
    if isinstance(node, dict):
        for key in ("containers", "initContainers"):
            for c in node.get(key) or []:
                if isinstance(c, dict):
                    yield c
        for v in node.values():
            yield from _walk_containers(v)
    elif isinstance(node, list):
        for v in node:
            yield from _walk_containers(v)


def read_yaml(rel: str, text: str) -> Iterator[Setting]:
    for doc in _yaml_docs(text):
        if not isinstance(doc, dict):
            continue
        if isinstance(doc.get("services"), dict):                                 # Compose
            for svc in doc["services"].values():
                if isinstance(svc, dict):
                    yield from _container_settings(rel, text, svc, "Compose")
        if "kind" in doc and "apiVersion" in doc:                                  # Kubernetes
            for c in _walk_containers(doc):
                yield from _container_settings(rel, text, c, "Kubernetes")


_SPRING_CONFIG = re.compile(r"^(application|bootstrap)(-[\w.\-]+)?\.(properties|ya?ml)$")


def _flatten(prefix: str, node) -> Iterator[Tuple[str, object]]:
    if isinstance(node, dict):
        for k, v in node.items():
            yield from _flatten(f"{prefix}.{k}" if prefix else str(k), v)
    elif not isinstance(node, list):
        yield prefix, node


def read_spring_config(rel: str, text: str) -> Iterator[Setting]:
    """Spring Boot's own configuration files: `application.properties`, `application-prod.yml`..."""
    via = Path(rel).name
    if rel.endswith(".properties"):
        for i, line in enumerate(text.splitlines(), 1):
            st = line.strip()
            m = re.match(r"^([^=:\s]+)\s*[=:\s]\s*(.*)$", st) if st and st[0] not in "#!" else None
            if m:
                yield Setting("spring-property", m.group(1), m.group(2).strip(), f"{rel}:{i}", via)
        return
    lines = text.splitlines()
    for doc in _yaml_docs(text):
        for key, value in _flatten("", doc):
            v = str(value).lower() if isinstance(value, bool) else str(value)
            leaf = key.rsplit(".", 1)[-1]
            line = next((i for i, ln in enumerate(lines, 1) if ln.strip().startswith(f"{leaf}:")), 0)
            yield Setting("spring-property", key, v, f"{rel}:{line}", via)


def _relaxed(key: str) -> str:
    """Spring's relaxed binding: `first-name`, `firstName`, `first_name` are one name."""
    return ".".join(seg.replace("-", "").replace("_", "").lower() for seg in key.split("."))


def spring_env_name(key: str) -> str:
    """The environment variable Spring Boot binds to a property (dots to `_`, dashes dropped)."""
    return key.replace("-", "").replace(".", "_").upper()


def read_env_file(rel: str, text: str) -> Iterator[Setting]:
    for i, line in enumerate(text.splitlines(), 1):
        m = re.match(r"^\s*(?:export\s+)?([A-Za-z_]\w*)=(.*)$", line)
        if m and not line.lstrip().startswith("#"):
            v = m.group(2).strip()
            v = v[1:-1] if len(v) >= 2 and v[0] == v[-1] and v[0] in "'\"" else v
            yield from _env_settings(m.group(1), v, f"{rel}:{i}", ".env")


def read_shell(rel: str, text: str) -> Iterator[Setting]:
    for i, line in enumerate(text.splitlines(), 1):
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        m = re.match(r"^(?:export\s+)([A-Za-z_]\w*)=(.*)$", s)
        if m:
            toks = _split(m.group(2))
            yield from _env_settings(m.group(1), " ".join(toks), f"{rel}:{i}", "shell export")
            continue
        toks = _split(s)
        if _is_java_command(toks):
            yield from _d_props(toks, f"{rel}:{i}", "java command line")


def read_systemd(rel: str, text: str) -> Iterator[Setting]:
    for i, line in enumerate(text.splitlines(), 1):
        k, _, v = line.strip().partition("=")
        if k == "Environment":
            for t in _split(v):
                if "=" in t:
                    ek, ev = t.split("=", 1)
                    yield from _env_settings(ek, ev, f"{rel}:{i}", "systemd Environment")
        elif k == "ExecStart":
            toks = _split(v.lstrip("-@:+!"))
            if _is_java_command(toks):
                yield from _d_props(toks, f"{rel}:{i}", "systemd ExecStart")


def read_properties(rel: str, text: str) -> Iterator[Setting]:
    name = Path(rel).name
    for i, line in enumerate(text.splitlines(), 1):
        s = line.strip()
        if not s or s[0] in "#!":
            continue
        m = re.match(r"^([^=:\s]+)\s*[=:\s]\s*(.*)$", s)
        if m:
            yield Setting("properties-file", f"{name}:{m.group(1)}", m.group(2).strip(), f"{rel}:{i}", name)


def _norm(text: str) -> str:
    return re.sub(r"\s+", "", text)


def read_java(rel: str, text: str, calls: Set[Tuple[str, str]]) -> Iterator[Setting]:
    """`System.setProperty("k", "v")` and the curated calls (receiver, method), from the syntax tree."""
    if "setProperty" not in text and not any(m in text for _, m in calls):
        return
    from frame.sca.mine import _parser
    from frame.sil.source_facts import _text, _walk
    try:
        root = _parser("java").parse(text.encode("utf-8")).root_node
    except Exception:                                    # no Java grammar installed
        return
    for n in _walk(root):
        if n.type != "method_invocation":
            continue
        name, obj = n.child_by_field_name("name"), n.child_by_field_name("object")
        args = n.child_by_field_name("arguments")
        argv = [a for a in (args.named_children if args is not None else [])]
        method, receiver = _text(name), _norm(_text(obj)) if obj is not None else ""
        loc = f"{rel}:{n.start_point[0] + 1}"
        if method == "setProperty" and receiver in ("System", "java.lang.System") and len(argv) == 2 \
                and all(a.type == "string_literal" for a in argv):
            k, v = (_text(a)[1:-1] for a in argv)
            yield Setting("jvm-property", k, v, loc, "System.setProperty")
        elif (receiver, method) in calls:
            yield Setting("java-call", f"{receiver}.{method}", ",".join(_norm(_text(a)) for a in argv), loc, "call")


_SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "target", "build", "dist", "__pycache__", ".gradle", ".idea"}


def project_settings(root: Path, properties_files: Set[str] = frozenset(),
                     calls: Set[Tuple[str, str]] = frozenset(), exclude: Iterable = ()) -> List[Setting]:
    root = Path(root)
    skip = _SKIP_DIRS | {e for e in exclude if isinstance(e, str)}
    out: List[Setting] = []
    stack = [root]
    while stack:
        d = stack.pop()
        try:
            entries = sorted(d.iterdir())
        except OSError:
            continue
        for p in entries:
            if p.is_dir():
                if p.name not in skip and not p.is_symlink():
                    stack.append(p)
                continue
            name, rel = p.name, p.relative_to(root).as_posix()
            reader = None
            if name == "Dockerfile" or name.startswith("Dockerfile.") or name.endswith(".dockerfile"):
                reader = read_dockerfile
            elif _SPRING_CONFIG.match(name):
                reader = read_spring_config
            elif name.endswith((".yaml", ".yml")):
                reader = read_yaml
            elif name == ".env" or name.startswith(".env."):
                reader = read_env_file
            elif name.endswith(".sh"):
                reader = read_shell
            elif name.endswith(".service"):
                reader = read_systemd
            elif name in properties_files:
                reader = read_properties
            elif name.endswith(".java"):
                try:
                    text = p.read_text(encoding="utf-8", errors="replace")
                except OSError:
                    continue
                out.extend(read_java(rel, text, set(calls)))
                continue
            if reader is None:
                continue
            try:
                text = p.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            out.extend(reader(rel, text))
    return out


# ---------------------------------------------------------------------------------------------

def _matches(way: dict, s: Setting) -> bool:
    value = str(way["value"]).lower() if "value" in way else ""
    if way["kind"] == "jvm-property":
        return s.kind == "jvm-property" and s.key == way["key"] and s.value.lower() == value
    if way["kind"] == "env":
        return s.kind == "env" and s.key == way["key"] and s.value.lower() == value
    if way["kind"] == "properties-file":
        return s.kind == "properties-file" and s.key == f"{way['file']}:{way['key']}" and s.value.lower() == value
    if way["kind"] == "java-call":
        return s.kind == "java-call" and s.key == f"{_norm(way['receiver'])}.{way['method']}" \
            and s.value == ",".join(_norm(a) for a in way["args"])
    if way["kind"] == "spring-property":
        if s.value.strip().strip("'\"").lower() != value:
            return False
        if s.kind in ("spring-property", "jvm-property"):
            return _relaxed(s.key) == _relaxed(way["key"])
        return s.kind == "env" and s.key == spring_env_name(way["key"])
    return False


def describe(way: dict) -> str:
    k = way["kind"]
    if k == "jvm-property":
        return f"-D{way['key']}={way['value']}"
    if k == "env":
        return f"{way['key']}={way['value']}"
    if k == "properties-file":
        return f"{way['key']}={way['value']} in {way['file']}"
    if k == "spring-property":
        return (f"{way['key']}={way['value']} (application.properties / .yml, -D, --argument, "
                f"or {spring_env_name(way['key'])}={way['value']})")
    return f"{way['receiver']}.{way['method']}({', '.join(way['args'])})"


def annotate(findings: List[dict], root: Path, revision_dir: Optional[Path], exclude: Iterable = ()) -> None:
    """Add `mitigations` to each finding that has one for its version (in place)."""
    from frame.sca.ranges import satisfies
    by_eco: Dict[str, Dict[str, List[dict]]] = {}
    relevant: List[Tuple[dict, List[dict]]] = []
    for f in findings:
        eco = f["ecosystem"]
        if eco not in by_eco:
            by_eco[eco] = load(eco, revision_dir)
        entries = []
        for ident in [f["id"], *f.get("aliases", [])]:
            for e in by_eco[eco].get(ident, []):
                if e["package"].lower() == f["package"].lower() and e not in entries \
                        and satisfies(eco, f["version"], e["versions"]) is True:
                    entries.append(e)
        if entries:
            relevant.append((f, entries))
    if not relevant:
        return
    files = {w["file"] for _, es in relevant for e in es for w in e["ways"] if w["kind"] == "properties-file"}
    calls = {(_norm(w["receiver"]), w["method"]) for _, es in relevant for e in es for w in e["ways"]
             if w["kind"] == "java-call"}
    settings = project_settings(root, files, calls, exclude)
    for f, entries in relevant:
        out = []
        for e in entries:
            applied = [{"location": s.location, "via": s.via, "setting": describe(w)}
                       for w in e["ways"] for s in settings if _matches(w, s)]
            out.append({"summary": e["summary"], "complete": e["complete"], "caveat": e.get("caveat", ""),
                        "ways": [describe(w) for w in e["ways"]], "references": e["references"],
                        "applied": applied, "settings": e["ways"]})
        f["mitigations"] = out


def format_lines(f: dict) -> List[str]:
    lines = []
    for m in f.get("mitigations", []):
        kind = "complete" if m["complete"] else "partial"
        if m["applied"]:
            where = ", ".join(f"{a['location']} ({a['via']})" for a in m["applied"][:3])
            lines.append(f"mitigation ({kind}): {m['summary']}: APPLIED at {where}")
        else:
            lines.append(f"mitigation ({kind}): {m['summary']}: not found; set one of {'; '.join(m['ways'])}")
        if m["caveat"]:
            lines.append(f"  caveat: {m['caveat']}")
    return lines


# ---------------------------------------------------------------------------------------------
# writing one (frame deps --vulns --mitigate)

def _resources_dir(root: Path, manifest: str) -> Optional[Path]:
    d = (root / manifest).parent / "src" / "main" / "resources"
    return d if d.is_dir() else None


def _final_stage_insert(text: str, line: str) -> str:
    """`line` at the end of the Dockerfile's last stage, before its CMD / ENTRYPOINT."""
    lines = text.splitlines()
    last_from = max((i for i, ln in enumerate(lines) if re.match(r"(?i)^\s*FROM\s", ln)), default=-1)
    at = len(lines)
    for i in range(len(lines) - 1, last_from, -1):
        if re.match(r"(?i)^\s*(CMD|ENTRYPOINT)\s", lines[i]):
            at = i
    lines.insert(at, line)
    return "\n".join(lines) + "\n"


def propose(findings: List[dict], root: Path) -> Tuple[List["Change"], List[str]]:
    """Edits that apply a complete, not yet applied mitigation, one per advisory: a properties
    file the library reads from the classpath (inside the artifact, whatever runs it), else the
    JVM option / environment variable in the Dockerfile's last stage. Everything else is listed
    for a person, with the setting (partial mitigations always)."""
    from frame.sca.apply import Change
    root = Path(root)
    edits: Dict[str, Change] = {}
    manual: List[str] = []
    done: Set[Tuple[str, str]] = set()
    dockerfiles = sorted(p for p in root.rglob("Dockerfile") if not set(p.relative_to(root).parts) & _SKIP_DIRS)
    for f in findings:
        for m in f.get("mitigations", []):
            key = (f["id"], m["summary"])
            if m["applied"] or key in done:
                continue
            done.add(key)
            label = f"{f['package']}@{f['version']} {f['id']}"
            if not m["complete"]:
                manual.append(f"{label}: partial mitigation not applied automatically ({m['summary']}): {m['caveat']}")
                continue
            ways: Dict[str, dict] = {}
            for w in m.get("settings", []):
                ways.setdefault(w["kind"], w)
            res = _resources_dir(root, f["path"])
            if "spring-property" in ways and res is not None:      # the application's own configuration
                w = ways["spring-property"]
                rel = (res / "application.properties").relative_to(root).as_posix()
                cur = edits[rel].after if rel in edits else (root / rel).read_text() if (root / rel).is_file() else ""
                new = cur + ("" if not cur or cur.endswith("\n") else "\n") + f"{w['key']}={w['value']}\n"
                edits[rel] = Change(rel, edits[rel].before if rel in edits else cur, new, f"{label}: {m['summary']}")
                continue
            if "properties-file" in ways and res is not None:
                w = ways["properties-file"]
                rel = (res / w["file"]).relative_to(root).as_posix()
                cur = edits[rel].after if rel in edits else (root / rel).read_text() if (root / rel).is_file() else ""
                new = cur + ("" if not cur or cur.endswith("\n") else "\n") + f"{w['key']}={w['value']}\n"
                edits[rel] = Change(rel, edits[rel].before if rel in edits else cur, new, f"{label}: {m['summary']}")
                continue
            if dockerfiles and ("jvm-property" in ways or "env" in ways):
                rel = dockerfiles[0].relative_to(root).as_posix()
                cur = edits[rel].after if rel in edits else dockerfiles[0].read_text()
                if "jvm-property" in ways:
                    w = ways["jvm-property"]
                    line = f'ENV JAVA_TOOL_OPTIONS="${{JAVA_TOOL_OPTIONS}} -D{w["key"]}={w["value"]}"'
                else:
                    w = ways["env"]
                    line = f"ENV {w['key']}={w['value']}"
                edits[rel] = Change(rel, edits[rel].before if rel in edits else cur, _final_stage_insert(cur, line),
                                  f"{label}: {m['summary']}")
                continue
            manual.append(f"{label}: set one of {'; '.join(m['ways'])} where the application runs")
    return list(edits.values()), manual
