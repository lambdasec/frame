"""Kubernetes manifests: every object of a YAML (or JSON) stream that has `apiVersion` and
`kind`, the items of a `v1` `List` included, with the views of `data/kubernetes.toml`.

Files inside a Helm chart's `templates/` are Go templates: one with template actions (`{{`) is
skipped with a warning (render the chart and scan the output); one without any is rendered as
written, so it is read like any manifest.
"""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

try:                                        # Python 3.11+
    import tomllib
except ModuleNotFoundError:                 # pragma: no cover - 3.10
    import tomli as tomllib                 # type: ignore[no-redef]

from .engine import DocPath
from .model import ReadResult, Resource
from .yaml_doc import YamlError, load_all

DATA = Path(__file__).parent / "data" / "kubernetes.toml"
_WORKLOAD_KEYS = {"kind", "groups", "pod", "podmeta"}


def _path(text: str) -> DocPath:
    return tuple(text.split("."))


@lru_cache(maxsize=1)
def _catalog() -> Tuple[Dict[Tuple[str, str], Dict[str, DocPath]], Dict[str, List[str]]]:
    data = tomllib.loads(DATA.read_text(encoding="utf-8"))
    if set(data) - {"workload", "collections"}:
        raise ValueError(f"{DATA.name}: unknown table(s) {sorted(set(data) - {'workload', 'collections'})}")
    workloads: Dict[Tuple[str, str], Dict[str, DocPath]] = {}
    for i, w in enumerate(data.get("workload", [])):
        if set(w) != _WORKLOAD_KEYS:
            raise ValueError(f"{DATA.name}: workload {i + 1} needs exactly {sorted(_WORKLOAD_KEYS)}")
        for group in w["groups"]:
            workloads[(group, w["kind"])] = {"pod": _path(w["pod"]), "podmeta": _path(w["podmeta"])}
    collections = {k: list(v) for k, v in data.get("collections", {}).items()}
    for name, parts in collections.items():
        for p in parts:
            if p.split(".")[0] not in ("pod", "podmeta"):
                raise ValueError(f"{DATA.name}: collection {name}: {p} does not start at a view")
    return workloads, collections


def view_names() -> set:
    _, collections = _catalog()
    return {"self", "pod", "podmeta"} | set(collections)


def _group(api_version: str) -> str:
    return api_version.split("/", 1)[0] if "/" in api_version else ""


def _views(doc: Dict[str, Any]) -> Dict[str, Any]:
    workloads, collections = _catalog()
    views: Dict[str, Any] = {"self": ()}
    found = workloads.get((_group(str(doc.get("apiVersion", ""))), str(doc.get("kind", ""))))
    if found:
        views.update(found)
        for name, parts in collections.items():
            views[name] = [found[p.split(".")[0]] + tuple(p.split(".")[1:]) for p in parts]
    return views


def _in_helm_templates(path: Path, root: Path) -> bool:
    for parent in path.parents:
        if parent.name == "templates" and (parent.parent / "Chart.yaml").is_file():
            return True
        if parent == root:
            break
    return False


def _resource(doc: Dict[str, Any], lines, start: int, rel: str) -> Resource:
    meta = doc.get("metadata") if isinstance(doc.get("metadata"), dict) else {}
    name = str(meta.get("name") or meta.get("generateName") or "")
    ns = meta.get("namespace")
    kind = str(doc["kind"])
    address = f"{kind}/{ns}/{name}" if ns else f"{kind}/{name}"
    return Resource(format="kubernetes", type=kind, name=name, file=rel, line=start, document=doc,
                    lines=lines, views=_views(doc), address=address)


def _is_object(doc: Any) -> bool:
    return isinstance(doc, dict) and isinstance(doc.get("apiVersion"), str) and isinstance(doc.get("kind"), str)


def read_file(path: Path, rel: str, out: ReadResult, text: Optional[str] = None) -> None:
    """Add the Kubernetes objects of one file to `out`."""
    try:
        text = path.read_text(encoding="utf-8") if text is None else text
    except (OSError, UnicodeDecodeError) as e:
        out.warnings.append(f"{rel}: cannot read: {e}")
        return
    found = 0
    try:
        for doc, lines, start in load_all(text):
            if not _is_object(doc):
                continue
            if doc["kind"] == "List" and isinstance(doc.get("items"), list):
                for i, item in enumerate(doc["items"]):
                    if _is_object(item):
                        prefix = ("items", i)
                        sub = {p[2:]: n for p, n in lines.items() if p[:2] == prefix}
                        out.resources.append(_resource(item, sub, lines.get(prefix, start), rel))
                        found += 1
                continue
            out.resources.append(_resource(doc, lines, start, rel))
            found += 1
    except YamlError as e:
        if found or _looks_like_manifest(text):
            out.warnings.append(f"{rel}: not valid YAML: {e}")
        return
    if found:
        out.files.append(rel)


def _looks_like_manifest(text: str) -> bool:
    head = text[:4096]
    return "apiVersion:" in head and "kind:" in head


def _render_charts(root: Path, excluded, out: ReadResult) -> set:
    """Each chart rendered by Helm, its objects read; the chart directories it handled."""
    from . import helm
    done = set()
    for chart in helm.charts(root, excluded):
        rel_chart = chart.relative_to(root).as_posix() if chart != root else "."
        done.add(chart.resolve())                  # its files are Helm's to read, rendered or not
        rendered, why = helm.render(chart)
        if rendered is None:
            out.warnings.append(f"{rel_chart}: Helm chart not rendered ({why})")
            continue
        for source, text in helm.split_sources(rendered):
            # "<chart name>/templates/x.yaml" (or a subchart's "<chart>/charts/<sub>/templates/x.yaml")
            inside = source.split("/", 1)[1] if "/" in source else source
            rel = (f"{rel_chart}/{inside}" if rel_chart != "." else inside) if source else rel_chart
            before = len(out.resources)
            read_file(chart / inside, rel, out, text)
            for r in out.resources[before:]:
                r.line = 1
                r.lines = {}                       # rendered lines are not the template's
    return done


def read(paths: List[Tuple[Path, str]], root: Path, render_helm: bool = False, excluded=frozenset()) -> ReadResult:
    out = ReadResult()
    rendered = _render_charts(root, excluded, out) if render_helm and root.is_dir() else set()
    for path, rel in paths:
        if rendered and any(parent.resolve() in rendered for parent in path.parents):
            continue                               # read through Helm's rendering
        if _in_helm_templates(path, root):
            try:
                text = path.read_text(encoding="utf-8")
            except (OSError, UnicodeDecodeError) as e:
                out.warnings.append(f"{rel}: cannot read: {e}")
                continue
            if "{{" in text:
                out.warnings.append(f"{rel}: a Helm template (not checked; render the chart with "
                                    "`helm template` and scan the output)")
                continue
            # a template without actions is rendered as written
            read_file(path, rel, out, text)
            continue
        read_file(path, rel, out)
    return out


__all__ = ["read", "read_file", "view_names"]
