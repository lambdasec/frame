"""Dockerfiles: each build stage is a resource (`dockerfile_parser` reads the file as BuildKit
does).

A stage's document:

    index, name (its `AS` alias or none), final (the last stage: the image that is built),
    from:   ref, image, tag, digest, platform, stage (an earlier stage it builds on), scratch,
            external (neither an earlier stage nor scratch)
    user:   the user the stage's processes run as: its last USER, else the user of the stage it
            builds on, "" for scratch (root); unknown for an external base image (its own
            configuration, which the files do not give)
    user_set: whether a USER in the stage or the stages it builds on sets it
    instructions: cmd (lower case), args, flags (`--checksum=...` as checksum: "..."), json, and for
            ADD/COPY sources and dest, for ENV/ARG/LABEL vars [{key, value, credential}] where
            credential is the provider format a value contains (frame/sil/secret_formats)
    preamble: (first stage only) the ARG instructions before the first FROM

A value that BuildKit would expand from a variable (`$X`, `${X}`) is unknown: a build argument
can change it. Stage resources have the view `self`.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from .dockerfile_parser import DockerfileError, Instruction, parse
from .engine import Unknown
from .model import ReadResult, Resource


def _has_variable(word: str, escape: str) -> bool:
    i = 0
    while i < len(word):
        if word[i] == escape:
            i += 2
            continue
        if word[i] == "$" and i + 1 < len(word) and (word[i + 1] == "{" or word[i + 1].isalnum() or word[i + 1] == "_"):
            return True
        i += 1
    return False


def _value(word: str, escape: str, key: str):
    return Unknown(key, word) if _has_variable(word, escape) else word


def _flags(flags: List[str]) -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    for f in flags:
        name, eq, value = f[2:].partition("=") if f.startswith("--") else (f, "", "")
        out[name.lower()] = value if eq else True
    return out


def _image_reference(ref: str) -> Dict[str, Any]:
    """A reference's parts as the distribution reference grammar writes them:
    [registry/]path[:tag][@digest] (a tag's colon comes after the last slash)."""
    name, _, digest = ref.partition("@")
    tag = None
    slash = name.rfind("/")
    colon = name.rfind(":")
    if colon > slash:
        name, tag = name[:colon], name[colon + 1:]
    return {"image": name, "tag": tag, "digest": digest or None}


def _vars(ins: Instruction, escape: str, key: str) -> List[Dict[str, Any]]:
    from frame.sil.secret_formats import find
    out = []
    if ins.name in ("env", "label"):
        triples = [ins.args[i:i + 3] for i in range(0, len(ins.args) - 2, 3)]
        pairs = [(t[0], t[1]) for t in triples]
    else:                                   # ARG name[=default] ...
        pairs = [(w.partition("=")[0], w.partition("=")[2] if "=" in w else None) for w in ins.args]
    for i, (k, v) in enumerate(pairs):
        entry: Dict[str, Any] = {"key": k}
        if v is not None:
            entry["value"] = _value(v, escape, f"{key}.vars[{i}]")
            hit = find(v)
            if hit is not None:
                entry["credential"] = hit[0].id
        out.append(entry)
    return out


def _instruction_doc(ins: Instruction, escape: str, key: str) -> Dict[str, Any]:
    doc: Dict[str, Any] = {"cmd": ins.name, "args": list(ins.args), "flags": _flags(ins.flags), "json": ins.json}
    if ins.name in ("add", "copy") and ins.args:
        doc["sources"] = [_value(a, escape, f"{key}.sources[{i}]") for i, a in enumerate(ins.args[:-1])]
        doc["dest"] = _value(ins.args[-1], escape, f"{key}.dest")
    if ins.name in ("env", "label", "arg"):
        doc["vars"] = _vars(ins, escape, key)
    return doc


def _stages(instructions: List[Instruction], escape: str, rel: str) -> Tuple[List[Dict[str, Any]], List[Dict]]:
    stages: List[Dict[str, Any]] = []
    lines: List[Dict] = []
    preamble: List[Dict[str, Any]] = []
    preamble_lines: Dict = {}
    names: Dict[str, int] = {}
    for ins in instructions:
        if ins.name == "from":
            idx = len(stages)
            key = f"{rel}#stage{idx}"
            args = list(ins.args)
            alias = args[2] if len(args) >= 3 and args[1].lower() == "as" else None
            ref = args[0] if args else ""
            frm: Dict[str, Any] = {"ref": ref, "platform": _flags(ins.flags).get("platform")}
            if _has_variable(ref, escape):
                u = Unknown(f"{key}.from", ref)
                frm.update(image=u.child("image"), tag=u.child("tag"), digest=u.child("digest"),
                           stage=None, scratch=False, external=u.child("external"))
            elif ref.lower() in names:
                frm.update(image=None, tag=None, digest=None, stage=names[ref.lower()], scratch=False, external=False)
            elif ref.lower() == "scratch":
                frm.update(image="scratch", tag=None, digest=None, stage=None, scratch=True, external=False)
            else:
                frm.update(_image_reference(ref), stage=None, scratch=False, external=True)
            stage = {"index": idx, "name": alias, "final": False, "from": frm, "instructions": []}
            stages.append(stage)
            lines.append({(): ins.start_line, ("from",): ins.start_line})
            if alias:
                names[alias.lower()] = idx
            continue
        if not stages:
            preamble_lines[("preamble", len(preamble))] = ins.start_line
            preamble.append(_instruction_doc(ins, escape, f"{rel}#preamble{len(preamble)}"))
            continue
        stage, where = stages[-1], lines[-1]
        j = len(stage["instructions"])
        key = f"{rel}#stage{stage['index']}.instructions[{j}]"
        stage["instructions"].append(_instruction_doc(ins, escape, key))
        where[("instructions", j)] = ins.start_line
        if ins.name == "user" and ins.args:
            stage["user"] = _value(ins.args[0], escape, f"{rel}#stage{stage['index']}.user")
            stage["user_set"] = True
            where[("user",)] = ins.start_line
    for stage in stages:
        if "user" not in stage:
            frm = stage["from"]
            if frm["stage"] is not None:
                parent = stages[frm["stage"]]
                stage["user"], stage["user_set"] = parent["user"], parent["user_set"]
            elif frm["scratch"] is True:
                stage["user"], stage["user_set"] = "", False
            else:
                stage["user"] = Unknown(f"{rel}#stage{stage['index']}.base-user", f"the user of {frm['ref']}")
                stage["user_set"] = False
    if stages:
        stages[-1]["final"] = True
        stages[0]["preamble"] = preamble
        lines[0].update(preamble_lines)
    return stages, lines


def read_file(path: Path, rel: str, out: ReadResult, text: Optional[str] = None) -> None:
    try:
        text = path.read_text(encoding="utf-8") if text is None else text
    except (OSError, UnicodeDecodeError) as e:
        out.warnings.append(f"{rel}: cannot read: {e}")
        return
    try:
        instructions, escape = parse(text)
    except DockerfileError as e:
        out.warnings.append(f"{rel}: not a valid Dockerfile ({e})")
        return
    stages, lines = _stages(instructions, escape, rel)
    for stage, where in zip(stages, lines):
        label = stage["name"] or str(stage["index"])
        out.resources.append(Resource(
            format="dockerfile", type="stage", name=label, file=rel, line=where[()], document=stage,
            lines=where, views={"self": ()}, address=f"{rel} stage {label}"))
    if stages:
        out.files.append(rel)


def is_dockerfile(path: Path) -> bool:
    from frame.sil.inventory import _container_kind
    return _container_kind(path) == "dockerfile"


def read(paths: List[Tuple[Path, str]]) -> ReadResult:
    out = ReadResult()
    for path, rel in paths:
        read_file(path, rel, out)
    return out


__all__ = ["is_dockerfile", "read", "read_file"]
