"""Breaking-change adaptation: when an upgrade makes the project's own build or tests fail
(`frame deps --apply --verify COMMAND --adapt`), a model adapts the code that uses the upgraded
packages, and the project decides.

    1. the code that imports an upgraded package (Frame's reachability reader) and the failing
       command's output go to the model, which answers with minimal search / replace edits;
    2. the edits are applied (application source only: never a manifest or lockfile, which
       would undo the upgrade) and the command runs again; up to `rounds` times, each round
       seeing the new output;
    3. kept only if the command passes AND a Frame scan of every edited file finds no finding
       type it did not have before. Otherwise every edit is restored (and the caller rolls the
       upgrade back).

The model is never trusted: the project's command and Frame's scan are the verdict.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Dict, Iterable, List, Optional, Tuple

from frame.sca.lockfiles import LOCKFILES

SYSTEM = (
    "You adapt application code to a dependency upgrade that broke its build or tests. You get the "
    "upgrades, the failing command's output, and the files that use the upgraded packages. Change "
    "only what the new versions require (renamed or removed APIs, new signatures, changed defaults); "
    "keep behaviour the same; never change dependency versions, manifests or lockfiles, and never "
    "weaken security checks. Answer with one JSON object: {\"edits\": [{\"path\": ..., \"original\": "
    "<verbatim span of that file>, \"replacement\": ...}], \"rationale\": <one line>}.")

MANIFESTS = {"package.json", "pyproject.toml", "requirements.txt", "pom.xml", "build.gradle", "build.gradle.kts",
             "go.mod", "Cargo.toml", "Gemfile", "composer.json", "pubspec.yaml", "mix.exs"}
OUTPUT_TAIL = 150
FILE_CHARS = 12000


@dataclass
class Adaptation:
    status: str                          # "adapted" | "failed" | "introduces-findings" | "no-usage"
    rounds: int = 0
    changes: list = field(default_factory=list)          # apply.Change per edited file
    introduced: List[str] = field(default_factory=list)  # finding types the edits added
    rationale: str = ""
    output: str = ""                     # the command's last output


def usage_files(root: Path, upgrades: List[dict], excluded: Iterable = ()) -> List[str]:
    """Source files that import an upgraded package (as reachability reads imports)."""
    from frame.sca.reachability import Usage, _imports_module, module_names
    root = Path(root)
    usage = Usage(root, excluded)
    out = []
    for fu in usage.files():
        for u in upgrades:
            mods = module_names(u["ecosystem"], u["package"], usage.venv(root))
            if any(_imports_module(u["ecosystem"], v, m) for m in mods for v in fu.imports | fu.wildcards):
                out.append(fu.rel)
                break
    return sorted(set(out))


def _tail(text: str, n: int = OUTPUT_TAIL) -> str:
    return "\n".join(text.strip().splitlines()[-n:])


def prompt(upgrades: List[dict], output: str, sources: Dict[str, str]) -> str:
    ups = "\n".join(f"- {u['package']} {u['current']} -> {u['target']}" + (" (new major version)" if u.get("major") else "")
                    for u in upgrades)
    files = "\n\n".join(f"=== {rel} ===\n{text[:FILE_CHARS]}" for rel, text in sorted(sources.items()))
    return (f"Upgrades:\n{ups}\n\nThe project's command now fails:\n{_tail(output)}\n\n"
            f"Files that use the upgraded packages:\n{files}\n\n"
            "Reason briefly about what changed in the new versions, then output the JSON object.")


def propose(upgrades: List[dict], output: str, sources: Dict[str, str], config, client=None) -> dict:
    from frame.sil.llm_client import LLMClient, _extract_json_object
    client = client or LLMClient(config)
    rf = None if getattr(config, "json_mode", "json_object") == "off" else {"type": "json_object"}
    raw = client.complete([{"role": "system", "content": SYSTEM},
                           {"role": "user", "content": prompt(upgrades, output, sources)}],
                          response_format=rf, force_json=(rf is not None), max_tokens=config.max_tokens)
    return _extract_json_object(raw) or {}


def _finding_types(root: Path, rels: Iterable[str]) -> Dict[str, Optional[Counter]]:
    from frame.sil.scanner import FrameScanner, language_for_file
    out: Dict[str, Counter] = {}
    for rel in rels:
        p = Path(root) / rel
        lang = language_for_file(str(p))
        if lang is None or not p.is_file():
            out[rel] = Counter()
            continue
        try:
            r = FrameScanner(language=lang).scan_file(str(p))
            out[rel] = Counter(v.type.value for v in r.vulnerabilities)
        except Exception:
            out[rel] = None                     # not scanned: the edits cannot be judged (fails closed)
    return out


def _editable(root: Path, rel: str) -> bool:
    p = (Path(root) / rel).resolve()
    name = p.name
    return (p.is_file() and Path(root).resolve() in p.parents and name not in MANIFESTS and name not in LOCKFILES
            and not name.endswith((".lock", ".lockfile")))


def adapt(root: Path, upgrades: List[dict], verify: str, failing_output: str, config=None, excluded: Iterable = (),
          rounds: int = 3, proposer: Optional[Callable[[List[dict], str, Dict[str, str]], dict]] = None,
          run: Optional[Callable[[str, Path], Tuple[bool, str]]] = None) -> Adaptation:
    from frame.sca.apply import Change, _run_verify
    from frame.sil.llm_fix import apply_fix
    root = Path(root).resolve()
    run = run or _run_verify
    propose_ = proposer or (lambda u, o, s: propose(u, o, s, config))
    files = usage_files(root, upgrades, excluded)
    if not files:
        return Adaptation("no-usage", output=failing_output)
    original: Dict[str, str] = {}
    current = {rel: (root / rel).read_text(encoding="utf-8") for rel in files}
    before = _finding_types(root, files)
    output, ok, rationale, n = failing_output, False, "", 0
    for n in range(1, rounds + 1):
        answer = propose_(upgrades, output, current)
        rationale = str(answer.get("rationale", "")) or rationale
        changed = False
        for e in answer.get("edits") or []:
            rel = str(e.get("path", "")).lstrip("./")
            if not rel or not _editable(root, rel):
                continue
            text = current.get(rel)
            if text is None:                              # a file beyond the usage set: measured first
                text = (root / rel).read_text(encoding="utf-8")
                current[rel] = text
                before.update(_finding_types(root, [rel]))
            patched, applied = apply_fix(text, e)
            if applied and patched != text:
                original.setdefault(rel, text)
                current[rel] = patched
                (root / rel).write_text(patched, encoding="utf-8")
                changed = True
        if not changed:
            break
        ok, output = run(verify, root)
        if ok:
            break
    edited = sorted(original)

    def restore() -> None:
        for rel, text in original.items():
            (root / rel).write_text(text, encoding="utf-8")
    if not ok or not edited:
        restore()
        return Adaptation("failed", n, rationale=rationale, output=output)
    after = _finding_types(root, edited)
    if any(after[rel] is None for rel in edited):
        restore()
        return Adaptation("introduces-findings", n, introduced=["(an edited file could not be re-scanned)"],
                          rationale=rationale, output=output)
    introduced = sorted({t for rel in edited
                         for t, c in (after[rel] - (before.get(rel) or Counter())).items() if c})
    if introduced:
        restore()
        return Adaptation("introduces-findings", n, introduced=introduced, rationale=rationale, output=output)
    return Adaptation("adapted", n, [Change(rel, original[rel], current[rel], rationale) for rel in edited],
                      rationale=rationale, output=output)
