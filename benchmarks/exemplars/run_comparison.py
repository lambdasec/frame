#!/usr/bin/env python3
"""Run Frame and other SAST tools on the cross-file exemplars and on real apps.

    python benchmarks/exemplars/run_comparison.py                        # Frame only, controlled cases
    python benchmarks/exemplars/run_comparison.py --semgrep semgrep --opengrep opengrep \\
        --opengrep-interfile ./opengrep-alpha --bandit bandit \\
        --stock-config p/default --stock-config p/python --stock-config p/javascript
    python benchmarks/exemplars/run_comparison.py --real --repos-dir /tmp/repos ...   # real apps

Controlled cases (cases.json): each has a vulnerable/ tree (one real flow, at a known sink)
and a safe/ twin with the same structure and no flow. A tool scores a hit when it reports a
finding in the sink's file within one line of the sink; the same report on the safe twin is a
false alarm. Frame must also report the right CWE (the other tools' rule ids are not CWEs, so
for them the location is the only evidence).

Real apps (real_repos.json): cloned at a pinned commit; the answer key lists the
cross-file vulnerabilities we confirmed by reading both ends. Sinks marked "ignore" are
neither credited nor counted as noise.

Other tools run with the custom taint rules in rules/ (written the way a user would, and
checked against controls/, where source and sink share a function) and, if --stock-config is
given, with registry rule packs. The stock rows are pattern matchers: they flag the sink whether
or not data reaches it, which is why they also fire on the safe twins.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Callable, Dict, List, Tuple

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
Finding = Tuple[str, int, str]          # path, line, rule id / CWE
Tool = Callable[[Path], List[Finding]]


def run_json(cmd: List[str], cwd: Path = None) -> dict:
    p = subprocess.run(cmd, capture_output=True, text=True, cwd=cwd)
    try:
        return json.loads(p.stdout)
    except json.JSONDecodeError:
        raise RuntimeError(f"{cmd[0]} produced no JSON (exit {p.returncode}): {p.stderr[-300:]}")


def frame_tool(target: Path) -> List[Finding]:
    data = run_json([sys.executable, "-m", "frame.sil.cli", "scan", str(target), "--format", "json"], cwd=ROOT)
    return [(fr["filename"], int(v["line"]), v.get("cwe_id", ""))
            for fr in data.get("files", []) for v in fr.get("vulnerabilities", [])]


def semgrep_like(binary: str, configs: List[str], extra: List[str]) -> Tool:
    def run(target: Path) -> List[Finding]:
        cmd = [binary, "-q", "--json"]
        if "semgrep" in Path(binary).name:
            cmd += ["--metrics=off", "--disable-version-check"]
        for c in configs:
            cmd += ["--config", c]
        data = run_json(cmd + extra + [str(target)])
        return [(r["path"], r["start"]["line"], r["check_id"].split(".")[-1]) for r in data.get("results", [])]
    return run


def bandit(binary: str) -> Tool:
    def run(target: Path) -> List[Finding]:
        data = run_json([binary, "-r", str(target), "-f", "json", "-q"])
        return [(r["filename"], r["line_number"], r["test_id"]) for r in data.get("results", [])]
    return run


def codeql(binary: str) -> Tool:
    """CodeQL's security-extended suite. A database is built per target (no build needed for
    Python/JS/TS). Free for OSI-licensed code and demonstrations only (see its terms), so it
    is not bundled; pass your own install with --codeql."""
    def run(target: Path) -> List[Finding]:
        counts = {"python": len(list(target.rglob("*.py"))),
                  "javascript-typescript": len([p for ext in ("*.js", "*.ts") for p in target.rglob(ext)
                                                if "node_modules" not in p.parts])}
        lang = max(counts, key=counts.get)
        suite = "python" if lang == "python" else "javascript"
        with tempfile.TemporaryDirectory() as tmp:
            db, sarif = f"{tmp}/db", f"{tmp}/out.sarif"
            subprocess.run([binary, "database", "create", db, f"--language={lang}", f"--source-root={target}",
                            "--overwrite"], capture_output=True, check=True)
            subprocess.run([binary, "database", "analyze", db,
                            f"codeql/{suite}-queries:codeql-suites/{suite}-security-extended.qls",
                            "--format=sarif-latest", f"--output={sarif}"], capture_output=True, check=True)
            runs = json.loads(Path(sarif).read_text())["runs"]
        out: List[Finding] = []
        for r in runs[0]["results"]:
            loc = r["locations"][0]["physicalLocation"]
            out.append((loc["artifactLocation"]["uri"], loc["region"]["startLine"], r["ruleId"]))
        return out
    return run


def at(finding: Finding, case: dict) -> bool:
    f, line, _ = finding
    want = case.get("path", case["file"])
    return ((f == want or f.endswith("/" + want))
            and abs(line - case["line"]) <= case.get("tolerance", 1))


def hit(findings: List[Finding], case: dict, need_cwe: bool) -> bool:
    return any(at(f, case) and (not need_cwe or f[2] == case["cwe"]) for f in findings)


def build_tools(a: argparse.Namespace) -> Dict[str, Tool]:
    tools: Dict[str, Tool] = {"Frame": frame_tool}
    rules = [str(HERE / "rules")]
    stock = a.stock_config or []
    if a.semgrep:
        tools["Semgrep, custom taint rules"] = semgrep_like(a.semgrep, rules, [])
        if stock:
            tools["Semgrep, stock rule packs"] = semgrep_like(a.semgrep, stock, [])
    if a.opengrep:
        tools["OpenGrep, custom taint rules (--taint-intrafile)"] = semgrep_like(a.opengrep, rules, ["--taint-intrafile"])
        if stock:
            tools["OpenGrep, stock rule packs"] = semgrep_like(a.opengrep, stock, [])
    if a.opengrep_interfile:
        tools["OpenGrep alpha, custom taint rules (--taint-interfile)"] = semgrep_like(
            a.opengrep_interfile, rules, ["--taint-interfile"])
    if a.bandit:
        tools["Bandit"] = bandit(a.bandit)
    if a.codeql:
        tools["CodeQL, security-extended"] = codeql(a.codeql)
    return tools


def md_table(header: List[str], rows: List[List[str]]) -> str:
    out = ["| " + " | ".join(header) + " |", "|" + "|".join("---" for _ in header) + "|"]
    out += ["| " + " | ".join(r) + " |" for r in rows]
    return "\n".join(out)


def run_cases(tools: Dict[str, Tool], holdout: bool = False) -> Tuple[str, dict]:
    base_dir = HERE / "holdout" if holdout else HERE
    cases = json.loads((base_dir / ("holdout.json" if holdout else "cases.json")).read_text())["cases"]
    table: Dict[str, Dict[str, Tuple[bool, bool]]] = {}
    for name, tool in tools.items():
        print(f"  {name} ...", file=sys.stderr, flush=True)
        table[name] = {}
        for case in cases:
            base = base_dir / "cases" / case["id"]
            table[name][case["id"]] = (hit(tool(base / "vulnerable"), case, name == "Frame"),
                                       hit(tool(base / "safe"), case, False))

    def cell(n: str, c: str) -> str:
        tp, fp = table[n][c]
        return ("found" if tp else "missed") + (" (+ false alarm)" if fp else "")

    rows = [[f"`{c['id']}`"] + [cell(n, c["id"]) for n in tools] for c in cases]
    summary = [[n, f"{sum(t for t, _ in table[n].values())}/{len(cases)}",
                f"{sum(f for _, f in table[n].values())}/{len(cases)}"] for n in tools]
    text = (md_table(["case"] + list(tools), rows) + "\n\n"
            + md_table(["tool", "real flows found", "false alarms on safe twins"], summary))
    return text, {n: {c: {"found": t, "false_alarm": f} for c, (t, f) in r.items()} for n, r in table.items()}


def clone(repo: dict, repos_dir: Path) -> Path:
    dest = repos_dir / repo["id"]
    if not dest.exists():
        subprocess.run(["git", "clone", "-q", repo["url"], str(dest)], check=True)
    subprocess.run(["git", "-C", str(dest), "checkout", "-q", repo["commit"]], check=True)
    return dest / repo["scan_path"]


def run_real(tools: Dict[str, Tool], repos_dir: Path, only: List[str] = None) -> Tuple[str, dict]:
    repos = [r for r in json.loads((HERE / "real_repos.json").read_text())["repos"] if not only or r["id"] in only]
    out: Dict[str, Dict[str, dict]] = {n: {} for n in tools}
    for repo in repos:
        target = clone(repo, repos_dir)
        for name, tool in tools.items():
            print(f"  {repo['id']}: {name} ...", file=sys.stderr, flush=True)
            found = tool(target)
            expected, ignore = repo["expected"], repo.get("ignore", [])
            tps = [e for e in expected if hit(found, e, name == "Frame")]
            noise = [f for f in found if not any(at(f, e) for e in expected + ignore)]
            out[name][repo["id"]] = {"found": len(tps), "expected": len(expected),
                                     "other_findings": len(noise), "total": len(found),
                                     "hits": [f"{e['file']}:{e['line']}" for e in tps]}
    rows = []
    for repo in repos:
        rows.append([f"`{repo['id']}`"] + [
            f"{out[n][repo['id']]['found']}/{out[n][repo['id']]['expected']}"
            f" ({out[n][repo['id']]['other_findings']} other)" for n in tools])
    text = md_table(["app (pinned commit)"] + list(tools), rows)
    return text, out


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--semgrep")
    ap.add_argument("--opengrep")
    ap.add_argument("--opengrep-interfile", help="OpenGrep build with --taint-interfile")
    ap.add_argument("--bandit")
    ap.add_argument("--codeql", help="path to your own CodeQL CLI (not bundled: its licence limits use to OSI-licensed code)")
    ap.add_argument("--stock-config", action="append", help="rule pack/dir for the stock run (repeatable)")
    ap.add_argument("--real", action="store_true", help="score the real apps in real_repos.json instead of cases.json")
    ap.add_argument("--holdout", action="store_true",
                    help="score holdout/ (cases keyed before Frame was run on them) instead of cases.json")
    ap.add_argument("--only", action="append", help="with --real: only these repo ids (repeatable)")
    ap.add_argument("--repos-dir", type=Path, default=Path("/tmp/frame-exemplar-repos"))
    ap.add_argument("--controls", action="store_true",
                    help="only check that the custom rules fire when source and sink share a function")
    ap.add_argument("--json", help="write raw results here")
    a = ap.parse_args()

    tools = build_tools(a)
    if a.controls:
        for name, tool in tools.items():
            if name != "Frame":
                print(name, sorted({(Path(f).name, ln) for f, ln, _ in tool(HERE / "controls")}))
        return 0
    if a.real:
        a.repos_dir.mkdir(parents=True, exist_ok=True)
        text, raw = run_real(tools, a.repos_dir, a.only)
    else:
        text, raw = run_cases(tools, a.holdout)
    print(text)
    if a.json:
        Path(a.json).write_text(json.dumps(raw, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
