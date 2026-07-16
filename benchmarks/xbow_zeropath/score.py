#!/usr/bin/env python3
"""Score Frame's SARIF on the XBOW/ZeroPath benchmark using ZeroPath's OWN GPT-4o
judge, scoped to Frame, and compare against ZeroPath's published vendor numbers.

Detection is judged over the vulnerable apps (a finding that matches a ground-truth
vuln = true positive); false positives over the patched twins (a finding that
re-flags the fixed vuln = false positive). Same judge (gpt-4o, seed 1337) and same
matching prompt the vendors were scored with, so the comparison is apples-to-apples.

The judge uses the OpenAI SDK. Point it at any endpoint serving gpt-4o:
    export OPENAI_API_KEY=...  OPENAI_BASE_URL=...   # e.g. OpenRouter
    export JUDGE_MODEL=openai/gpt-4o                 # OpenRouter names it this way
    python benchmarks/xbow_zeropath/score.py --workspace /tmp/frame-xbow
"""
import argparse
import asyncio
import json
import re
import sys
from pathlib import Path

TOOLS = ["zeropath", "semgrep", "snyk_code", "bearer"]


def _patch_judge_model(script: Path) -> None:
    """Make the judge model env-configurable (JUDGE_MODEL) in-place; idempotent."""
    txt = script.read_text()
    if "JUDGE_MODEL" in txt:
        return
    txt = txt.replace('model="gpt-4o"',
                      'model=__import__("os").environ.get("JUDGE_MODEL","gpt-4o")')
    script.write_text(txt)


def _detected(bench_results, bid) -> bool:
    br = bench_results.get(bid, {})
    tp = (br.get("technical", {}).get("true_positives", 0)
          + br.get("non_technical", {}).get("true_positives", 0))
    return tp > 0


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--workspace", required=True)
    ap.add_argument("--output", default=str(Path(__file__).resolve().parent / "results.json"))
    args = ap.parse_args()
    root = Path(args.workspace).expanduser().resolve() / "validation-benchmarks"

    scripts = root / "scripts"
    _patch_judge_model(scripts / "count_true_positives.py")
    sys.path.insert(0, str(scripts))
    import os
    os.chdir(root)
    from count_true_positives import SarifValidator  # noqa: E402

    published = json.loads(
        (root / "results" / "scanner_performance_summary_detection_rates.json").read_text()
    )["results"]
    ids = sorted({b for t in published.values() for b in t["benchmark_results"]})

    v = SarifValidator("rules/")

    async def judge(sarif_glob):
        sarifs = [str(p) for p in root.glob(sarif_glob) if "frame_raw.sarif" in p.name]
        res = await v.validate_findings(sarifs)
        return res["tool_results"].get("frame", {}).get("benchmark_results", {})

    det = asyncio.run(judge("benchmarks/*/frame_raw.sarif"))
    fp = asyncio.run(judge("benchmarks_patched/*/frame_raw.sarif"))

    # aggregate Frame
    frame_det = sum(1 for b in ids if _detected(det, b))
    patched_ids = [b for b in ids if (root / "benchmarks_patched" / f"{b}-24").is_dir()]
    frame_fp = sum(1 for b in patched_ids if _detected(fp, b))

    out = {
        "pinned": "9c114481b130b8755d6a56ff5a9c26c7567ded4e",
        "n_benchmarks": len(ids),
        "n_patched": len(patched_ids),
        "frame": {"detected": frame_det, "detection_rate": round(100 * frame_det / len(ids), 1),
                  "false_positives": frame_fp,
                  "fp_rate": round(100 * frame_fp / max(1, len(patched_ids)), 1)},
        "published_detection": {t: published[t]["technical"]["detection_rate"] for t in TOOLS if t in published},
        "per_benchmark": {b: {"frame_detected": _detected(det, b),
                              "frame_fp": _detected(fp, b) if b in patched_ids else None}
                          for b in ids},
    }
    Path(args.output).write_text(json.dumps(out, indent=2))
    print(f"[score] Frame: {frame_det}/{len(ids)} detected "
          f"({out['frame']['detection_rate']}%), {frame_fp}/{len(patched_ids)} FP "
          f"({out['frame']['fp_rate']}%)")
    print(f"[score] published technical detection: "
          + ", ".join(f"{t.replace('_code','')} {published[t]['technical']['detection_rate']}%"
                      for t in TOOLS if t in published))
    print(f"[score] wrote {args.output}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
