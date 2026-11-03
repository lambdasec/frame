"""Publish Frame's agent traces to a HuggingFace dataset so others can view them.

Frame writes each agent run as an HF Session-Trace (STS-Format) JSONL with `harness: "frame"`
(see llm_trace.py). This module gathers those traces, writes a tagged dataset card, and
uploads them to a dataset repo (e.g. `lambdasec/frame-agent-traces`), where the Hub's trace
viewer renders them. The repo must be PUBLIC for the viewer / Dataset Viewer to show.

The traces are redacted on write (local home/username scrubbed) and otherwise contain only
public open-source application code and the model's reasoning, so they are safe to share --
but the uploader re-checks each file is a valid STS trace before publishing, and never reads
or sends a credential (the HF token comes from the environment and is never logged).

`huggingface_hub` is imported lazily and is NOT a scan dependency: `pip install huggingface_hub`
only when uploading.
"""

from __future__ import annotations

import json
import os
from typing import Any, Dict, List, Optional, Tuple

HARNESS = "frame"


def _is_sts_trace(path: str) -> Optional[Dict[str, Any]]:
    """Return the session header if `path`'s first non-empty line is a valid STS session
    header (`type: session`, with a harness), else None -- so only real traces are published."""
    try:
        with open(path, encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                obj = json.loads(line)
                if obj.get("type") == "session" and obj.get("harness"):
                    return obj
                return None
    except (OSError, json.JSONDecodeError):
        return None
    return None


def collect_traces(trace_dir: str) -> List[Tuple[str, str, Dict[str, Any]]]:
    """Find every STS trace under `trace_dir`. Returns (upload_name, path, header), where
    upload_name is a flat, readable name derived from the path (…/traj/<case>/<checkout>/
    hunt.jsonl -> `<case>__<checkout>.jsonl`). Skips the `.calls.jsonl` timing sidecars."""
    out: List[Tuple[str, str, Dict[str, Any]]] = []
    root = os.path.realpath(trace_dir)
    for dp, _dns, fns in os.walk(root):
        for fn in fns:
            if not fn.endswith(".jsonl") or fn.endswith(".calls.jsonl"):
                continue
            p = os.path.join(dp, fn)
            header = _is_sts_trace(p)
            if header is None:
                continue
            rel = os.path.relpath(p, root)
            parts = [x for x in rel[:-len(".jsonl")].split(os.sep) if x != "traj"]
            if len(parts) > 1 and parts[-1] == "hunt":    # drop the generic trace filename
                parts = parts[:-1]
            name = "__".join(parts) + ".jsonl"
            out.append((name, p, header))
    return sorted(out)


def dataset_card(n_traces: int, harnesses: List[str], extra_tags: List[str]) -> str:
    """A HF dataset card (README.md) with YAML frontmatter tagging the repo as agent traces."""
    tags = sorted(set(["agent-traces", "agent-trace", "security", "sast", "authorization",
                       HARNESS] + list(extra_tags)))
    fm_tags = "\n".join(f"- {t}" for t in tags)
    harness_line = ", ".join(sorted(set(harnesses))) or HARNESS
    return (
        "---\n"
        "pretty_name: Frame Agent Traces\n"
        "license: apache-2.0\n"
        "task_categories:\n- other\n"
        "tags:\n" + fm_tags + "\n"
        "---\n\n"
        "# Frame Agent Traces\n\n"
        f"{n_traces} agent traces from [Frame](https://github.com/lambdasec/frame)'s "
        "neuro-symbolic security agent, in the Hugging Face "
        "[Session-Trace format](https://huggingface.co/docs/hub/session-traces-format) "
        f"(`harness: {harness_line}`), so they render in the Hub's trace viewer.\n\n"
        "Each `.jsonl` file is one run of Frame's agentic authorization / business-logic hunt: "
        "the agent investigates a repository using Frame's own engine facts (the handlers it "
        "found and their authorization posture, the vulnerabilities it already proved) plus "
        "`grep`/`read_file`, then reports findings. The traces are redacted of local paths and "
        "usernames; the code shown is from public open-source projects.\n\n"
        "Produced on the public [BAC-Bench](https://arxiv.org/abs/2610.00977) broken-access-"
        "control benchmark. A companion `*.calls.jsonl` timing log (latency, time-to-first-"
        "token, prompt/cached tokens) is not uploaded here.\n"
    )


def upload_traces(trace_dir: str, repo: str, token: Optional[str] = None,
                  private: bool = False, extra_tags: Optional[List[str]] = None,
                  dry_run: bool = False) -> Dict[str, Any]:
    """Upload every STS trace under `trace_dir` to the HF dataset `repo` (e.g.
    `lambdasec/frame-agent-traces`) with a tagged dataset card. Returns a summary. With
    `dry_run`, validates and builds the card but uploads nothing (for offline testing).

    The token comes from `token` or the HF_TOKEN / HUGGING_FACE_HUB_TOKEN environment, and is
    never logged. The repo must be public for the Hub trace viewer to render the traces.
    """
    traces = collect_traces(trace_dir)
    if not traces:
        return {"uploaded": 0, "repo": repo, "note": "no STS traces found"}
    card = dataset_card(len(traces), [h.get("harness", "") for _n, _p, h in traces],
                        extra_tags or [])
    summary = {"repo": repo, "n_traces": len(traces),
               "names": [n for n, _p, _h in traces][:10], "private": private}
    if dry_run:
        summary["dry_run"] = True
        summary["card_preview"] = card[:200]
        return summary

    try:
        from huggingface_hub import HfApi
    except ImportError as e:
        raise RuntimeError("uploading needs huggingface_hub: pip install huggingface_hub") from e
    tok = token or os.environ.get("HF_TOKEN") or os.environ.get("HUGGING_FACE_HUB_TOKEN")
    api = HfApi(token=tok)
    api.create_repo(repo, repo_type="dataset", private=private, exist_ok=True)
    import tempfile
    with tempfile.TemporaryDirectory() as td:
        with open(os.path.join(td, "README.md"), "w", encoding="utf-8") as fh:
            fh.write(card)
        api.upload_file(path_or_fileobj=os.path.join(td, "README.md"), path_in_repo="README.md",
                        repo_id=repo, repo_type="dataset")
    for name, path, _h in traces:
        api.upload_file(path_or_fileobj=path, path_in_repo=f"traces/{name}",
                        repo_id=repo, repo_type="dataset")
    summary["uploaded"] = len(traces)
    summary["url"] = f"https://huggingface.co/datasets/{repo}"
    return summary


def _main(argv: Optional[List[str]] = None) -> int:
    import argparse
    ap = argparse.ArgumentParser(description="Upload Frame agent traces to a HF dataset.")
    ap.add_argument("trace_dir")
    ap.add_argument("--repo", default="lambdasec/frame-agent-traces")
    ap.add_argument("--private", action="store_true")
    ap.add_argument("--tag", action="append", default=[], help="extra dataset tag")
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args(argv)
    res = upload_traces(args.trace_dir, args.repo, private=args.private,
                        extra_tags=args.tag, dry_run=args.dry_run)
    print(json.dumps(res, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(_main())
