"""Rerun cases with the real tools and rewrite the offline corpus (tests/fixtures/sca/real/).

    python tests/sca_real/refresh.py                  # every case
    python tests/sca_real/refresh.py npm-lock cargo   # some
    FRAME_SCA_REAL_DOCKER=1 python tests/sca_real/refresh.py maven-tree   # JVM/.NET/Go in docker

A case is written only when Frame matched the tool, so the corpus never records a mismatch as
the expected answer. Each case directory holds `files/` (what Frame reads, as the tool wrote it)
and `expected.json` (the tool's answer).
"""

from __future__ import annotations

import json
import shutil
import sys
import tempfile
from pathlib import Path

sys.path[:0] = [str(Path(__file__).resolve().parents[1]), str(Path(__file__).resolve().parents[2])]

from sca_real.harness import CASES, CORPUS, BY_NAME, run_case  # noqa: E402


def main(names) -> int:
    cases = [BY_NAME[n] for n in names] if names else CASES
    failed = 0
    for case in cases:
        missing = case.missing_tools()
        if missing:
            print(f"SKIP  {case.name}: missing {missing}")
            continue
        with tempfile.TemporaryDirectory() as tmp:
            try:
                truth, clean, problems = run_case(case, Path(tmp))
            except Exception as e:                                  # noqa: BLE001 - report and go on
                print(f"ERROR {case.name}: {e}")
                failed += 1
                continue
            if problems:
                print(f"FAIL  {case.name}:")
                for p in problems:
                    print(f"        {p}")
                failed += 1
                continue
            dest = CORPUS / case.name
            if dest.exists():
                shutil.rmtree(dest)
            shutil.copytree(clean, dest / "files")
            doc = {"case": case.name, "ecosystem": case.ecosystem, "pip_report": case.pip_report,
                   **truth.to_json()}
            (dest / "expected.json").write_text(json.dumps(doc, indent=1) + "\n")
            size = sum(f.stat().st_size for f in dest.rglob("*") if f.is_file())
            print(f"OK    {case.name}: {len(truth.packages)} packages, {size // 1024} KB")
    return 1 if failed else 0


if __name__ == "__main__":
    args = sys.argv[1:]
    if "--docker" in args:                       # same as FRAME_SCA_REAL_DOCKER=1
        import os
        os.environ["FRAME_SCA_REAL_DOCKER"] = "1"
        args.remove("--docker")
    sys.exit(main(args))
