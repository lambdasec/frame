"""`frame deps` against the package managers themselves (see tests/sca_real/harness.py).

Live: runs only with FRAME_SCA_REAL=1 (the `sca-real` CI job installs every tool). There, a
missing tool FAILS the case instead of skipping it, so CI cannot pass by not running. Locally,
FRAME_SCA_REAL_DOCKER=1 runs Maven, Gradle, .NET and Go in their official images.
"""

import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))

from sca_real.harness import CASES, run_case  # noqa: E402

LIVE = os.environ.get("FRAME_SCA_REAL", "") not in ("", "0")
# cases a run may leave out on purpose (comma separated), e.g. swift where no toolchain exists
OPTIONAL = {n.strip() for n in os.environ.get("FRAME_SCA_REAL_SKIP", "").split(",") if n.strip()}

pytestmark = pytest.mark.skipif(not LIVE, reason="set FRAME_SCA_REAL=1 to run the package managers")


@pytest.mark.parametrize("case", CASES, ids=[c.name for c in CASES])
def test_frame_matches_the_package_manager(case, tmp_path):
    if case.name in OPTIONAL:
        pytest.skip(f"{case.name} listed in FRAME_SCA_REAL_SKIP")
    missing = case.missing_tools()
    if missing:
        pytest.fail(f"{case.name} needs {missing} on PATH (FRAME_SCA_REAL=1 never skips a missing tool)")
    if case.source is not None and not case.source.is_dir():
        pytest.fail(f"{case.name}: source project {case.source} is not present")
    truth, _, problems = run_case(case, tmp_path)
    assert truth.packages, f"{case.name}: the tool reported no packages"
    assert not problems, f"{case.name}:\n  " + "\n  ".join(problems)
