"""Rendering Helm charts with Helm itself (`frame iac --render-helm`).

A chart's templates are Go templates; only Helm renders them as a cluster would receive them.
With `--render-helm`, every chart under the target (a `Chart.yaml`, not inside another chart's
`charts/`, since a subchart renders with its parent) is rendered with `helm template` and the
chart's own default values, and the output is read as Kubernetes manifests. Nothing is fetched:
a chart whose dependencies are not in its `charts/` directory is a warning, and values schemas
are not validated (one may reference a URL). Each object is
attributed to the template Helm names in its `# Source:` comment; a rendered line does not
correspond to a template line, so a finding points at the template file (line 1) and names the
field.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path
from typing import List, Optional, Tuple

TIMEOUT = 120
RELEASE = "release"


def charts(root: Path, excluded) -> List[Path]:
    from frame.sil.scanner import FrameScanner
    out = []
    for chart in sorted(root.rglob("Chart.yaml")):
        d = chart.parent
        if FrameScanner._is_excluded_dir_member(chart, root, excluded):
            continue
        if any(p.name == "charts" and (p.parent / "Chart.yaml").is_file() for p in d.parents):
            continue                                     # a subchart: rendered with its parent
        out.append(d)
    return out


def render(chart: Path, helm: Optional[str] = None) -> Tuple[Optional[str], str]:
    """(rendered YAML, "") or (None, the reason it could not be rendered)."""
    helm = helm or shutil.which("helm")
    if helm is None:
        return None, "helm is not installed (needed by --render-helm)"
    env = {k: v for k, v in os.environ.items() if not k.startswith("HELM_")}
    try:
        # --skip-schema-validation: a values schema may reference a URL, and nothing is fetched
        proc = subprocess.run([helm, "template", RELEASE, str(chart), "--namespace", "default",
                               "--skip-schema-validation"],
                              capture_output=True, text=True, timeout=TIMEOUT, env=env)
    except (OSError, subprocess.TimeoutExpired) as e:
        return None, f"helm template failed: {e}"
    if proc.returncode != 0:
        err = proc.stderr.strip()
        if "checking for chart dependencies" in err or "missing in charts/" in err:
            return None, "its dependencies are not in charts/ (run `helm dependency build` first)"
        reason = (err.splitlines() or ["no output"])[-1]
        return None, f"helm template failed: {reason[:200]}"
    return proc.stdout, ""


def split_sources(rendered: str) -> List[Tuple[str, str]]:
    """(source template, document text) for each document Helm wrote."""
    out: List[Tuple[str, str]] = []
    source, buf = "", []
    for line in rendered.splitlines(keepends=True):
        if line.rstrip() == "---":
            if "".join(buf).strip():
                out.append((source, "".join(buf)))
            source, buf = "", []
            continue
        if line.startswith("# Source: "):
            source = line[len("# Source: "):].strip()
        buf.append(line)
    if "".join(buf).strip():
        out.append((source, "".join(buf)))
    return out


__all__ = ["charts", "render", "split_sources"]
