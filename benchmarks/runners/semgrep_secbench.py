"""Run Semgrep over the real SecBench.js benchmark for a head-to-head with Frame.

Uses Semgrep's out-of-the-box ruleset (`p/default`, the same set `semgrep scan`
runs with no config) and the *identical* methodology as
run_secbench_real_division: recall on each vulnerable package's ground-truth
sink file, precision/FPR on the patched version. Semgrep is invoked once over
all files (batched) for speed; findings are mapped to a category by the CWE in
each rule's metadata.

Run:  python -m benchmarks.runners.semgrep_secbench [max_per_cat]
Requires:  pip install semgrep
"""

import json
import os
import shutil
import subprocess
import sys
import tempfile
from collections import defaultdict

from benchmarks.downloaders.secbench_real import get_secbench_real_entries, CATEGORY_CWE

# CWEs that count as a hit for each category (generous to Semgrep).
CATEGORY_CWES = {
    'command-injection': {'CWE-78', 'CWE-77'},
    'code-injection': {'CWE-94', 'CWE-95', 'CWE-96'},
    'path-traversal': {'CWE-22', 'CWE-23', 'CWE-73', 'CWE-35'},
    'prototype-pollution': {'CWE-1321', 'CWE-915'},
    'redos': {'CWE-1333', 'CWE-400', 'CWE-730', 'CWE-185'},
}

SEMGREP_CONFIG = 'p/default'


def _run_semgrep(paths):
    """Run Semgrep once over `paths`; return {orig_path: set(CWE-NNN)}.

    Semgrep rejects long lists of individual file targets ("invalid scanning
    root"), so stage every file into one temp directory under a unique name
    (preserving the .js/.ts extension) and scan that single root, mapping
    results back to the original paths."""
    out = defaultdict(set)
    if not paths:
        return out
    tmp = tempfile.mkdtemp(prefix='sg_secbench_')
    name_to_orig = {}
    try:
        for i, p in enumerate(paths):
            ext = '.ts' if p.endswith('.ts') else '.js'
            name = f"{i:05d}{ext}"
            name_to_orig[name] = p
            shutil.copyfile(p, os.path.join(tmp, name))
        cmd = ['semgrep', '--config', SEMGREP_CONFIG, '--json', '--quiet',
               '--metrics=off', tmp]
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=3600)
        try:
            data = json.loads(proc.stdout)
        except ValueError:
            sys.stderr.write(proc.stderr[-2000:])
            return out
        for r in data.get('results', []):
            orig = name_to_orig.get(os.path.basename(r['path']))
            if orig is None:
                continue
            cwes = r.get('extra', {}).get('metadata', {}).get('cwe', [])
            if isinstance(cwes, str):
                cwes = [cwes]
            for c in cwes:
                out[orig].add(c.split(':')[0].strip())
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    return out


def run(cache_dir='./benchmarks/cache', max_per_cat=60):
    entries = get_secbench_real_entries(cache_dir, max_per_cat=max_per_cat)

    files = set()
    for e in entries:
        if e['vuln_file']:
            files.add(e['vuln_file'])
        if e['fixed_file']:
            files.add(e['fixed_file'])
    print(f"Running Semgrep ({SEMGREP_CONFIG}) over {len(files)} files...")
    detected = _run_semgrep(sorted(files))

    cats = {c: {'tp': 0, 'fp': 0, 'fn': 0, 'neg': 0, 'skip': 0} for c in CATEGORY_CWE}
    for e in entries:
        cat = e['category']
        want = CATEGORY_CWES[cat]
        if not e['vuln_file']:
            cats[cat]['skip'] += 1
            continue
        if detected.get(e['vuln_file'], set()) & want:
            cats[cat]['tp'] += 1
        else:
            cats[cat]['fn'] += 1
        if e['fixed_file']:
            cats[cat]['neg'] += 1
            if detected.get(e['fixed_file'], set()) & want:
                cats[cat]['fp'] += 1

    print("\nSemgrep on SecBench.js by category:")
    tot = {'tp': 0, 'fp': 0, 'fn': 0, 'neg': 0}
    for c, d in cats.items():
        for k in tot:
            tot[k] += d[k]
        P = d['tp'] / (d['tp'] + d['fp']) if (d['tp'] + d['fp']) else 0.0
        R = d['tp'] / (d['tp'] + d['fn']) if (d['tp'] + d['fn']) else 0.0
        fpr = d['fp'] / d['neg'] if d['neg'] else 0.0
        print(f"  {c:22} TP={d['tp']:3} FP={d['fp']:3} FN={d['fn']:3} "
              f"P={P:.0%} R={R:.0%} TPR-FPR={R-fpr:+.0%}")
    P = tot['tp'] / (tot['tp'] + tot['fp']) if (tot['tp'] + tot['fp']) else 0.0
    R = tot['tp'] / (tot['tp'] + tot['fn']) if (tot['tp'] + tot['fn']) else 0.0
    fpr = tot['fp'] / tot['neg'] if tot['neg'] else 0.0
    print(f"  {'OVERALL':22} TP={tot['tp']:3} FP={tot['fp']:3} FN={tot['fn']:3} "
          f"P={P:.0%} R={R:.0%} TPR-FPR={R-fpr:+.0%}")
    return cats


if __name__ == '__main__':
    n = int(sys.argv[1]) if len(sys.argv) > 1 else 60
    run(max_per_cat=n)
