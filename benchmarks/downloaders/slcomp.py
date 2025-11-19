"""SL-COMP benchmark downloaders"""

import os
import time
import requests
from typing import Optional


def download_slcomp_file(cache_dir: str, division: str, filename: str) -> bool:
    """Download a single SL-COMP benchmark file"""
    cache_path = os.path.join(cache_dir, division, filename)

    if os.path.exists(cache_path):
        return True

    url = f"https://raw.githubusercontent.com/sl-comp/SL-COMP18/master/bench/{division}/{filename}"

    try:
        response = requests.get(url, timeout=10)
        if response.status_code == 200:
            os.makedirs(os.path.dirname(cache_path), exist_ok=True)
            with open(cache_path, 'w') as f:
                f.write(response.text)
            print(f"  ✓ Downloaded {filename}")
            return True
        else:
            print(f"  ✗ Failed to download {filename} (HTTP {response.status_code})")
            return False
    except Exception as e:
        print(f"  ✗ Error downloading {filename}: {e}")
        return False



def download_slcomp_division(cache_dir: str, division: str, max_files: Optional[int] = None) -> int:
    """Download all benchmarks in a SL-COMP division"""
    # NOTE: This downloads a small sample. For full benchmarks, they are
    # already cached in benchmarks/cache/ from the repository
    SAMPLES = {
        # Entailment
        'qf_shls_entl': ['bolognesa-10-e01.tptp.smt2', 'bolognesa-10-e02.tptp.smt2'],
        'qf_shid_entl': ['bolognesa-05-e01.tptp.smt2', 'clones-01-e01.tptp.smt2'],
        'qf_shlid_entl': ['nll-vc01.smt2', 'nll-vc02.smt2'],
        'qf_shidlia_entl': ['dll-vc01.smt2', 'dll-vc02.smt2'],
        'shid_entl': ['node-vc01.smt2', 'node-vc02.smt2'],
        'shidlia_entl': ['tree-vc01.smt2', 'tree-vc02.smt2'],
        # Satisfiability
        'qf_shid_sat': ['abduced00.defs.smt2', 'atll-01.smt2', 'dll-01.smt2'],
        'qf_shls_sat': ['ls-01.smt2', 'ls-02.smt2'],
        'qf_bsl_sat': ['chain-sat-1.cvc4.smt2', 'chain-sat-2.cvc4.smt2'],
        'qf_bsllia_sat': ['lseg-1.cvc4.smt2', 'lseg-2.cvc4.smt2'],
        'bsl_sat': ['dispose-iter-2.cvc4.smt2', 'test-dispose-1.cvc4.smt2'],
        'qf_shidlia_sat': ['dll-sat-01.smt2', 'dll-sat-02.smt2'],
    }

    if division not in SAMPLES:
        print(f"No sample benchmarks defined for {division}")
        return 0

    print(f"\nDownloading {division} benchmarks...")
    files = SAMPLES[division]
    if max_files:
        files = files[:max_files]

    success = 0
    for filename in files:
        if download_slcomp_file(cache_dir, division, filename):
            success += 1
        time.sleep(0.5)  # Rate limiting

    print(f"Downloaded {success}/{len(files)} files")
    return success

