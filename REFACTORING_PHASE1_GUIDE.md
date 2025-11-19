# Phase 1 Refactoring Guide - benchmarks/runner.py

## Status: IN PROGRESS

### Completed (Part 1)

✅ **Core Modules Extracted** (`benchmarks/core/`)
- `result.py` - BenchmarkResult dataclass (30 lines)
- `base_runner.py` - SMT2 execution utilities (70 lines)
- `analysis.py` - Result analysis and reporting (124 lines)
- `utils.py` in `downloaders/` - Download utilities (80 lines)

**Total Extracted:** ~304 lines from 2644 (11.5% complete)

---

## Next Steps (Part 2 - Part 6)

### Part 2: Extract Downloaders (~600 lines)

Create these files:

**`benchmarks/downloaders/qf_ax.py`** (~180 lines)
```python
"""QF_AX benchmark downloaders"""

import os
import requests
import shutil
from pathlib import Path
from typing import Optional

def download_qf_ax_samples(cache_dir: str, max_files: Optional[int] = None) -> int:
    """Download QF_AX sample benchmarks"""
    # Extract lines 910-994 from runner.py
    # Method starts at line 910: def download_qf_ax_samples
    pass

def download_qf_ax_full(cache_dir: str) -> int:
    """Download full QF_AX benchmark set"""
    # Extract lines 1297-1393 from runner.py
    # Method starts at line 1297: def download_qf_ax_full
    pass
```

**`benchmarks/downloaders/qf_bv.py`** (~200 lines)
```python
"""QF_BV benchmark downloaders"""

def download_qf_bv_samples(cache_dir: str, max_files: Optional[int] = None) -> int:
    # Extract lines 998-1090 from runner.py
    pass

def download_qf_bv_full(cache_dir: str) -> int:
    # Extract lines 1395-1495 from runner.py
    pass
```

**`benchmarks/downloaders/qf_s.py`** (~400 lines)
```python
"""QF_S string theory benchmark downloaders"""

def download_qf_s_kaluza(cache_dir: str, max_files: Optional[int] = None) -> int:
    # Extract lines 305-695 from runner.py
    pass

def download_qf_s_kaluza_full(cache_dir: str, max_files: Optional[int] = None) -> int:
    # Extract lines 696-747 from runner.py
    pass

def download_qf_s_pisa(cache_dir: str, max_files: Optional[int] = None) -> int:
    # Extract lines 748-831 from runner.py
    pass

def download_qf_s_woorpje(cache_dir: str, max_files: Optional[int] = None) -> int:
    # Extract lines 832-909 from runner.py
    pass

def download_full_kaluza(cache_dir: str) -> int:
    # Extract lines 1138-1284 from runner.py
    pass

def download_full_pisa(cache_dir: str) -> int:
    # Extract line 1285 from runner.py (calls kaluza)
    pass

def download_full_appscan(cache_dir: str) -> int:
    # Extract line 1289 from runner.py (calls kaluza)
    pass

def download_full_pyex(cache_dir: str) -> int:
    # Extract line 1293 from runner.py (calls kaluza)
    pass
```

**`benchmarks/downloaders/slcomp.py`** (~100 lines)
```python
"""SL-COMP benchmark downloaders"""

def download_slcomp_file(cache_dir: str, division: str, filename: str) -> bool:
    # Extract lines 137-160 from runner.py
    pass

def download_slcomp_division(cache_dir: str, division: str, max_files: Optional[int] = None) -> int:
    # Extract lines 161-199 from runner.py
    pass
```

**`benchmarks/downloaders/__init__.py`**
```python
"""Benchmark downloaders"""

from benchmarks.downloaders.qf_ax import download_qf_ax_samples, download_qf_ax_full
from benchmarks.downloaders.qf_bv import download_qf_bv_samples, download_qf_bv_full
from benchmarks.downloaders.qf_s import (
    download_qf_s_kaluza, download_qf_s_kaluza_full,
    download_qf_s_pisa, download_qf_s_woorpje,
    download_full_kaluza, download_full_pisa,
    download_full_appscan, download_full_pyex
)
from benchmarks.downloaders.slcomp import download_slcomp_file, download_slcomp_division
from benchmarks.downloaders.utils import download_gdrive_file, extract_archive

__all__ = [
    # QF_AX
    'download_qf_ax_samples', 'download_qf_ax_full',
    # QF_BV
    'download_qf_bv_samples', 'download_qf_bv_full',
    # QF_S
    'download_qf_s_kaluza', 'download_qf_s_kaluza_full',
    'download_qf_s_pisa', 'download_qf_s_woorpje',
    'download_full_kaluza', 'download_full_pisa',
    'download_full_appscan', 'download_full_pyex',
    # SL-COMP
    'download_slcomp_file', 'download_slcomp_division',
    # Utils
    'download_gdrive_file', 'extract_archive',
]
```

---

### Part 3: Extract Runners (~350 lines)

**`benchmarks/runners/qf_ax_runner.py`** (~120 lines)
```python
"""QF_AX benchmark runner"""

import os
import time
from typing import Optional
from benchmarks.core import BenchmarkResult, run_smt2_with_z3, parse_smt2_expected

def run_qf_ax_benchmark(cache_dir: str, source: str, filename: str,
                        full_path: Optional[str] = None) -> BenchmarkResult:
    # Extract lines 1950-1983 from runner.py
    pass

def run_qf_ax_division(cache_dir: str, source: str,
                       max_tests: Optional[int] = None) -> list:
    # Extract lines 1986-2016 from runner.py
    pass
```

**`benchmarks/runners/qf_bv_runner.py`** (~120 lines)
```python
"""QF_BV benchmark runner"""
# Extract lines 2019-2088 from runner.py
```

**`benchmarks/runners/qf_s_runner.py`** (~140 lines)
```python
"""QF_S benchmark runner"""
# Extract lines 1826-1948 from runner.py
```

**`benchmarks/runners/slcomp_runner.py`** (~150 lines)
```python
"""SL-COMP benchmark runner"""
# Extract lines 200-304 from runner.py
# Needs: SLCompParser, SMTLibStringParser, EntailmentChecker
```

---

### Part 4: Extract Curators (~350 lines)

**`benchmarks/curators/samplers.py`**
```python
"""Benchmark sampling and curation"""

import os
import random
import shutil
from pathlib import Path
from typing import Optional

def create_qf_s_curated_set(cache_dir: str, sample_size: int = 3300, seed: int = 42) -> int:
    # Extract lines 1498-1587 from runner.py
    pass

def create_slcomp_curated_set(cache_dir: str, sample_size: int = 700, seed: int = 42) -> int:
    # Extract lines 1588-1687 from runner.py
    pass

def create_qf_ax_curated_set(cache_dir: str, sample_size: int = 250, seed: int = 42) -> int:
    # Extract lines 1688-1749 from runner.py
    pass

def create_qf_bv_curated_set(cache_dir: str, sample_size: int = 250, seed: int = 42) -> int:
    # Extract lines 1752-1825 from runner.py
    pass
```

---

### Part 5: Extract Commands (~450 lines)

**`benchmarks/commands/run_cmd.py`**
```python
"""Run command implementation"""
# Extract lines 2184-2279 from runner.py
```

**`benchmarks/commands/download_cmd.py`**
```python
"""Download command implementation"""
# Extract lines 2280-2411 from runner.py
```

**`benchmarks/commands/analyze_cmd.py`**
```python
"""Analyze command implementation"""
# Extract lines 2412-2445 from runner.py
```

**`benchmarks/commands/visualize_cmd.py`**
```python
"""Visualize command implementation"""

def extract_heap_edges(formula):
    # Extract lines 2473-2489 from runner.py
    pass

def extract_predicates(formula):
    # Extract lines 2490-2562 from runner.py
    pass

def cmd_visualize(args):
    # Extract lines 2446-2562 from runner.py
    pass
```

---

### Part 6: Create New Orchestrator

**`benchmarks/runner.py` (NEW - ~250 lines)**
```python
"""Frame Benchmark Suite - Main Orchestrator"""

import os
from pathlib import Path

# Import core
from benchmarks.core import (
    BenchmarkResult,
    run_smt2_with_z3,
    parse_smt2_expected,
    analyze_results,
    print_summary,
    save_results
)

# Import all downloaders
from benchmarks.downloaders import *

# Import all runners
from benchmarks.runners import *

# Import curators
from benchmarks.curators import *

class BenchmarkOrchestrator:
    """Orchestrates all benchmark operations"""

    def __init__(self, cache_dir: str = "./benchmarks/cache", verbose: bool = False):
        self.cache_dir = cache_dir
        self.verbose = verbose
        os.makedirs(cache_dir, exist_ok=True)
        self.results = []

    # Thin wrapper methods that delegate to extracted modules
    def download_qf_ax_samples(self, max_files=None):
        return download_qf_ax_samples(self.cache_dir, max_files)

    # ... etc for all operations
```

---

## Extraction Script Template

Use this Python script to extract methods:

```python
import re

def extract_method(file_path, method_name, start_line, end_line):
    """Extract method from file"""
    with open(file_path, 'r') as f:
        lines = f.readlines()

    # Get method lines
    method_lines = lines[start_line-1:end_line]

    # Remove class indentation (4 spaces)
    extracted = []
    for line in method_lines:
        if line.startswith('    '):
            extracted.append(line[4:])  # Remove 4 spaces
        else:
            extracted.append(line)

    return ''.join(extracted)

# Example usage
method_code = extract_method(
    '/home/user/frame/benchmarks/runner.py',
    'download_qf_ax_samples',
    910,  # start line
    994   # end line
)

# Write to new file
with open('/home/user/frame/benchmarks/downloaders/qf_ax.py', 'a') as f:
    f.write(method_code)
```

---

## Important Notes

### Imports to Add

Each extracted file needs proper imports:

```python
import os
import sys
import time
import json
import random
import shutil
import zipfile
import tarfile
import subprocess
import requests
from pathlib import Path
from typing import Dict, List, Tuple, Optional
from dataclasses import dataclass, asdict
from collections import defaultdict
```

### Signature Changes

Methods like `def download_qf_ax_samples(self, max_files=None)` become:
```python
def download_qf_ax_samples(cache_dir: str, max_files: Optional[int] = None) -> int:
```

Replace `self.cache_dir` with `cache_dir` parameter throughout.

### Testing After Each Part

After extracting each module, test with:
```bash
python -m pytest tests/ -v
python -m benchmarks run --division qf_ax_curated --max-tests 10
```

---

## Progress Tracking

- [x] Part 1: Core modules (304 lines) - COMPLETE
- [ ] Part 2: Downloaders (600 lines)
- [ ] Part 3: Runners (350 lines)
- [ ] Part 4: Curators (350 lines)
- [ ] Part 5: Commands (450 lines)
- [ ] Part 6: New orchestrator (250 lines)
- [ ] Part 7: Update __main__.py
- [ ] Part 8: Full integration test
- [ ] Part 9: Delete old runner.py

**Total:** 2644 lines → ~12 files averaging 220 lines each

---

## Estimated Time

- Part 1: ✅ Complete (1 hour)
- Parts 2-6: ~5-6 hours (methodical extraction)
- Testing & integration: ~2 hours
- **Total:** ~8-9 hours for complete refactoring

---

## Benefits After Completion

- All files < 500 lines ✅
- Clear module boundaries
- Easy to test individual components
- Simple to add new benchmark types
- Better code organization and maintainability
