"""NIST Juliet Test Suite downloader for C/C++"""

import os
import re
import shutil
import zipfile
import urllib.request
from typing import Optional, Dict, List, Tuple
from pathlib import Path


# NIST SARD Juliet Test Suite download URL
JULIET_URL = "https://samate.nist.gov/SARD/downloads/test-suites/2017-10-01-juliet-test-suite-for-c-cplusplus-v1-3.zip"
JULIET_FILENAME = "juliet-c-cpp-1.3.zip"


def download_juliet(cache_dir: str, max_files: Optional[int] = None) -> int:
    """
    Download NIST Juliet Test Suite for C/C++.

    The test suite contains ~57,000 test cases covering 118 CWEs.
    Each test case has 'good' (safe) and 'bad' (vulnerable) variants.

    Args:
        cache_dir: Directory to store benchmarks
        max_files: Maximum files to download (None for all)

    Returns:
        Number of test files downloaded
    """
    juliet_dir = os.path.join(cache_dir, 'juliet')
    testcases_dir = os.path.join(juliet_dir, 'testcases')

    # Check if already downloaded
    if os.path.exists(testcases_dir):
        files = list(Path(testcases_dir).rglob('*.c')) + list(Path(testcases_dir).rglob('*.cpp'))
        if files:
            print(f"Juliet already downloaded: {len(files)} files")
            return len(files)

    print("Downloading NIST Juliet Test Suite for C/C++...")
    print("(This is a large download: ~400MB)")
    os.makedirs(juliet_dir, exist_ok=True)

    zip_path = os.path.join(juliet_dir, JULIET_FILENAME)

    try:
        # Download if not already present
        if not os.path.exists(zip_path):
            print(f"Downloading from {JULIET_URL}...")
            urllib.request.urlretrieve(JULIET_URL, zip_path)

        # Extract
        print("Extracting test cases...")
        with zipfile.ZipFile(zip_path, 'r') as zf:
            # Find testcases directory in archive
            for member in zf.namelist():
                if 'testcases/' in member or 'testcases\\' in member:
                    zf.extract(member, juliet_dir)

        # Move testcases to expected location if nested
        for subdir in ['C', 'testcases']:
            nested = os.path.join(juliet_dir, subdir, 'testcases')
            if os.path.exists(nested) and not os.path.exists(testcases_dir):
                shutil.move(nested, testcases_dir)
                break

        # Count files
        files = list(Path(testcases_dir).rglob('*.c')) + list(Path(testcases_dir).rglob('*.cpp'))
        if max_files:
            files = files[:max_files]

        print(f"Downloaded Juliet: {len(files)} test files")
        return len(files)

    except Exception as e:
        print(f"ERROR downloading Juliet: {e}")
        return 0


def parse_juliet_testcase(filepath: str) -> Tuple[str, bool, str]:
    """
    Parse Juliet test case metadata from filepath.

    Juliet naming convention:
    - Files with ONLY 'good' in name (e.g., _good.c, _goodG2B.cpp) -> safe
    - Files with '_bad' in name -> vulnerable
    - Combined files (contain both bad and good code) -> vulnerable

    Combined files are the most common and contain both vulnerable (_bad function)
    and safe (_good function) code in the same file. These are still vulnerable
    as they contain exploitable code paths.

    Returns:
        Tuple of (cwe_id, is_vulnerable, language)
    """
    filename = os.path.basename(filepath)
    path_parts = filepath.replace('\\', '/').split('/')

    # Extract CWE from path or filename
    cwe_id = 'unknown'
    for part in path_parts + [filename]:
        match = re.search(r'CWE(\d+)', part)
        if match:
            cwe_id = f"CWE-{match.group(1)}"
            break

    # Determine if vulnerable (bad) or safe (good)
    # Key insight: Files are ONLY safe if they have 'good' pattern but NOT 'bad'
    # Combined files (most common) have neither suffix but ARE vulnerable
    filename_lower = filename.lower()

    # Check for good-only patterns (safe files)
    is_good_only = (
        '_good.' in filename_lower or           # ends with _good.c/.cpp
        '_goodg2b' in filename_lower or         # goodG2B pattern
        '_goodb2g' in filename_lower or         # goodB2G pattern
        'good_' in filename_lower               # good_ prefix pattern
    ) and '_bad' not in filename_lower

    # File is vulnerable if it's NOT a good-only file
    # This includes: _bad files, combined files, and other test files
    is_vulnerable = not is_good_only

    # Determine language
    language = 'cpp' if filename.endswith('.cpp') else 'c'

    return cwe_id, is_vulnerable, language


def get_juliet_test_files(cache_dir: str, cwe_filter: Optional[str] = None) -> List[str]:
    """
    Get list of Juliet test files.

    Args:
        cache_dir: Cache directory
        cwe_filter: Optional CWE filter (e.g., "CWE-120" or "120")

    Returns:
        List of file paths
    """
    testcases_dir = os.path.join(cache_dir, 'juliet', 'testcases')
    if not os.path.exists(testcases_dir):
        return []

    files = []
    for root, dirs, filenames in os.walk(testcases_dir):
        for filename in filenames:
            if filename.endswith('.c') or filename.endswith('.cpp'):
                filepath = os.path.join(root, filename)

                # Apply CWE filter if specified
                if cwe_filter:
                    cwe_norm = cwe_filter.upper().replace('CWE-', '').replace('CWE', '')
                    if f'CWE{cwe_norm}' not in filepath.upper():
                        continue

                files.append(filepath)

    return sorted(files)


def get_juliet_cwes(cache_dir: str) -> List[str]:
    """Get list of CWEs covered by Juliet"""
    testcases_dir = os.path.join(cache_dir, 'juliet', 'testcases')
    if not os.path.exists(testcases_dir):
        return []

    cwes = set()
    for item in os.listdir(testcases_dir):
        match = re.match(r'CWE(\d+)', item)
        if match:
            cwes.add(f"CWE-{match.group(1)}")

    return sorted(cwes)


def create_juliet_curated_set(
    cache_dir: str,
    sample_size: int = 1000,
    seed: int = 42
) -> int:
    """
    Create a curated subset of Juliet benchmarks.

    Ensures balanced representation of:
    - Different CWEs
    - Bad (vulnerable) and good (safe) variants
    - C and C++ files

    Args:
        cache_dir: Cache directory
        sample_size: Target size for curated set
        seed: Random seed for reproducibility

    Returns:
        Number of files in curated set
    """
    import random

    # Ensure full set exists
    full_count = download_juliet(cache_dir)
    if full_count == 0:
        return 0

    test_files = get_juliet_test_files(cache_dir)
    if not test_files:
        print("No Juliet test files found")
        return 0

    # Group by CWE, vulnerability status, and language
    by_category: Dict[str, List[str]] = {}
    for filepath in test_files:
        cwe_id, is_vuln, lang = parse_juliet_testcase(filepath)
        key = f"{cwe_id}_{lang}_{'bad' if is_vuln else 'good'}"

        if key not in by_category:
            by_category[key] = []
        by_category[key].append(filepath)

    # Stratified sampling
    random.seed(seed)
    curated_files = []

    # Limit categories to ensure diversity
    samples_per_category = max(1, sample_size // min(len(by_category), 200))

    for category, files in sorted(by_category.items()):
        n = min(len(files), samples_per_category)
        curated_files.extend(random.sample(files, n))

        if len(curated_files) >= sample_size:
            break

    curated_files = curated_files[:sample_size]

    # Create curated directory
    curated_dir = os.path.join(cache_dir, 'juliet', 'juliet_curated')
    if os.path.exists(curated_dir):
        shutil.rmtree(curated_dir)
    os.makedirs(curated_dir)

    # Copy files with CWE prefix for organization
    for filepath in curated_files:
        cwe_id, _, _ = parse_juliet_testcase(filepath)
        filename = os.path.basename(filepath)
        # Add CWE prefix if not already present
        if not filename.startswith('CWE'):
            filename = f"{cwe_id.replace('-', '')}_{filename}"
        shutil.copy(filepath, os.path.join(curated_dir, filename))

    print(f"Created Juliet curated set: {len(curated_files)} files")
    return len(curated_files)
