"""OWASP BenchmarkJava downloader"""

import os
import csv
import shutil
import subprocess
from typing import Optional, Dict, List
from pathlib import Path


OWASP_JAVA_REPO = "https://github.com/OWASP-Benchmark/BenchmarkJava.git"
OWASP_JAVA_BRANCH = "master"


def download_owasp_java(cache_dir: str, max_files: Optional[int] = None) -> int:
    """
    Download OWASP BenchmarkJava test suite.

    The benchmark is a Java web application with ~2,800 test cases.
    Each test case is a separate servlet with a known CWE.

    Args:
        cache_dir: Directory to store benchmarks
        max_files: Maximum files to download (None for all)

    Returns:
        Number of test files downloaded
    """
    owasp_dir = os.path.join(cache_dir, 'owasp_java')
    src_dir = os.path.join(owasp_dir, 'src')
    expected_results_path = os.path.join(owasp_dir, 'expectedresults.csv')

    # Check if already downloaded
    if os.path.exists(src_dir) and os.path.exists(expected_results_path):
        files = list(Path(src_dir).rglob('*.java'))
        print(f"OWASP Java already downloaded: {len(files)} files")
        return len(files)

    print("Downloading OWASP BenchmarkJava...")
    os.makedirs(owasp_dir, exist_ok=True)

    # Clone the repository (shallow clone to save space)
    temp_dir = os.path.join(cache_dir, '_owasp_java_temp')
    if os.path.exists(temp_dir):
        shutil.rmtree(temp_dir)

    try:
        subprocess.run([
            'git', 'clone',
            '--depth', '1',
            '--branch', OWASP_JAVA_BRANCH,
            OWASP_JAVA_REPO,
            temp_dir
        ], check=True, capture_output=True)

        # Copy source files
        repo_src = os.path.join(temp_dir, 'src', 'main', 'java', 'org', 'owasp', 'benchmark', 'testcode')
        if os.path.exists(repo_src):
            if os.path.exists(src_dir):
                shutil.rmtree(src_dir)
            shutil.copytree(repo_src, src_dir)

        # Copy expected results CSV
        repo_expected = os.path.join(temp_dir, 'expectedresults-1.2.csv')
        if os.path.exists(repo_expected):
            shutil.copy(repo_expected, expected_results_path)
        else:
            # Try alternate locations
            import glob
            for pattern in ['expectedresults*.csv', 'results/*.csv']:
                matches = glob.glob(os.path.join(temp_dir, pattern))
                if matches:
                    shutil.copy(matches[0], expected_results_path)
                    break

        # Clean up
        shutil.rmtree(temp_dir)

        files = list(Path(src_dir).rglob('*.java'))
        if max_files:
            files = files[:max_files]

        print(f"Downloaded OWASP Java: {len(files)} test files")
        return len(files)

    except subprocess.CalledProcessError as e:
        print(f"ERROR: Failed to clone OWASP Java: {e}")
        if os.path.exists(temp_dir):
            shutil.rmtree(temp_dir)
        return 0
    except Exception as e:
        print(f"ERROR: {e}")
        if os.path.exists(temp_dir):
            shutil.rmtree(temp_dir)
        return 0


def load_owasp_java_expected_results(cache_dir: str) -> Dict[str, Dict]:
    """
    Load expected results from OWASP BenchmarkJava CSV.

    Returns:
        Dict mapping test name -> {cwe, category, vulnerable}
    """
    expected_path = os.path.join(cache_dir, 'owasp_java', 'expectedresults.csv')

    if not os.path.exists(expected_path):
        print(f"Expected results not found: {expected_path}")
        return {}

    results = {}
    try:
        with open(expected_path, 'r') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue

                parts = line.split(',')
                if len(parts) >= 4:
                    test_name = parts[0].strip()
                    category = parts[1].strip()
                    vulnerable = parts[2].strip().lower() == 'true'
                    cwe = parts[3].strip()

                    results[test_name] = {
                        'cwe': cwe,
                        'category': category,
                        'vulnerable': vulnerable,
                    }
    except Exception as e:
        print(f"ERROR loading expected results: {e}")

    return results


def get_owasp_java_test_files(cache_dir: str) -> List[str]:
    """Get list of OWASP Java test files"""
    src_dir = os.path.join(cache_dir, 'owasp_java', 'src')
    if not os.path.exists(src_dir):
        return []

    files = []
    for root, dirs, filenames in os.walk(src_dir):
        for filename in filenames:
            if filename.startswith('BenchmarkTest') and filename.endswith('.java'):
                files.append(os.path.join(root, filename))

    return sorted(files)


def create_owasp_java_curated_set(
    cache_dir: str,
    sample_size: int = 500,
    seed: int = 42
) -> int:
    """
    Create a curated subset of OWASP Java benchmarks.

    Args:
        cache_dir: Cache directory
        sample_size: Target size for curated set
        seed: Random seed for reproducibility

    Returns:
        Number of files in curated set
    """
    import random

    # Ensure full set exists
    full_count = download_owasp_java(cache_dir)
    if full_count == 0:
        return 0

    # Load expected results for stratified sampling
    expected = load_owasp_java_expected_results(cache_dir)
    test_files = get_owasp_java_test_files(cache_dir)

    if not test_files:
        print("No OWASP Java test files found")
        return 0

    # Group by CWE and vulnerability status
    by_category: Dict[str, List[str]] = {}
    for filepath in test_files:
        test_name = os.path.basename(filepath).replace('.java', '')
        info = expected.get(test_name, {})
        cwe = info.get('cwe', 'unknown')
        vulnerable = info.get('vulnerable', False)
        key = f"{cwe}_{'vuln' if vulnerable else 'safe'}"

        if key not in by_category:
            by_category[key] = []
        by_category[key].append(filepath)

    # Stratified sampling
    random.seed(seed)
    curated_files = []
    samples_per_category = max(1, sample_size // len(by_category))

    for category, files in sorted(by_category.items()):
        n = min(len(files), samples_per_category)
        curated_files.extend(random.sample(files, n))

    # Fill remaining quota
    remaining = sample_size - len(curated_files)
    if remaining > 0:
        all_remaining = [f for f in test_files if f not in curated_files]
        if all_remaining:
            curated_files.extend(random.sample(all_remaining, min(remaining, len(all_remaining))))

    # Create curated directory
    curated_dir = os.path.join(cache_dir, 'owasp_java', 'owasp_java_curated')
    if os.path.exists(curated_dir):
        shutil.rmtree(curated_dir)
    os.makedirs(curated_dir)

    # Copy files
    for filepath in curated_files:
        filename = os.path.basename(filepath)
        shutil.copy(filepath, os.path.join(curated_dir, filename))

    # Copy expected results
    expected_src = os.path.join(cache_dir, 'owasp_java', 'expectedresults.csv')
    if os.path.exists(expected_src):
        shutil.copy(expected_src, os.path.join(curated_dir, 'expectedresults.csv'))

    print(f"Created OWASP Java curated set: {len(curated_files)} files")
    return len(curated_files)
