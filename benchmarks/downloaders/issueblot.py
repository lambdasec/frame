"""IssueBlot.NET downloader for C# security benchmarks"""

import os
import re
import shutil
import subprocess
from typing import Optional, Dict, List, Tuple
from pathlib import Path


ISSUEBLOT_REPO = "https://github.com/CodeThreat/IssueBlot.NET.git"
ISSUEBLOT_BRANCH = "main"


def download_issueblot(cache_dir: str, max_files: Optional[int] = None) -> int:
    """
    Download IssueBlot.NET benchmark suite for C#.

    IssueBlot.NET contains vulnerable C# code samples across multiple
    .NET frameworks (Core MVC, Core Standalone, NET MVC, NET WCF, NET WebForms).

    Args:
        cache_dir: Directory to store benchmarks
        max_files: Maximum files to download (None for all)

    Returns:
        Number of test files downloaded
    """
    issueblot_dir = os.path.join(cache_dir, 'issueblot')
    src_dir = os.path.join(issueblot_dir, 'src')

    # Check if already downloaded
    if os.path.exists(src_dir):
        files = list(Path(src_dir).rglob('*.cs'))
        if files:
            print(f"IssueBlot.NET already downloaded: {len(files)} files")
            return len(files)

    print("Downloading IssueBlot.NET...")
    os.makedirs(issueblot_dir, exist_ok=True)

    # Clone the repository
    temp_dir = os.path.join(cache_dir, '_issueblot_temp')
    if os.path.exists(temp_dir):
        shutil.rmtree(temp_dir)

    try:
        subprocess.run([
            'git', 'clone',
            '--depth', '1',
            '--branch', ISSUEBLOT_BRANCH,
            ISSUEBLOT_REPO,
            temp_dir
        ], check=True, capture_output=True)

        # Copy all C# source files
        if os.path.exists(src_dir):
            shutil.rmtree(src_dir)
        os.makedirs(src_dir)

        for root, dirs, filenames in os.walk(temp_dir):
            # Skip git and bin/obj directories
            dirs[:] = [d for d in dirs if d not in ['.git', 'bin', 'obj', 'packages']]

            for filename in filenames:
                if filename.endswith('.cs'):
                    src_path = os.path.join(root, filename)
                    # Preserve relative path structure
                    rel_path = os.path.relpath(root, temp_dir)
                    dest_dir = os.path.join(src_dir, rel_path)
                    os.makedirs(dest_dir, exist_ok=True)
                    shutil.copy(src_path, os.path.join(dest_dir, filename))

        # Clean up
        shutil.rmtree(temp_dir)

        files = list(Path(src_dir).rglob('*.cs'))
        if max_files:
            files = files[:max_files]

        print(f"Downloaded IssueBlot.NET: {len(files)} C# files")
        return len(files)

    except subprocess.CalledProcessError as e:
        print(f"ERROR: Failed to clone IssueBlot.NET: {e}")
        if os.path.exists(temp_dir):
            shutil.rmtree(temp_dir)
        return 0
    except Exception as e:
        print(f"ERROR: {e}")
        if os.path.exists(temp_dir):
            shutil.rmtree(temp_dir)
        return 0


def parse_issueblot_testcase(filepath: str, content: str) -> Tuple[str, bool, List[str]]:
    """
    Parse IssueBlot.NET test case metadata.

    IssueBlot uses naming conventions and comments to indicate vulnerabilities:
    - Files with 'Vulnerable', 'Unsafe', 'Bad' in name/path are vulnerable
    - Comments may contain CWE references

    Returns:
        Tuple of (primary_cwe, is_vulnerable, all_cwes)
    """
    filename = os.path.basename(filepath).lower()
    path_lower = filepath.lower()

    # Check for vulnerability indicators in path/filename
    vuln_indicators = ['vulnerable', 'unsafe', 'bad', 'insecure', 'weak']
    safe_indicators = ['safe', 'secure', 'fixed', 'good']

    is_vulnerable = any(ind in path_lower for ind in vuln_indicators)
    is_safe = any(ind in path_lower for ind in safe_indicators)

    # Default to vulnerable if not clearly marked as safe
    if not is_safe and not is_vulnerable:
        is_vulnerable = True  # IssueBlot is primarily vulnerable code

    # Extract CWEs from content
    cwes = []
    cwe_pattern = r'CWE[-_]?(\d+)'
    for match in re.finditer(cwe_pattern, content, re.IGNORECASE):
        cwes.append(f"CWE-{match.group(1)}")

    # Infer CWE from vulnerability type in path
    cwe_hints = {
        'sql': 'CWE-89',
        'xss': 'CWE-79',
        'command': 'CWE-78',
        'path': 'CWE-22',
        'traversal': 'CWE-22',
        'deserialization': 'CWE-502',
        'xxe': 'CWE-611',
        'crypto': 'CWE-327',
        'injection': 'CWE-89',
        'ldap': 'CWE-90',
        'xpath': 'CWE-643',
    }

    for hint, cwe in cwe_hints.items():
        if hint in path_lower and cwe not in cwes:
            cwes.append(cwe)

    primary_cwe = cwes[0] if cwes else 'CWE-unknown'

    return primary_cwe, is_vulnerable, cwes


def get_issueblot_test_files(cache_dir: str) -> List[str]:
    """Get list of IssueBlot.NET test files"""
    src_dir = os.path.join(cache_dir, 'issueblot', 'src')
    if not os.path.exists(src_dir):
        return []

    files = []
    for root, dirs, filenames in os.walk(src_dir):
        for filename in filenames:
            if filename.endswith('.cs'):
                files.append(os.path.join(root, filename))

    return sorted(files)


def create_issueblot_curated_set(
    cache_dir: str,
    sample_size: int = 200,
    seed: int = 42
) -> int:
    """
    Create a curated subset of IssueBlot.NET benchmarks.

    Args:
        cache_dir: Cache directory
        sample_size: Target size for curated set
        seed: Random seed for reproducibility

    Returns:
        Number of files in curated set
    """
    import random

    # Ensure full set exists
    full_count = download_issueblot(cache_dir)
    if full_count == 0:
        return 0

    test_files = get_issueblot_test_files(cache_dir)
    if not test_files:
        print("No IssueBlot.NET test files found")
        return 0

    # Group by framework (from path)
    by_framework: Dict[str, List[str]] = {}
    for filepath in test_files:
        # Extract framework from path
        parts = filepath.replace('\\', '/').split('/')
        framework = 'other'
        for part in parts:
            if 'Core' in part or 'MVC' in part or 'WCF' in part or 'WebForms' in part:
                framework = part
                break

        if framework not in by_framework:
            by_framework[framework] = []
        by_framework[framework].append(filepath)

    # Stratified sampling
    random.seed(seed)
    curated_files = []
    samples_per_framework = max(1, sample_size // len(by_framework))

    for framework, files in sorted(by_framework.items()):
        n = min(len(files), samples_per_framework)
        curated_files.extend(random.sample(files, n))

    curated_files = curated_files[:sample_size]

    # Create curated directory
    curated_dir = os.path.join(cache_dir, 'issueblot', 'issueblot_curated')
    if os.path.exists(curated_dir):
        shutil.rmtree(curated_dir)
    os.makedirs(curated_dir)

    # Copy files
    for i, filepath in enumerate(curated_files):
        filename = os.path.basename(filepath)
        # Ensure unique names
        dest_name = f"{i:04d}_{filename}"
        shutil.copy(filepath, os.path.join(curated_dir, dest_name))

    print(f"Created IssueBlot.NET curated set: {len(curated_files)} files")
    return len(curated_files)
