"""SecBench.js downloader for JavaScript/TypeScript security benchmarks"""

import os
import json
import shutil
import subprocess
from typing import Optional, Dict, List, Tuple
from pathlib import Path


# SecBench.js repository (ICSE 2023 paper)
# Paper: https://software-lab.org/publications/icse2023_SecBenchJS.pdf
SECBENCH_REPO = "https://github.com/cristianstaicu/SecBench.js.git"
SECBENCH_BRANCH = "main"

# Fallback: Use NodeGoat as a well-known vulnerable Node.js app
NODEGOAT_REPO = "https://github.com/OWASP/NodeGoat.git"
NODEGOAT_BRANCH = "master"


def download_secbench_js(cache_dir: str, max_files: Optional[int] = None) -> int:
    """
    Download SecBench.js benchmark suite for JavaScript.

    SecBench.js contains 600 vulnerabilities across the 5 most common
    vulnerability classes for server-side JavaScript.

    Falls back to NodeGoat if SecBench.js is not available.

    Args:
        cache_dir: Directory to store benchmarks
        max_files: Maximum files to download (None for all)

    Returns:
        Number of test files downloaded
    """
    secbench_dir = os.path.join(cache_dir, 'secbench_js')
    src_dir = os.path.join(secbench_dir, 'src')

    # Check if already downloaded
    if os.path.exists(src_dir):
        files = list(Path(src_dir).rglob('*.js')) + list(Path(src_dir).rglob('*.ts'))
        if files:
            print(f"SecBench.js already downloaded: {len(files)} files")
            return len(files)

    print("Downloading JavaScript security benchmarks...")
    os.makedirs(secbench_dir, exist_ok=True)

    # Try SecBench.js first
    temp_dir = os.path.join(cache_dir, '_secbench_temp')
    if os.path.exists(temp_dir):
        shutil.rmtree(temp_dir)

    success = False
    try:
        subprocess.run([
            'git', 'clone',
            '--depth', '1',
            SECBENCH_REPO,
            temp_dir
        ], check=True, capture_output=True, timeout=60)
        success = True
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
        print("SecBench.js not available, falling back to NodeGoat...")

    # Fall back to NodeGoat
    if not success:
        try:
            subprocess.run([
                'git', 'clone',
                '--depth', '1',
                '--branch', NODEGOAT_BRANCH,
                NODEGOAT_REPO,
                temp_dir
            ], check=True, capture_output=True)
            success = True
        except subprocess.CalledProcessError as e:
            print(f"ERROR: Failed to clone NodeGoat: {e}")
            return 0

    if not success:
        return 0

    try:
        # Copy JavaScript/TypeScript source files
        if os.path.exists(src_dir):
            shutil.rmtree(src_dir)
        os.makedirs(src_dir)

        for root, dirs, filenames in os.walk(temp_dir):
            # Skip non-source directories
            dirs[:] = [d for d in dirs if d not in ['.git', 'node_modules', 'dist', 'build', 'coverage']]

            for filename in filenames:
                if filename.endswith(('.js', '.ts', '.jsx', '.tsx')):
                    # Skip test files and configs
                    if '.test.' in filename or '.spec.' in filename or filename.endswith('.config.js'):
                        continue

                    src_path = os.path.join(root, filename)
                    rel_path = os.path.relpath(root, temp_dir)
                    dest_dir = os.path.join(src_dir, rel_path)
                    os.makedirs(dest_dir, exist_ok=True)
                    shutil.copy(src_path, os.path.join(dest_dir, filename))

        # Create manifest with known vulnerabilities
        manifest = create_js_vulnerability_manifest(src_dir)
        manifest_path = os.path.join(secbench_dir, 'manifest.json')
        with open(manifest_path, 'w') as f:
            json.dump(manifest, f, indent=2)

        # Clean up
        shutil.rmtree(temp_dir)

        files = list(Path(src_dir).rglob('*.js')) + list(Path(src_dir).rglob('*.ts'))
        if max_files:
            files = files[:max_files]

        print(f"Downloaded JS benchmarks: {len(files)} files")
        return len(files)

    except Exception as e:
        print(f"ERROR: {e}")
        if os.path.exists(temp_dir):
            shutil.rmtree(temp_dir)
        return 0


def create_js_vulnerability_manifest(src_dir: str) -> Dict:
    """
    Create a manifest of known vulnerabilities in the JS codebase.

    Scans for common vulnerability patterns and creates ground truth.
    """
    import re

    manifest = {
        'files': {},
        'vulnerability_types': [
            'sql_injection',
            'xss',
            'command_injection',
            'path_traversal',
            'nosql_injection',
            'prototype_pollution',
            'ssrf',
            'xxe',
            'insecure_deserialization',
        ]
    }

    # Patterns that indicate vulnerabilities
    vuln_patterns = {
        'sql_injection': [
            r'\.query\s*\(\s*["\'].*\+',  # String concat in SQL
            r'\.query\s*\(\s*`.*\$\{',     # Template literal in SQL
            r'execute\s*\(\s*["\'].*\+',
        ],
        'xss': [
            r'\.html\s*\(\s*\w+',          # jQuery .html() with variable
            r'innerHTML\s*=\s*\w+',
            r'document\.write\s*\(',
            r'res\.send\s*\(\s*\w+',        # Express res.send without escape
        ],
        'command_injection': [
            r'exec\s*\(\s*["\'].*\+',
            r'exec\s*\(\s*`.*\$\{',
            r'spawn\s*\(\s*\w+',
            r'execSync\s*\(',
        ],
        'path_traversal': [
            r'readFile\s*\(\s*\w+',
            r'readFileSync\s*\(\s*\w+',
            r'path\.join\s*\([^)]*req\.',
        ],
        'nosql_injection': [
            r'\.find\s*\(\s*\{[^}]*req\.',
            r'\.findOne\s*\(\s*\{[^}]*req\.',
            r'\$where.*req\.',
        ],
        'prototype_pollution': [
            r'Object\.assign\s*\([^,]+,\s*\w+\)',
            r'\.\.\.req\.',
            r'merge\s*\([^,]+,\s*req\.',
        ],
    }

    cwe_mapping = {
        'sql_injection': 'CWE-89',
        'xss': 'CWE-79',
        'command_injection': 'CWE-78',
        'path_traversal': 'CWE-22',
        'nosql_injection': 'CWE-943',
        'prototype_pollution': 'CWE-1321',
        'ssrf': 'CWE-918',
        'xxe': 'CWE-611',
        'insecure_deserialization': 'CWE-502',
    }

    for root, dirs, filenames in os.walk(src_dir):
        for filename in filenames:
            if filename.endswith(('.js', '.ts')):
                filepath = os.path.join(root, filename)
                rel_path = os.path.relpath(filepath, src_dir)

                try:
                    with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()

                    file_vulns = []
                    for vuln_type, patterns in vuln_patterns.items():
                        for pattern in patterns:
                            matches = list(re.finditer(pattern, content))
                            for match in matches:
                                # Find line number
                                line_num = content[:match.start()].count('\n') + 1
                                file_vulns.append({
                                    'type': vuln_type,
                                    'cwe': cwe_mapping.get(vuln_type, 'unknown'),
                                    'line': line_num,
                                    'pattern': pattern,
                                })

                    if file_vulns:
                        manifest['files'][rel_path] = {
                            'vulnerabilities': file_vulns,
                            'language': 'typescript' if filename.endswith('.ts') else 'javascript',
                        }

                except Exception:
                    pass

    return manifest


def load_secbench_manifest(cache_dir: str) -> Dict:
    """Load the vulnerability manifest"""
    manifest_path = os.path.join(cache_dir, 'secbench_js', 'manifest.json')
    if os.path.exists(manifest_path):
        with open(manifest_path, 'r') as f:
            return json.load(f)
    return {'files': {}}


def get_secbench_test_files(cache_dir: str) -> List[str]:
    """Get list of SecBench.js test files"""
    src_dir = os.path.join(cache_dir, 'secbench_js', 'src')
    if not os.path.exists(src_dir):
        return []

    files = []
    for root, dirs, filenames in os.walk(src_dir):
        for filename in filenames:
            if filename.endswith(('.js', '.ts')):
                files.append(os.path.join(root, filename))

    return sorted(files)


def create_secbench_curated_set(
    cache_dir: str,
    sample_size: int = 200,
    seed: int = 42
) -> int:
    """
    Create a curated subset of SecBench.js benchmarks.

    Prioritizes files with known vulnerabilities.

    Args:
        cache_dir: Cache directory
        sample_size: Target size for curated set
        seed: Random seed for reproducibility

    Returns:
        Number of files in curated set
    """
    import random

    # Ensure full set exists
    full_count = download_secbench_js(cache_dir)
    if full_count == 0:
        return 0

    manifest = load_secbench_manifest(cache_dir)
    test_files = get_secbench_test_files(cache_dir)
    src_dir = os.path.join(cache_dir, 'secbench_js', 'src')

    if not test_files:
        print("No SecBench.js test files found")
        return 0

    # Prioritize files with known vulnerabilities
    vuln_files = []
    other_files = []

    for filepath in test_files:
        rel_path = os.path.relpath(filepath, src_dir)
        if rel_path in manifest.get('files', {}):
            vuln_files.append(filepath)
        else:
            other_files.append(filepath)

    random.seed(seed)

    # Select mostly vulnerable files, some clean files
    curated_files = []
    vuln_quota = min(len(vuln_files), int(sample_size * 0.8))
    other_quota = sample_size - vuln_quota

    if vuln_files:
        curated_files.extend(random.sample(vuln_files, vuln_quota))
    if other_files:
        curated_files.extend(random.sample(other_files, min(len(other_files), other_quota)))

    # Create curated directory
    curated_dir = os.path.join(cache_dir, 'secbench_js', 'secbench_js_curated')
    if os.path.exists(curated_dir):
        shutil.rmtree(curated_dir)
    os.makedirs(curated_dir)

    # Copy files
    for i, filepath in enumerate(curated_files):
        filename = os.path.basename(filepath)
        dest_name = f"{i:04d}_{filename}"
        shutil.copy(filepath, os.path.join(curated_dir, dest_name))

    # Copy manifest
    manifest_src = os.path.join(cache_dir, 'secbench_js', 'manifest.json')
    if os.path.exists(manifest_src):
        shutil.copy(manifest_src, os.path.join(curated_dir, 'manifest.json'))

    print(f"Created SecBench.js curated set: {len(curated_files)} files")
    return len(curated_files)
