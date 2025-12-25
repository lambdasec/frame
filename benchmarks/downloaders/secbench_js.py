"""JavaScript/TypeScript security benchmarks downloader.

Includes multiple benchmark sources for comprehensive coverage:
1. NodeGoat - OWASP's intentionally vulnerable Node.js app
2. DVNA - Damn Vulnerable NodeJS Application (OWASP Top 10)
3. Juice Shop - OWASP's modern insecure web app (TypeScript/Angular)
4. OpenSSF CVE Benchmark - 200+ real JavaScript/TypeScript CVEs
"""

import os
import json
import shutil
import subprocess
import re
from typing import Optional, Dict, List, Tuple
from pathlib import Path


# Benchmark repositories
BENCHMARKS = {
    'nodegoat': {
        'name': 'NodeGoat',
        'repo': 'https://github.com/OWASP/NodeGoat.git',
        'branch': 'master',
        'description': 'OWASP intentionally vulnerable Node.js application',
        'languages': ['javascript'],
    },
    'dvna': {
        'name': 'DVNA',
        'repo': 'https://github.com/appsecco/dvna.git',
        'branch': 'master',
        'description': 'Damn Vulnerable NodeJS Application - OWASP Top 10',
        'languages': ['javascript'],
    },
    'juice_shop': {
        'name': 'Juice Shop',
        'repo': 'https://github.com/juice-shop/juice-shop.git',
        'branch': 'master',
        'description': 'OWASP modern insecure web app (TypeScript/Angular)',
        'languages': ['typescript', 'javascript'],
    },
    'openssf_cve': {
        'name': 'OpenSSF CVE Benchmark',
        'repo': 'https://github.com/ossf-cve-benchmark/ossf-cve-benchmark.git',
        'branch': 'main',
        'description': '200+ real JavaScript/TypeScript CVEs with ground truth',
        'languages': ['javascript', 'typescript'],
    },
}


def download_secbench_js(cache_dir: str, max_files: Optional[int] = None) -> int:
    """
    Download all JavaScript/TypeScript security benchmarks.

    Downloads from multiple sources:
    - NodeGoat: OWASP vulnerable Node.js app
    - DVNA: Damn Vulnerable NodeJS Application
    - Juice Shop: TypeScript/Angular vulnerable app
    - OpenSSF CVE Benchmark: 200+ real CVEs

    Args:
        cache_dir: Directory to store benchmarks
        max_files: Maximum files to download per source (None for all)

    Returns:
        Total number of test files downloaded
    """
    secbench_dir = os.path.join(cache_dir, 'secbench_js')
    src_dir = os.path.join(secbench_dir, 'src')

    # Check if already downloaded
    if os.path.exists(src_dir):
        files = list(Path(src_dir).rglob('*.js')) + list(Path(src_dir).rglob('*.ts'))
        if len(files) > 100:  # Require substantial download
            print(f"JS benchmarks already downloaded: {len(files)} files")
            return len(files)

    print("Downloading JavaScript/TypeScript security benchmarks...")
    os.makedirs(secbench_dir, exist_ok=True)
    os.makedirs(src_dir, exist_ok=True)

    total_files = 0

    for bench_id, bench_info in BENCHMARKS.items():
        count = _download_single_benchmark(
            cache_dir, bench_id, bench_info, src_dir, max_files
        )
        total_files += count
        print(f"  {bench_info['name']}: {count} files")

    # Create combined manifest
    manifest = create_js_vulnerability_manifest(src_dir)
    manifest_path = os.path.join(secbench_dir, 'manifest.json')
    with open(manifest_path, 'w') as f:
        json.dump(manifest, f, indent=2)

    print(f"\nTotal JS/TS benchmarks: {total_files} files")
    print(f"Files with detected vulnerabilities: {len(manifest.get('files', {}))}")

    return total_files


def _download_single_benchmark(
    cache_dir: str,
    bench_id: str,
    bench_info: Dict,
    src_dir: str,
    max_files: Optional[int]
) -> int:
    """Download a single benchmark repository."""
    temp_dir = os.path.join(cache_dir, f'_js_temp_{bench_id}')
    if os.path.exists(temp_dir):
        shutil.rmtree(temp_dir)

    try:
        print(f"  Downloading {bench_info['name']}...")
        subprocess.run([
            'git', 'clone',
            '--depth', '1',
            '--branch', bench_info['branch'],
            bench_info['repo'],
            temp_dir
        ], check=True, capture_output=True, timeout=120)

        # Create subdirectory for this benchmark
        bench_src_dir = os.path.join(src_dir, bench_id)
        os.makedirs(bench_src_dir, exist_ok=True)

        # Copy JavaScript/TypeScript source files
        file_count = 0
        for root, dirs, filenames in os.walk(temp_dir):
            # Skip non-source directories
            dirs[:] = [d for d in dirs if d not in [
                '.git', 'node_modules', 'dist', 'build', 'coverage',
                '.nyc_output', 'test', 'tests', '__tests__', 'spec'
            ]]

            for filename in filenames:
                if filename.endswith(('.js', '.ts', '.jsx', '.tsx')):
                    # Skip test files, configs, and minified files
                    if any(skip in filename.lower() for skip in [
                        '.test.', '.spec.', '.config.', '.min.', 'd.ts'
                    ]):
                        continue

                    src_path = os.path.join(root, filename)
                    rel_path = os.path.relpath(root, temp_dir)
                    dest_dir = os.path.join(bench_src_dir, rel_path)
                    os.makedirs(dest_dir, exist_ok=True)

                    try:
                        shutil.copy(src_path, os.path.join(dest_dir, filename))
                        file_count += 1

                        if max_files and file_count >= max_files:
                            break
                    except Exception:
                        pass

                if max_files and file_count >= max_files:
                    break
            if max_files and file_count >= max_files:
                break

        # Clean up
        shutil.rmtree(temp_dir)
        return file_count

    except subprocess.CalledProcessError as e:
        print(f"  WARNING: Failed to clone {bench_info['name']}: {e}")
        if os.path.exists(temp_dir):
            shutil.rmtree(temp_dir)
        return 0
    except subprocess.TimeoutExpired:
        print(f"  WARNING: Timeout cloning {bench_info['name']}")
        if os.path.exists(temp_dir):
            shutil.rmtree(temp_dir)
        return 0
    except Exception as e:
        print(f"  WARNING: Error with {bench_info['name']}: {e}")
        if os.path.exists(temp_dir):
            shutil.rmtree(temp_dir)
        return 0


def create_js_vulnerability_manifest(src_dir: str) -> Dict:
    """
    Create a manifest of known vulnerabilities in the JS codebase.

    Scans for common vulnerability patterns and creates ground truth.
    """
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
            'open_redirect',
            'hardcoded_secret',
        ],
        'sources': list(BENCHMARKS.keys()),
    }

    # Patterns that indicate vulnerabilities
    vuln_patterns = {
        'sql_injection': [
            r'\.query\s*\(\s*["\'].*\+',  # String concat in SQL
            r'\.query\s*\(\s*`.*\$\{',     # Template literal in SQL
            r'execute\s*\(\s*["\'].*\+',
            r'sequelize\.query\s*\(',
        ],
        'xss': [
            r'\.html\s*\(\s*\w+',          # jQuery .html() with variable
            r'innerHTML\s*=\s*[^"\']+',
            r'document\.write\s*\(',
            r'res\.send\s*\(\s*[^"\'<]+\)',  # Express res.send without escape
            r'dangerouslySetInnerHTML',
        ],
        'command_injection': [
            r'exec\s*\(\s*["\'].*\+',
            r'exec\s*\(\s*`.*\$\{',
            r'spawn\s*\(\s*\w+[^)]*\)',
            r'execSync\s*\([^"\']+\)',
            r'child_process',
        ],
        'path_traversal': [
            r'readFile\s*\(\s*[^"\']+\)',
            r'readFileSync\s*\(\s*[^"\']+\)',
            r'path\.join\s*\([^)]*req\.',
            r'fs\.\w+\s*\([^)]*req\.',
        ],
        'nosql_injection': [
            r'\.find\s*\(\s*\{[^}]*req\.',
            r'\.findOne\s*\(\s*\{[^}]*req\.',
            r'\$where.*req\.',
            r'mongoose\.\w+\s*\([^)]*req\.',
        ],
        'prototype_pollution': [
            r'Object\.assign\s*\([^,]+,\s*\w+\)',
            r'\.\.\.req\.',
            r'merge\s*\([^,]+,\s*req\.',
            r'extend\s*\([^,]+,\s*req\.',
            r'\[.*\]\s*=.*req\.',
        ],
        'ssrf': [
            r'axios\s*\(\s*[^"\']+\)',
            r'fetch\s*\(\s*[^"\']+\)',
            r'request\s*\(\s*[^"\']+\)',
            r'http\.get\s*\(\s*[^"\']+\)',
        ],
        'open_redirect': [
            r'res\.redirect\s*\(\s*req\.',
            r'location\s*=\s*[^"\']+',
            r'window\.location\.href\s*=',
        ],
        'hardcoded_secret': [
            r'password\s*[=:]\s*["\'][^"\']+["\']',
            r'secret\s*[=:]\s*["\'][^"\']+["\']',
            r'apikey\s*[=:]\s*["\'][^"\']+["\']',
            r'api_key\s*[=:]\s*["\'][^"\']+["\']',
            r'AWS_SECRET',
        ],
        'insecure_deserialization': [
            r'JSON\.parse\s*\(\s*req\.',
            r'eval\s*\(',
            r'Function\s*\(',
            r'serialize\s*\(',
            r'unserialize\s*\(',
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
        'open_redirect': 'CWE-601',
        'hardcoded_secret': 'CWE-798',
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
                            try:
                                matches = list(re.finditer(pattern, content, re.IGNORECASE))
                                for match in matches:
                                    # Find line number
                                    line_num = content[:match.start()].count('\n') + 1
                                    file_vulns.append({
                                        'type': vuln_type,
                                        'cwe': cwe_mapping.get(vuln_type, 'unknown'),
                                        'line': line_num,
                                        'pattern': pattern,
                                    })
                            except re.error:
                                pass

                    if file_vulns:
                        # Deduplicate by line number and type
                        seen = set()
                        unique_vulns = []
                        for v in file_vulns:
                            key = (v['type'], v['line'])
                            if key not in seen:
                                seen.add(key)
                                unique_vulns.append(v)

                        manifest['files'][rel_path] = {
                            'vulnerabilities': unique_vulns,
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
    """Get list of all JS/TS benchmark test files"""
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
    sample_size: int = 500,
    seed: int = 42
) -> int:
    """
    Create a curated subset of JS/TS benchmarks.

    Prioritizes files with known vulnerabilities and balances across sources.

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
        print("No JS/TS test files found")
        return 0

    # Group files by source
    by_source: Dict[str, List[str]] = {}
    for filepath in test_files:
        rel_path = os.path.relpath(filepath, src_dir)
        parts = rel_path.split(os.sep)
        source = parts[0] if parts else 'unknown'

        if source not in by_source:
            by_source[source] = []
        by_source[source].append(filepath)

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

    # Select mostly vulnerable files, balanced across sources
    curated_files = []

    # First, take vulnerable files (80% of quota)
    vuln_quota = min(len(vuln_files), int(sample_size * 0.8))
    if vuln_files:
        curated_files.extend(random.sample(vuln_files, vuln_quota))

    # Then fill with other files, balanced by source
    remaining = sample_size - len(curated_files)
    if remaining > 0 and other_files:
        # Balance across sources
        per_source = max(1, remaining // len(by_source))
        for source, files in by_source.items():
            available = [f for f in files if f not in curated_files]
            n = min(len(available), per_source)
            if available and n > 0:
                curated_files.extend(random.sample(available, n))

    curated_files = curated_files[:sample_size]

    # Create curated directory
    curated_dir = os.path.join(cache_dir, 'secbench_js', 'secbench_js_curated')
    if os.path.exists(curated_dir):
        shutil.rmtree(curated_dir)
    os.makedirs(curated_dir)

    # Copy files with source prefix to avoid name collisions
    for i, filepath in enumerate(curated_files):
        rel_path = os.path.relpath(filepath, src_dir)
        parts = rel_path.split(os.sep)
        source = parts[0] if parts else 'unknown'
        filename = os.path.basename(filepath)
        dest_name = f"{i:04d}_{source}_{filename}"
        shutil.copy(filepath, os.path.join(curated_dir, dest_name))

    # Copy manifest
    manifest_src = os.path.join(cache_dir, 'secbench_js', 'manifest.json')
    if os.path.exists(manifest_src):
        shutil.copy(manifest_src, os.path.join(curated_dir, 'manifest.json'))

    print(f"Created JS/TS curated set: {len(curated_files)} files")
    print(f"  Sources: {list(by_source.keys())}")
    return len(curated_files)


# Additional helper for loading OpenSSF CVE metadata
def load_openssf_cve_metadata(cache_dir: str) -> Dict:
    """
    Load CVE metadata from OpenSSF benchmark if available.

    The OpenSSF CVE Benchmark contains detailed metadata for 200+ CVEs.
    """
    cve_dir = os.path.join(cache_dir, 'secbench_js', 'src', 'openssf_cve', 'CVEs')
    if not os.path.exists(cve_dir):
        return {}

    cve_data = {}
    for cve_id in os.listdir(cve_dir):
        cve_path = os.path.join(cve_dir, cve_id)
        if os.path.isdir(cve_path):
            # Look for metadata file
            meta_file = os.path.join(cve_path, 'cve.json')
            if os.path.exists(meta_file):
                try:
                    with open(meta_file, 'r') as f:
                        cve_data[cve_id] = json.load(f)
                except Exception:
                    pass

    return cve_data
