"""QF_AX (Array Theory) benchmark downloaders"""

import os
import requests
import shutil
from pathlib import Path
from typing import Optional


def download_qf_ax_samples(cache_dir: str, max_files: Optional[int] = None) -> int:
    """Download QF_AX (Array Theory) sample benchmarks"""
    print("\nDownloading QF_AX (Array Theory) benchmarks...")

    qf_ax_dir = os.path.join(cache_dir, 'qf_ax', 'samples')
    os.makedirs(qf_ax_dir, exist_ok=True)

    # QF_AX benchmarks test array operations with select/store axioms
    # NOTE: Using QF_ALIA for samples since they use Int sorts (arrays + linear integer arithmetic)
    qf_ax_samples = {
        'select_store_01.smt2': """(set-info :status sat)
(set-logic QF_ALIA)
(declare-const arr1 (Array Int Int))
(declare-const arr2 (Array Int Int))
(assert (= arr2 (store arr1 0 42)))
(assert (= (select arr2 0) 42))
(check-sat)
""",
        'select_store_diff_index.smt2': """(set-info :status sat)
(set-logic QF_ALIA)
(declare-const arr1 (Array Int Int))
(declare-const arr2 (Array Int Int))
(assert (= arr2 (store arr1 0 42)))
(assert (= (select arr1 5) 10))
(assert (= (select arr2 5) 10))
(check-sat)
""",
        'array_equality_01.smt2': """(set-info :status sat)
(set-logic QF_ALIA)
(declare-const arr1 (Array Int Int))
(declare-const arr2 (Array Int Int))
(assert (= (select arr1 0) (select arr2 0)))
(assert (= (select arr1 1) (select arr2 1)))
(assert (not (= arr1 arr2)))
(check-sat)
""",
        'const_array_01.smt2': """(set-info :status sat)
(set-logic QF_ALIA)
(declare-const arr (Array Int Int))
(assert (= arr ((as const (Array Int Int)) 0)))
(assert (= (select arr 5) 0))
(assert (= (select arr 100) 0))
(check-sat)
""",
        'buffer_overflow_01.smt2': """(set-info :status sat)
(set-logic QF_ALIA)
(declare-const arr (Array Int Int))
(declare-const size Int)
(declare-const index Int)
(assert (= size 10))
(assert (>= index size))
(check-sat)
""",
        'in_bounds_01.smt2': """(set-info :status sat)
(set-logic QF_ALIA)
(declare-const arr (Array Int Int))
(declare-const size Int)
(declare-const index Int)
(assert (= size 10))
(assert (< index size))
(assert (>= index 0))
(check-sat)
""",
    }

    count = 0
    files_to_create = list(qf_ax_samples.items())
    if max_files:
        files_to_create = files_to_create[:max_files]

    for filename, content in files_to_create:
        filepath = os.path.join(qf_ax_dir, filename)
        if not os.path.exists(filepath):
            with open(filepath, 'w') as f:
                f.write(content)
            print(f"  ✓ Created {filename}")
            count += 1
        else:
            print(f"  ✓ {filename} (already exists)")
            count += 1

    print(f"\nQF_AX benchmarks: {count} files")
    print(f"Location: {qf_ax_dir}")

    return count



def download_qf_ax_full(cache_dir: str) -> int:
    """Download full QF_AX (Array Theory) benchmark set from SMT-LIB"""
    print("\n" + "=" * 80)
    print("DOWNLOADING FULL QF_AX BENCHMARK SET FROM SMT-LIB")
    print("=" * 80)
    print("Source: SMT-LIB 2024 Release (Zenodo)")
    print("Theory: QF_AX (Quantifier-Free Array Theory with Extensionality)")

    qf_ax_full_dir = os.path.join(cache_dir, 'qf_ax_full')
    os.makedirs(qf_ax_full_dir, exist_ok=True)

    # Check if already downloaded
    existing_files = list(Path(qf_ax_full_dir).rglob('*.smt2'))
    if len(existing_files) > 50:
        print(f"\n✓ QF_AX benchmarks already cached ({len(existing_files)} files)")
        print(f"  Location: {qf_ax_full_dir}")
        return len(existing_files)

    # Official SMT-LIB 2024 release on Zenodo
    zenodo_url = "https://zenodo.org/records/11061097/files/QF_AX.tar.zst?download=1"
    archive_path = os.path.join(cache_dir, 'QF_AX.tar.zst')

    try:
        if not os.path.exists(archive_path):
            print(f"\n  Downloading QF_AX benchmarks from Zenodo (131.5 KB compressed)...")
            response = requests.get(zenodo_url, timeout=300, stream=True)
            if response.status_code == 200:
                total_size = int(response.headers.get('content-length', 0))
                with open(archive_path, 'wb') as f:
                    downloaded = 0
                    for chunk in response.iter_content(chunk_size=8192):
                        f.write(chunk)
                        downloaded += len(chunk)
                        if total_size > 0:
                            progress = (downloaded / total_size) * 100
                            print(f"\r  Progress: {progress:.1f}%", end='', flush=True)
                print(f"\n  ✓ Downloaded ({downloaded / 1024 / 1024:.1f} MB)")
            else:
                print(f"  ✗ Zenodo download failed (HTTP {response.status_code})")
                print(f"  Using local samples instead...")
                return download_qf_ax_samples(cache_dir)

        # Extract QF_AX benchmarks using tar with zstd
        print(f"  Extracting QF_AX benchmarks from .tar.zst archive...")

        # Extract to a temporary directory first
        extract_dir = os.path.join(cache_dir, 'qf_ax_extract_tmp')
        os.makedirs(extract_dir, exist_ok=True)

        # Use Python's zstandard library to extract .tar.zst
        try:
            import zstandard
            import tarfile

            dctx = zstandard.ZstdDecompressor()
            with open(archive_path, 'rb') as compressed:
                with dctx.stream_reader(compressed) as reader:
                    with tarfile.open(fileobj=reader, mode='r|') as tar:
                        tar.extractall(path=extract_dir)
        except Exception as e:
            print(f"  ✗ Extraction failed: {e}")
            print(f"  Using local samples instead...")
            shutil.rmtree(extract_dir, ignore_errors=True)
            return download_qf_ax_samples(cache_dir)

        # Move all .smt2 files to qf_ax_full_dir
        for root, dirs, files in os.walk(extract_dir):
            for file in files:
                if file.endswith('.smt2'):
                    src = os.path.join(root, file)
                    dst = os.path.join(qf_ax_full_dir, file)
                    shutil.move(src, dst)

        smt2_files = list(Path(qf_ax_full_dir).rglob('*.smt2'))

        # If we got very few files, fall back to samples
        if len(smt2_files) < 10:
            print(f"  ✗ Insufficient benchmarks extracted ({len(smt2_files)} files)")
            print(f"  Using local samples instead...")
            return download_qf_ax_samples(cache_dir)

        print(f"\n✓ QF_AX benchmarks ready: {len(smt2_files)} files")
        print(f"  Location: {qf_ax_full_dir}")

        # Clean up
        try:
            os.remove(archive_path)
            shutil.rmtree(extract_dir, ignore_errors=True)
        except:
            pass

        return len(smt2_files)

    except Exception as e:
        print(f"  ✗ Download failed: {e}")
        print(f"  Using local samples instead...")
        return download_qf_ax_samples(cache_dir)

