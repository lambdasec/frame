"""QF_BV (Bitvector Theory) benchmark downloaders"""

import os
import requests
import shutil
from pathlib import Path
from typing import Optional


def download_qf_bv_samples(cache_dir: str, max_files: Optional[int] = None) -> int:
    """Download QF_BV (Bitvector Theory) sample benchmarks"""
    print("\nDownloading QF_BV (Bitvector Theory) benchmarks...")

    qf_bv_dir = os.path.join(cache_dir, 'qf_bv', 'samples')
    os.makedirs(qf_bv_dir, exist_ok=True)

    # QF_BV benchmarks test bitvector operations and overflow detection
    qf_bv_samples = {
        'bvadd_01.smt2': """(set-info :status sat)
(set-logic QF_BV)
(declare-const x (_ BitVec 8))
(declare-const y (_ BitVec 8))
(assert (= x #x05))
(assert (= y #x03))
(assert (= (bvadd x y) #x08))
(check-sat)
""",
        'bvand_01.smt2': """(set-info :status sat)
(set-logic QF_BV)
(declare-const x (_ BitVec 8))
(assert (= (bvand x #xFF) x))
(check-sat)
""",
        'bvor_01.smt2': """(set-info :status sat)
(set-logic QF_BV)
(declare-const x (_ BitVec 8))
(assert (= (bvor #xF0 #x0F) #xFF))
(check-sat)
""",
        'bvxor_01.smt2': """(set-info :status sat)
(set-logic QF_BV)
(declare-const x (_ BitVec 8))
(assert (= x #xFF))
(assert (= (bvxor x x) #x00))
(check-sat)
""",
        'overflow_unsigned_01.smt2': """(set-info :status sat)
(set-logic QF_BV)
(declare-const x (_ BitVec 8))
(declare-const y (_ BitVec 8))
(assert (= x #xFF))
(assert (= y #x01))
(assert (= (bvadd x y) #x00))
(check-sat)
""",
        'overflow_signed_01.smt2': """(set-info :status unsat)
(set-logic QF_BV)
(declare-const x (_ BitVec 8))
(assert (= x #x7F))
(assert (bvsgt (bvadd x #x01) x))
(check-sat)
""",
        'shift_01.smt2': """(set-info :status sat)
(set-logic QF_BV)
(declare-const x (_ BitVec 8))
(assert (= x #x01))
(assert (= (bvshl x #x03) #x08))
(check-sat)
""",
        'comparison_unsigned_01.smt2': """(set-info :status sat)
(set-logic QF_BV)
(declare-const x (_ BitVec 8))
(declare-const y (_ BitVec 8))
(assert (= x #x05))
(assert (= y #x0A))
(assert (bvult x y))
(check-sat)
""",
    }

    count = 0
    files_to_create = list(qf_bv_samples.items())
    if max_files:
        files_to_create = files_to_create[:max_files]

    for filename, content in files_to_create:
        filepath = os.path.join(qf_bv_dir, filename)
        if not os.path.exists(filepath):
            with open(filepath, 'w') as f:
                f.write(content)
            print(f"  ✓ Created {filename}")
            count += 1
        else:
            print(f"  ✓ {filename} (already exists)")
            count += 1

    print(f"\nQF_BV benchmarks: {count} files")
    print(f"Location: {qf_bv_dir}")

    return count



def download_qf_bv_full(cache_dir: str) -> int:
    """Download full QF_BV (Bitvector Theory) benchmark set from SMT-LIB"""
    print("\n" + "=" * 80)
    print("DOWNLOADING FULL QF_BV BENCHMARK SET FROM SMT-LIB")
    print("=" * 80)
    print("Source: SMT-LIB 2024 Release (Zenodo)")
    print("Theory: QF_BV (Quantifier-Free Bitvector Theory)")

    qf_bv_full_dir = os.path.join(cache_dir, 'qf_bv_full')
    os.makedirs(qf_bv_full_dir, exist_ok=True)

    # Check if already downloaded
    existing_files = list(Path(qf_bv_full_dir).rglob('*.smt2'))
    if len(existing_files) > 50:
        print(f"\n✓ QF_BV benchmarks already cached ({len(existing_files)} files)")
        print(f"  Location: {qf_bv_full_dir}")
        return len(existing_files)

    # Official SMT-LIB 2024 release on Zenodo
    zenodo_url = "https://zenodo.org/records/11061097/files/QF_BV.tar.zst?download=1"
    archive_path = os.path.join(cache_dir, 'QF_BV.tar.zst')

    try:
        if not os.path.exists(archive_path):
            print(f"\n  Downloading QF_BV benchmarks from Zenodo (1.7 GB compressed)...")
            print(f"  This may take several minutes...")
            response = requests.get(zenodo_url, timeout=600, stream=True)
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
                return download_qf_bv_samples(cache_dir)

        # Extract QF_BV benchmarks using tar with zstd
        print(f"  Extracting QF_BV benchmarks from .tar.zst archive...")
        print(f"  This may take several minutes due to large file size...")

        # Extract to a temporary directory first
        extract_dir = os.path.join(cache_dir, 'qf_bv_extract_tmp')
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
            return download_qf_bv_samples(cache_dir)

        # Move all .smt2 files to qf_bv_full_dir
        print(f"  Moving extracted files...")
        for root, dirs, files in os.walk(extract_dir):
            for file in files:
                if file.endswith('.smt2'):
                    src = os.path.join(root, file)
                    dst = os.path.join(qf_bv_full_dir, file)
                    shutil.move(src, dst)

        smt2_files = list(Path(qf_bv_full_dir).rglob('*.smt2'))

        # If we got very few files, fall back to samples
        if len(smt2_files) < 10:
            print(f"  ✗ Insufficient benchmarks extracted ({len(smt2_files)} files)")
            print(f"  Using local samples instead...")
            return download_qf_bv_samples(cache_dir)

        print(f"\n✓ QF_BV benchmarks ready: {len(smt2_files)} files")
        print(f"  Location: {qf_bv_full_dir}")

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
        return download_qf_bv_samples(cache_dir)
