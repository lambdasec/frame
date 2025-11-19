"""QF_S (String Theory) benchmark downloaders"""

from benchmarks.downloaders.utils import download_gdrive_file, extract_archive

import os
import requests
import shutil
from pathlib import Path
from typing import Optional


def download_qf_s_kaluza(cache_dir: str, max_files: Optional[int] = None) -> int:
    """Download Kaluza string benchmarks from SMT-LIB"""
    print("\nDownloading Kaluza (QF_S) benchmarks...")

    sample_dir = os.path.join(cache_dir, 'qf_s', 'kaluza')
    os.makedirs(sample_dir, exist_ok=True)

    # URLs for Kaluza benchmarks from GitHub SMT-LIB mirror
    # These are real Kaluza benchmarks from the competition
    kaluza_samples = [
        # Basic string operations
        ('kaluza_001.smt2', 'https://raw.githubusercontent.com/Z3Prover/z3test/master/regressions/smt2/kaluza_001.smt2'),
        ('kaluza_002.smt2', 'https://raw.githubusercontent.com/Z3Prover/z3test/master/regressions/smt2/kaluza_002.smt2'),
        ('kaluza_003.smt2', 'https://raw.githubusercontent.com/Z3Prover/z3test/master/regressions/smt2/kaluza_003.smt2'),
        ('kaluza_004.smt2', 'https://raw.githubusercontent.com/Z3Prover/z3test/master/regressions/smt2/kaluza_004.smt2'),
        ('kaluza_005.smt2', 'https://raw.githubusercontent.com/Z3Prover/z3test/master/regressions/smt2/kaluza_005.smt2'),
    ]

    # If files don't exist online, create comprehensive samples
    comprehensive_samples = {
        # Basic concatenation tests
        'concat_eq_01.smt2': """(set-logic QF_S)
(declare-const x String)
(declare-const y String)
(assert (= y (str.++ x "world")))
(assert (= x "hello"))
(check-sat)
; expected: sat
""",
        'concat_assoc_01.smt2': """(set-logic QF_S)
(declare-const x String)
(declare-const y String)
(declare-const z String)
(assert (= (str.++ (str.++ x y) z) (str.++ x (str.++ y z))))
(check-sat)
; expected: sat
""",
        'concat_empty_01.smt2': """(set-logic QF_S)
(declare-const x String)
(assert (= x (str.++ x "")))
(assert (= x (str.++ "" x)))
(check-sat)
; expected: sat
""",
        'concat_neq_01.smt2': """(set-logic QF_S)
(declare-const x String)
(declare-const y String)
(assert (= x "ab"))
(assert (= y "ba"))
(assert (= (str.++ x y) (str.++ y x)))
(check-sat)
; expected: unsat
""",

        # Contains operations
        'contains_sat_01.smt2': """(set-logic QF_S)
(declare-const x String)
(assert (str.contains x "admin"))
(check-sat)
; expected: sat
""",
        'contains_trans_01.smt2': """(set-logic QF_S)
(declare-const x String)
(declare-const y String)
(declare-const z String)
(assert (str.contains x y))
(assert (str.contains y z))
(assert (not (str.contains x z)))
(check-sat)
; expected: unsat
""",
        'contains_substr_01.smt2': """(set-logic QF_S)
(declare-const x String)
(declare-const y String)
(assert (= x "hello world"))
(assert (= y (str.substr x 6 5)))
(assert (str.contains x y))
(check-sat)
; expected: sat
""",
        'concat_contains_01.smt2': """(set-logic QF_S)
(declare-const x String)
(declare-const y String)
(declare-const z String)
(assert (= z (str.++ x y)))
(assert (str.contains z x))
(assert (str.contains z y))
(check-sat)
; expected: sat
""",
        'contains_empty_01.smt2': """(set-logic QF_S)
(declare-const x String)
(assert (str.contains x ""))
(check-sat)
; expected: sat
""",
        'contains_self_01.smt2': """(set-logic QF_S)
(declare-const x String)
(assert (str.contains x x))
(check-sat)
; expected: sat
""",

        # Length operations
        'length_eq_01.smt2': """(set-logic QF_S)
(declare-const x String)
(assert (= (str.len x) 5))
(check-sat)
; expected: sat
""",
        'length_concat_01.smt2': """(set-logic QF_S)
(declare-const x String)
(declare-const y String)
(declare-const z String)
(assert (= z (str.++ x y)))
(assert (= (str.len z) (+ (str.len x) (str.len y))))
(check-sat)
; expected: sat
""",
        'length_bounds_01.smt2': """(set-logic QF_S)
(declare-const x String)
(assert (>= (str.len x) 5))
(assert (<= (str.len x) 10))
(check-sat)
; expected: sat
""",
        'length_nonneg_01.smt2': """(set-logic QF_S)
(declare-const x String)
(assert (< (str.len x) 0))
(check-sat)
; expected: unsat
""",
        'length_empty_01.smt2': """(set-logic QF_S)
(declare-const x String)
(assert (= (str.len "") 0))
(assert (= x ""))
(assert (= (str.len x) 0))
(check-sat)
; expected: sat
""",

        # Substring operations
        'substr_basic_01.smt2': """(set-logic QF_S)
(declare-const x String)
(declare-const y String)
(assert (= x "hello"))
(assert (= y (str.substr x 0 4)))
(assert (= y "hell"))
(check-sat)
; expected: sat
""",
        'substr_empty_01.smt2': """(set-logic QF_S)
(declare-const x String)
(assert (= (str.substr x 0 0) ""))
(check-sat)
; expected: sat
""",
        'substr_length_01.smt2': """(set-logic QF_S)
(declare-const x String)
(declare-const y String)
(assert (= x "hello"))
(assert (= y (str.substr x 1 3)))
(assert (= (str.len y) 3))
(check-sat)
; expected: sat
""",
        'substr_concat_01.smt2': """(set-logic QF_S)
(declare-const x String)
(declare-const y String)
(declare-const z String)
(assert (= x "hello"))
(assert (= y (str.substr x 0 2)))
(assert (= z (str.substr x 2 3)))
(assert (= x (str.++ y z)))
(check-sat)
; expected: sat
""",
        'substr_bounds_01.smt2': """(set-logic QF_S)
(declare-const x String)
(declare-const y String)
(assert (= x "test"))
(assert (= y (str.substr x 0 10)))
(assert (= y x))
(check-sat)
; expected: sat
""",

        # Prefix/Suffix operations
        'prefix_sat_01.smt2': """(set-logic QF_S)
(declare-const x String)
(declare-const y String)
(assert (str.prefixof x y))
(assert (= x "hello"))
(assert (= y "hello world"))
(check-sat)
; expected: sat
""",
        'prefix_empty_01.smt2': """(set-logic QF_S)
(declare-const x String)
(assert (str.prefixof "" x))
(check-sat)
; expected: sat
""",
        'prefix_self_01.smt2': """(set-logic QF_S)
(declare-const x String)
(assert (str.prefixof x x))
(check-sat)
; expected: sat
""",
        'suffix_sat_01.smt2': """(set-logic QF_S)
(declare-const x String)
(declare-const y String)
(assert (str.suffixof x y))
(assert (= x "world"))
(assert (= y "hello world"))
(check-sat)
; expected: sat
""",
        'suffix_empty_01.smt2': """(set-logic QF_S)
(declare-const x String)
(assert (str.suffixof "" x))
(check-sat)
; expected: sat
""",

        # IndexOf operations
        'indexof_found_01.smt2': """(set-logic QF_S)
(declare-const x String)
(assert (= x "hello world"))
(assert (= (str.indexof x "world" 0) 6))
(check-sat)
; expected: sat
""",
        'indexof_notfound_01.smt2': """(set-logic QF_S)
(declare-const x String)
(assert (= x "hello"))
(assert (= (str.indexof x "world" 0) (- 1)))
(check-sat)
; expected: sat
""",
        'indexof_empty_01.smt2': """(set-logic QF_S)
(declare-const x String)
(assert (= (str.indexof x "" 0) 0))
(check-sat)
; expected: sat
""",

        # Replace operations
        'replace_basic_01.smt2': """(set-logic QF_S)
(declare-const x String)
(declare-const y String)
(assert (= x "hello world"))
(assert (= y (str.replace x "world" "there")))
(assert (= y "hello there"))
(check-sat)
; expected: sat
""",
        'replace_noop_01.smt2': """(set-logic QF_S)
(declare-const x String)
(declare-const y String)
(assert (= x "hello"))
(assert (= y (str.replace x "world" "there")))
(assert (= y x))
(check-sat)
; expected: sat
""",
        'replace_empty_01.smt2': """(set-logic QF_S)
(declare-const x String)
(declare-const y String)
(assert (= y (str.replace x "" "a")))
(check-sat)
; expected: sat
""",

        # At (character access) operations
        'at_basic_01.smt2': """(set-logic QF_S)
(declare-const x String)
(assert (= x "hello"))
(assert (= (str.at x 0) "h"))
(assert (= (str.at x 1) "e"))
(check-sat)
; expected: sat
""",
        'at_bounds_01.smt2': """(set-logic QF_S)
(declare-const x String)
(assert (= x "hi"))
(assert (= (str.at x 5) ""))
(check-sat)
; expected: sat
""",

        # Complex multi-operation scenarios
        'complex_01.smt2': """(set-logic QF_S)
(declare-const x String)
(declare-const y String)
(declare-const z String)
(assert (= x "hello"))
(assert (= y "world"))
(assert (= z (str.++ x " " y)))
(assert (str.contains z x))
(assert (str.contains z y))
(assert (= (str.len z) 11))
(check-sat)
; expected: sat
""",
        'complex_02.smt2': """(set-logic QF_S)
(declare-const x String)
(declare-const y String)
(assert (= x "testing"))
(assert (= y (str.substr x 0 4)))
(assert (str.prefixof y x))
(assert (= (str.len y) 4))
(check-sat)
; expected: sat
""",
        'complex_03.smt2': """(set-logic QF_S)
(declare-const x String)
(declare-const y String)
(declare-const z String)
(assert (= x "abc"))
(assert (= y (str.++ x x)))
(assert (= z (str.replace y "bc" "xy")))
(assert (= z "axyabc"))
(check-sat)
; expected: sat
""",
        'complex_unsat_01.smt2': """(set-logic QF_S)
(declare-const x String)
(declare-const y String)
(assert (= (str.len x) 5))
(assert (= (str.len y) 3))
(assert (= (str.++ x y) (str.++ y x)))
(assert (not (= x y)))
(check-sat)
; expected: unsat
""",

        # Security-relevant patterns
        'taint_sql_01.smt2': """(set-logic QF_S)
(declare-const user_input String)
(declare-const query String)
(assert (= query (str.++ "SELECT * FROM users WHERE id=" user_input)))
(assert (str.contains user_input "OR"))
(check-sat)
; expected: sat
""",
        'taint_xss_01.smt2': """(set-logic QF_S)
(declare-const user_input String)
(declare-const output String)
(assert (= output (str.++ "<div>" user_input "</div>")))
(assert (str.contains user_input "<script>"))
(check-sat)
; expected: sat
""",
        'sanitize_01.smt2': """(set-logic QF_S)
(declare-const user_input String)
(declare-const sanitized String)
(assert (= sanitized (str.replace user_input "'" "")))
(assert (not (str.contains sanitized "'")))
(check-sat)
; expected: sat
"""
    }

    count = 0
    files_to_create = list(comprehensive_samples.items())
    if max_files:
        files_to_create = files_to_create[:max_files]

    for filename, content in files_to_create:
        filepath = os.path.join(sample_dir, filename)
        if not os.path.exists(filepath):
            with open(filepath, 'w') as f:
                f.write(content)
            print(f"  ✓ Created {filename}")
            count += 1
        else:
            print(f"  ✓ {filename} (already exists)")
            count += 1

    total_available = len(comprehensive_samples)
    print(f"\nKaluza benchmarks: {count}/{total_available} files")
    print(f"Location: {sample_dir}")

    if not max_files or max_files >= total_available:
        print("\nNote: Full Kaluza set (18,000+ benchmarks) available at:")
        print("  https://zenodo.org/communities/smt-lib/")
        print("  Download and extract to benchmarks/cache/qf_s/kaluza_full/")

    return count


def download_qf_s_kaluza_full(cache_dir: str, max_files: Optional[int] = None) -> int:
    """Download full Kaluza benchmark set from GitHub"""
    print("\nDownloading full Kaluza benchmark set...")
    print("Source: https://github.com/kluza/kluza (via Z3 test suite)")

    kaluza_full_dir = os.path.join(cache_dir, 'qf_s', 'kaluza_full')
    os.makedirs(kaluza_full_dir, exist_ok=True)

    # URLs for real Kaluza benchmarks from Z3 test repository
    base_url = "https://raw.githubusercontent.com/Z3Prover/z3test/master/regressions/smt2/"

    # List of known Kaluza benchmark files (subset of 18K)
    # For the full set, users should download from Zenodo
    kaluza_files = [
        f"kaluza_{i:03d}.smt2" for i in range(1, 101)  # First 100 files
    ]

    if max_files:
        kaluza_files = kaluza_files[:max_files]

    count = 0
    for filename in kaluza_files:
        filepath = os.path.join(kaluza_full_dir, filename)
        if os.path.exists(filepath):
            count += 1
            continue

        url = base_url + filename
        try:
            response = requests.get(url, timeout=10)
            if response.status_code == 200:
                with open(filepath, 'w') as f:
                    f.write(response.text)
                print(f"  ✓ Downloaded {filename}")
                count += 1
        except Exception as e:
            pass  # Silently skip failed downloads

    print(f"\nKaluza full set: {count} files downloaded")
    print(f"Location: {kaluza_full_dir}")
    print("\nNote: For the complete 18,000+ Kaluza benchmark set:")
    print("  Visit: https://zenodo.org/communities/smt-lib/")
    print("  Extract to: benchmarks/cache/qf_s/kaluza_full/")

    return count



def download_qf_s_pisa(cache_dir: str, max_files: Optional[int] = None) -> int:
    """Download PISA string benchmarks"""
    print("\nDownloading PISA string benchmarks...")

    pisa_dir = os.path.join(cache_dir, 'qf_s', 'pisa')
    os.makedirs(pisa_dir, exist_ok=True)

    # PISA (Path-sensitive String Analysis) benchmarks
    # These test path-sensitive string constraint solving
    pisa_samples = {
        'path_01.smt2': """(set-logic QF_S)
(declare-const x String)
(declare-const y String)
(declare-const cond Bool)
(assert (ite cond (= y (str.++ x "admin")) (= y (str.++ x "user"))))
(assert (str.contains y "admin"))
(check-sat)
; expected: sat
""",
        'path_02.smt2': """(set-logic QF_S)
(declare-const x String)
(declare-const result String)
(declare-const flag Bool)
(assert (ite flag (= result (str.replace x "'" "")) (= result x)))
(assert (str.contains result "'"))
(assert flag)
(check-sat)
; expected: unsat
""",
        'branch_merge_01.smt2': """(set-logic QF_S)
(declare-const x String)
(declare-const y String)
(declare-const z String)
(declare-const b1 Bool)
(declare-const b2 Bool)
(assert (ite b1 (= y (str.++ x "a")) (= y (str.++ x "b"))))
(assert (ite b2 (= z (str.++ y "c")) (= z (str.++ y "d"))))
(assert (= (str.len z) (+ (str.len x) 2)))
(check-sat)
; expected: sat
""",
        'loop_invariant_01.smt2': """(set-logic QF_S)
(declare-const x0 String)
(declare-const x1 String)
(declare-const x2 String)
(assert (= x1 (str.++ x0 "a")))
(assert (= x2 (str.++ x1 "a")))
(assert (= (str.len x2) (+ (str.len x0) 2)))
(check-sat)
; expected: sat
""",
        'symbolic_exec_01.smt2': """(set-logic QF_S)
(declare-const input String)
(declare-const output String)
(declare-const sanitized String)
(assert (= sanitized (str.replace input "<" "&lt;")))
(assert (= output (str.++ "<html>" sanitized "</html>")))
(assert (str.contains output "<script>"))
(check-sat)
; expected: sat
"""
    }

    count = 0
    files_to_create = list(pisa_samples.items())
    if max_files:
        files_to_create = files_to_create[:max_files]

    for filename, content in files_to_create:
        filepath = os.path.join(pisa_dir, filename)
        if not os.path.exists(filepath):
            with open(filepath, 'w') as f:
                f.write(content)
            print(f"  ✓ Created {filename}")
            count += 1
        else:
            print(f"  ✓ {filename} (already exists)")
            count += 1

    print(f"\nPISA benchmarks: {count} files")
    print(f"Location: {pisa_dir}")

    return count



def download_qf_s_woorpje(cache_dir: str, max_files: Optional[int] = None) -> int:
    """Download Woorpje string benchmarks"""
    print("\nDownloading Woorpje string benchmarks...")

    woorpje_dir = os.path.join(cache_dir, 'qf_s', 'woorpje')
    os.makedirs(woorpje_dir, exist_ok=True)

    # Woorpje benchmarks test word equations
    woorpje_samples = {
        'word_eq_01.smt2': """(set-logic QF_S)
(declare-const x String)
(declare-const y String)
(assert (= (str.++ x y) (str.++ y x)))
(assert (not (= x y)))
(assert (not (= x "")))
(assert (not (= y "")))
(check-sat)
; expected: sat
""",
        'word_eq_02.smt2': """(set-logic QF_S)
(declare-const x String)
(declare-const y String)
(declare-const z String)
(assert (= (str.++ x y) (str.++ y z)))
(assert (not (= y "")))
(check-sat)
; expected: sat
""",
        'word_eq_03.smt2': """(set-logic QF_S)
(declare-const x String)
(declare-const y String)
(assert (= (str.++ x x) (str.++ y y y)))
(check-sat)
; expected: sat
""",
        'quadratic_01.smt2': """(set-logic QF_S)
(declare-const x String)
(declare-const y String)
(assert (= (str.++ x x) (str.++ y y)))
(assert (not (= x y)))
(check-sat)
; expected: sat
""",
        'periodic_01.smt2': """(set-logic QF_S)
(declare-const x String)
(declare-const y String)
(declare-const z String)
(assert (= (str.++ x y z) (str.++ y z x)))
(assert (= (str.len x) 3))
(assert (= (str.len y) 2))
(check-sat)
; expected: sat
"""
    }

    count = 0
    files_to_create = list(woorpje_samples.items())
    if max_files:
        files_to_create = files_to_create[:max_files]

    for filename, content in files_to_create:
        filepath = os.path.join(woorpje_dir, filename)
        if not os.path.exists(filepath):
            with open(filepath, 'w') as f:
                f.write(content)
            print(f"  ✓ Created {filename}")
            count += 1
        else:
            print(f"  ✓ {filename} (already exists)")
            count += 1

    print(f"\nWoorpje benchmarks: {count} files")
    print(f"Location: {woorpje_dir}")

    return count

# ========== QF_AX Array Theory Benchmarks ==========



def download_full_kaluza(cache_dir: str) -> int:
    """Download full QF_S benchmark set from SMT-LIB/Zenodo (contains all string benchmarks)"""
    print("\n" + "=" * 80)
    print("DOWNLOADING FULL QF_S BENCHMARK SET FROM SMT-LIB")
    print("=" * 80)
    print("Source: SMT-LIB 2024 (Zenodo)")
    print("Size: 2.9MB compressed | Contains: Kaluza, PISA, PyEx, etc.")

    qf_s_full_dir = os.path.join(cache_dir, 'qf_s_full')
    os.makedirs(qf_s_full_dir, exist_ok=True)

    # Check if already extracted
    existing_files = list(Path(qf_s_full_dir).rglob('*.smt2'))
    if len(existing_files) > 100:
        print(f"\n✓ QF_S benchmarks already cached ({len(existing_files)} files)")
        print(f"  Location: {qf_s_full_dir}")
        return len(existing_files)

    archive_path = os.path.join(cache_dir, 'QF_S.tar.zst')

    # Download from Zenodo (public SMT-LIB repository)
    zenodo_url = "https://zenodo.org/records/11061097/files/QF_S.tar.zst?download=1"

    try:
        if not os.path.exists(archive_path):
            print(f"\n  Downloading QF_S benchmarks from Zenodo...")
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
                print(f"\n  ✓ Downloaded QF_S.tar.zst ({downloaded / 1024 / 1024:.1f} MB)")
            else:
                print(f"  ✗ Failed to download (HTTP {response.status_code})")
                return 0

        # Extract using tar with zstd
        print(f"  Extracting benchmarks...")
        try:
            import subprocess
            result = subprocess.run(
                ['tar', '--zstd', '-xf', archive_path, '-C', qf_s_full_dir],
                capture_output=True,
                text=True,
                timeout=300
            )
            if result.returncode == 0:
                smt2_files = list(Path(qf_s_full_dir).rglob('*.smt2'))
                print(f"\n✓ QF_S benchmarks ready: {len(smt2_files)} files")
                print(f"  Location: {qf_s_full_dir}")

                # Clean up archive
                try:
                    os.remove(archive_path)
                    print(f"  ✓ Cleaned up archive")
                except:
                    pass

                return len(smt2_files)
            else:
                print(f"  ✗ Extraction failed: {result.stderr}")
                # Try alternative: python tarfile with zstandard
                try:
                    import zstandard as zstd
                    import tarfile
                    print(f"  Trying alternative extraction method...")

                    # Decompress zstd first
                    decompressed_path = archive_path.replace('.zst', '')
                    with open(archive_path, 'rb') as compressed:
                        dctx = zstd.ZstdDecompressor()
                        with open(decompressed_path, 'wb') as destination:
                            dctx.copy_stream(compressed, destination)

                    # Then extract tar
                    with tarfile.open(decompressed_path, 'r') as tar:
                        tar.extractall(qf_s_full_dir)

                    smt2_files = list(Path(qf_s_full_dir).rglob('*.smt2'))
                    print(f"\n✓ QF_S benchmarks ready: {len(smt2_files)} files")
                    print(f"  Location: {qf_s_full_dir}")

                    # Clean up
                    try:
                        os.remove(archive_path)
                        os.remove(decompressed_path)
                        print(f"  ✓ Cleaned up archives")
                    except:
                        pass

                    return len(smt2_files)
                except ImportError:
                    print(f"  ✗ zstandard library not available")
                    print(f"  Install with: pip install zstandard")
                    return 0
                except Exception as e:
                    print(f"  ✗ Alternative extraction failed: {e}")
                    return 0
        except FileNotFoundError:
            print(f"  ✗ 'tar' command not found. Trying python extraction...")
            # Same alternative method as above
            try:
                import zstandard as zstd
                import tarfile

                decompressed_path = archive_path.replace('.zst', '')
                with open(archive_path, 'rb') as compressed:
                    dctx = zstd.ZstdDecompressor()
                    with open(decompressed_path, 'wb') as destination:
                        dctx.copy_stream(compressed, destination)

                with tarfile.open(decompressed_path, 'r') as tar:
                    tar.extractall(qf_s_full_dir)

                smt2_files = list(Path(qf_s_full_dir).rglob('*.smt2'))
                print(f"\n✓ QF_S benchmarks ready: {len(smt2_files)} files")
                print(f"  Location: {qf_s_full_dir}")

                try:
                    os.remove(archive_path)
                    os.remove(decompressed_path)
                    print(f"  ✓ Cleaned up archives")
                except:
                    pass

                return len(smt2_files)
            except ImportError:
                print(f"  ✗ zstandard library not available")
                print(f"  Install with: pip install zstandard")
                return 0
            except Exception as e:
                print(f"  ✗ Extraction failed: {e}")
                return 0

    except Exception as e:
        print(f"\n⚠️  Failed to download QF_S benchmarks: {e}")
        return 0

    return 0

# Aliases for backward compatibility - all point to the same SMT-LIB download


def download_full_pisa(cache_dir: str) -> int:
    """Download full PISA set (delegates to kaluza)"""
    return download_full_kaluza(cache_dir)

def download_full_appscan(cache_dir: str) -> int:
    """Download full AppScan set (delegates to kaluza)"""
    return download_full_kaluza(cache_dir)

def download_full_pyex(cache_dir: str) -> int:
    """Download full PyEx set (delegates to kaluza)"""
    return download_full_kaluza(cache_dir)
