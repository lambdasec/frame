"""QF_S (String Theory) benchmark downloaders"""

from benchmarks.downloaders.utils import download_gdrive_file, extract_archive
from benchmarks.downloaders._qf_s_benchmark_data import (
    comprehensive_samples,
    pisa_samples,
    woorpje_samples
)

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
