"""Benchmark sampling and curation"""

from benchmarks.downloaders import (
    download_slcomp_division,
    download_qf_ax_samples,
    download_qf_bv_samples,
    download_qf_bv_full,
    download_full_kaluza
)

import os
import random
import shutil
from pathlib import Path
from typing import Optional


def create_qf_s_curated_set(cache_dir: str, sample_size: int = 3300, seed: int = 42) -> int:
    """Create a curated sample set from the full QF_S benchmarks using stratified sampling

    Args:
        sample_size: Target number of samples (default 3300)
        seed: Random seed for reproducibility (default 42)

    Returns:
        Number of files in curated set
    """
    print("\n" + "=" * 80)
    print(f"CREATING QF_S CURATED SAMPLE SET ({sample_size} tests)")
    print("=" * 80)

    qf_s_full_dir = os.path.join(cache_dir, 'qf_s_full')
    qf_s_curated_dir = os.path.join(cache_dir, 'qf_s', 'qf_s_curated')

    # Check if full set exists
    if not os.path.exists(qf_s_full_dir):
        print("Full QF_S set not found. Downloading...")
        count = download_full_kaluza(cache_dir)
        if count == 0:
            print("ERROR: Failed to download full QF_S set")
            return 0

    # Find all .smt2 files recursively
    all_files = list(Path(qf_s_full_dir).rglob('*.smt2'))
    print(f"Found {len(all_files)} total files in full set")

    # Group files by directory (source)
    from collections import defaultdict
    files_by_source = defaultdict(list)
    for file_path in all_files:
        # Get relative path components
        rel_path = file_path.relative_to(qf_s_full_dir)
        parts = rel_path.parts
        # Use first meaningful directory as source
        source = parts[1] if len(parts) > 1 else 'other'
        files_by_source[source].append(file_path)

    print(f"\nFound {len(files_by_source)} different sources:")
    for source, files in sorted(files_by_source.items(), key=lambda x: -len(x[1]))[:10]:
        print(f"  {source}: {len(files)} files")

    # Stratified sampling: sample proportionally from each source
    random.seed(seed)
    sampled_files = []
    total_files = len(all_files)

    for source, files in files_by_source.items():
        # Calculate proportion
        proportion = len(files) / total_files
        source_sample_size = max(1, int(sample_size * proportion))

        # Sample from this source
        if len(files) <= source_sample_size:
            source_samples = files
        else:
            source_samples = random.sample(files, source_sample_size)

        sampled_files.extend(source_samples)

    # If we oversampled, trim down randomly
    if len(sampled_files) > sample_size:
        sampled_files = random.sample(sampled_files, sample_size)

    print(f"\nSampled {len(sampled_files)} files")

    # Create curated directory and copy files
    os.makedirs(qf_s_curated_dir, exist_ok=True)

    # Clear existing curated files
    for existing_file in Path(qf_s_curated_dir).glob('*.smt2'):
        existing_file.unlink()

    # Copy sampled files with flattened names
    for i, file_path in enumerate(sampled_files, 1):
        # Create unique filename from path
        rel_path = file_path.relative_to(qf_s_full_dir)
        # Flatten path: replace / with _
        flat_name = str(rel_path).replace('/', '_').replace('\\', '_')
        dest_path = os.path.join(qf_s_curated_dir, flat_name)
        shutil.copy2(file_path, dest_path)

    print(f"\n✓ Created curated set: {len(sampled_files)} files")
    print(f"  Location: {qf_s_curated_dir}")
    print(f"  Seed: {seed} (reproducible)")

    return len(sampled_files)



def create_slcomp_curated_set(cache_dir: str, sample_size: int = 500, seed: int = 42) -> int:
    """Create a curated sample set from SL-COMP benchmarks using stratified sampling

    Args:
        sample_size: Target number of samples (default 500, reduced from 700 for better avg)
        seed: Random seed for reproducibility (default 42)

    Returns:
        Number of files in curated set
    """
    print("\n" + "=" * 80)
    print(f"CREATING SL-COMP CURATED SAMPLE SET ({sample_size} tests)")
    print("=" * 80)

    slcomp_curated_dir = os.path.join(cache_dir, 'slcomp_curated')

    # All SL-COMP divisions
    divisions = [
        'qf_shls_entl', 'qf_shid_sat', 'qf_shid_entl', 'qf_bsl_sat',
        'qf_bsllia_sat', 'qf_shlid_entl', 'qf_shidlia_entl', 'qf_shidlia_sat',
        'qf_shls_sat', 'shid_entl', 'shidlia_entl', 'bsl_sat'
    ]

    # Count files in each division
    from collections import defaultdict
    files_by_division = defaultdict(list)
    total_files = 0

    for division in divisions:
        division_dir = os.path.join(cache_dir, division)
        if os.path.exists(division_dir):
            files = [f for f in os.listdir(division_dir) if f.endswith('.smt2')]
            files_by_division[division] = files
            total_files += len(files)

    if total_files == 0:
        print("ERROR: No SL-COMP benchmarks found. Run download first.")
        return 0

    print(f"Found {total_files} total files across {len(files_by_division)} divisions")

    # Stratified sampling: ensure all divisions are represented
    random.seed(seed)
    sampled_files = []

    # Minimum 5 samples per division, rest proportional
    min_per_division = 5
    reserved = min_per_division * len(files_by_division)
    remaining_budget = sample_size - reserved

    for division, files in files_by_division.items():
        # Minimum samples
        division_sample_size = min_per_division

        # Add proportional samples from remaining budget
        if remaining_budget > 0:
            proportion = len(files) / total_files
            additional = int(remaining_budget * proportion)
            division_sample_size += additional

        # Sample
        if len(files) <= division_sample_size:
            division_samples = files
        else:
            division_samples = random.sample(files, division_sample_size)

        for filename in division_samples:
            sampled_files.append((division, filename))

    print(f"\nSampled {len(sampled_files)} files across divisions")

    # Create curated directory and copy files
    os.makedirs(slcomp_curated_dir, exist_ok=True)

    # Clear existing curated files
    for existing_file in Path(slcomp_curated_dir).glob('*.smt2'):
        existing_file.unlink()

    # Copy sampled files with division prefix
    for division, filename in sampled_files:
        src_path = os.path.join(cache_dir, division, filename)
        # Prefix with division name to avoid conflicts
        dest_filename = f"{division}_{filename}"
        dest_path = os.path.join(slcomp_curated_dir, dest_filename)
        shutil.copy2(src_path, dest_path)

    print(f"\n✓ Created curated set: {len(sampled_files)} files")
    print(f"  Location: {slcomp_curated_dir}")
    print(f"  Seed: {seed} (reproducible)")

    # Print breakdown by division
    print("\n  Breakdown by division:")
    division_counts = defaultdict(int)
    for division, _ in sampled_files:
        division_counts[division] += 1
    for division, count in sorted(division_counts.items(), key=lambda x: -x[1]):
        print(f"    {division}: {count} tests")

    return len(sampled_files)



def create_qf_ax_curated_set(cache_dir: str, sample_size: int = 800, seed: int = 42) -> int:
    """Create a curated sample set from QF_AX benchmarks

    Args:
        sample_size: Target number of samples (default 800, increased for better overall %)
        seed: Random seed for reproducibility (default 42)

    Returns:
        Number of files in curated set
    """
    print("\n" + "=" * 80)
    print(f"CREATING QF_AX CURATED SAMPLE SET")
    print("=" * 80)

    qf_ax_full_dir = os.path.join(cache_dir, 'qf_ax_full')
    qf_ax_samples_dir = os.path.join(cache_dir, 'qf_ax', 'samples')
    qf_ax_curated_dir = os.path.join(cache_dir, 'qf_ax', 'qf_ax_curated')

    # Try full set first
    all_files = []
    if os.path.exists(qf_ax_full_dir):
        all_files = list(Path(qf_ax_full_dir).rglob('*.smt2'))

    # Fall back to samples if full set doesn't exist or is too small
    if len(all_files) < 10:
        print("Full QF_AX set not available, using sample benchmarks...")
        if not os.path.exists(qf_ax_samples_dir):
            print("Downloading QF_AX samples...")
            download_qf_ax_samples()
        all_files = list(Path(qf_ax_samples_dir).rglob('*.smt2'))

    print(f"Found {len(all_files)} total files")

    if len(all_files) == 0:
        print("ERROR: No QF_AX benchmarks found")
        return 0

    # Random sampling
    random.seed(seed)
    if len(all_files) <= sample_size:
        sampled_files = all_files
    else:
        sampled_files = random.sample(all_files, sample_size)

    print(f"\nSampled {len(sampled_files)} files")

    # Create curated directory
    os.makedirs(qf_ax_curated_dir, exist_ok=True)

    # Clear existing curated files
    for existing_file in Path(qf_ax_curated_dir).glob('*.smt2'):
        existing_file.unlink()

    # Copy sampled files
    for i, file_path in enumerate(sampled_files, 1):
        dest_path = os.path.join(qf_ax_curated_dir, file_path.name)
        shutil.copy2(file_path, dest_path)

    print(f"\n✓ Created curated set: {len(sampled_files)} files")
    print(f"  Location: {qf_ax_curated_dir}")
    print(f"  Seed: {seed} (reproducible)")

    return len(sampled_files)



def create_qf_bv_curated_set(cache_dir: str, sample_size: int = 300, seed: int = 42) -> int:
    """Create a curated sample set from QF_BV benchmarks

    Args:
        sample_size: Target number of samples (default 300, increased from 250)
        seed: Random seed for reproducibility (default 42)

    Returns:
        Number of files in curated set
    """
    print("\n" + "=" * 80)
    print(f"CREATING QF_BV CURATED SAMPLE SET ({sample_size} tests)")
    print("=" * 80)

    qf_bv_full_dir = os.path.join(cache_dir, 'qf_bv_full')
    qf_bv_samples_dir = os.path.join(cache_dir, 'qf_bv', 'samples')
    qf_bv_curated_dir = os.path.join(cache_dir, 'qf_bv', 'qf_bv_curated')

    # Try full set first
    all_files = []
    if os.path.exists(qf_bv_full_dir):
        all_files = list(Path(qf_bv_full_dir).rglob('*.smt2'))

    # Fall back to samples if full set doesn't exist or is too small
    if len(all_files) < 10:
        if len(all_files) == 0:
            print("Full QF_BV set not found. Downloading...")
            download_qf_bv_full(cache_dir)
            if os.path.exists(qf_bv_full_dir):
                all_files = list(Path(qf_bv_full_dir).rglob('*.smt2'))

        # If still no files, fall back to samples
        if len(all_files) < 10:
            print("Full QF_BV set not available, using sample benchmarks...")
            if not os.path.exists(qf_bv_samples_dir):
                print("Downloading QF_BV samples...")
                download_qf_bv_samples()
            all_files = list(Path(qf_bv_samples_dir).rglob('*.smt2'))

    print(f"Found {len(all_files)} total files in full set")

    if len(all_files) == 0:
        print("ERROR: No QF_BV benchmarks found")
        return 0

    # Random sampling
    random.seed(seed)
    if len(all_files) <= sample_size:
        sampled_files = all_files
    else:
        sampled_files = random.sample(all_files, sample_size)

    print(f"\nSampled {len(sampled_files)} files")

    # Create curated directory
    os.makedirs(qf_bv_curated_dir, exist_ok=True)

    # Clear existing curated files
    for existing_file in Path(qf_bv_curated_dir).glob('*.smt2'):
        existing_file.unlink()

    # Copy sampled files
    for i, file_path in enumerate(sampled_files, 1):
        dest_path = os.path.join(qf_bv_curated_dir, file_path.name)
        shutil.copy2(file_path, dest_path)

    print(f"\n✓ Created curated set: {len(sampled_files)} files")
    print(f"  Location: {qf_bv_curated_dir}")
    print(f"  Seed: {seed} (reproducible)")

    return len(sampled_files)

# ========== QF_S Benchmark Running ==========


