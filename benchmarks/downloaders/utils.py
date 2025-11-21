"""Downloader utility functions"""

import os
import zipfile
import tarfile

# Try to import gdown for Google Drive downloads
try:
    import gdown
    GDOWN_AVAILABLE = True
except ImportError:
    GDOWN_AVAILABLE = False


def download_gdrive_file(gdrive_id: str, output_path: str, description: str) -> bool:
    """
    Download file from Google Drive using gdown

    Args:
        gdrive_id: Google Drive file ID
        output_path: Local path to save file
        description: Description for logging

    Returns:
        True if successful, False otherwise
    """
    if not GDOWN_AVAILABLE:
        print(f"\n⚠️  gdown library not installed. Install with: pip install gdown")
        print(f"   Skipping download of {description}")
        return False

    if os.path.exists(output_path):
        print(f"  ✓ {description} already downloaded")
        return True

    try:
        print(f"  Downloading {description}...")
        url = f"https://drive.google.com/uc?id={gdrive_id}"
        gdown.download(url, output_path, quiet=False)

        if os.path.exists(output_path):
            print(f"  ✓ Downloaded {description} successfully")
            return True
        else:
            print(f"  ✗ Failed to download {description}")
            return False
    except Exception as e:
        print(f"  ✗ Error downloading {description}: {e}")
        return False


def extract_archive(archive_path: str, extract_to: str) -> bool:
    """
    Extract zip or tar.gz archive

    Args:
        archive_path: Path to archive file
        extract_to: Directory to extract to

    Returns:
        True if successful, False otherwise
    """
    try:
        if archive_path.endswith('.zip'):
            with zipfile.ZipFile(archive_path, 'r') as zip_ref:
                zip_ref.extractall(extract_to)
            print(f"  ✓ Extracted to {extract_to}")
            return True
        elif archive_path.endswith('.tar.gz') or archive_path.endswith('.tgz'):
            with tarfile.open(archive_path, 'r:gz') as tar_ref:
                tar_ref.extractall(extract_to)
            print(f"  ✓ Extracted to {extract_to}")
            return True
        else:
            print(f"  ✗ Unknown archive format: {archive_path}")
            return False
    except Exception as e:
        print(f"  ✗ Error extracting {archive_path}: {e}")
        return False
