"""Test-wide settings."""

import os
import tempfile

# Scans load framework packs from a cached knowledge base when one exists (frame.kb). Tests
# must not depend on what a developer has pulled: point the cache at an empty directory.
os.environ["FRAME_KB_CACHE"] = tempfile.mkdtemp(prefix="frame-kb-test-")
os.environ.pop("FRAME_KB_SOURCE", None)
