"""Frame's knowledge base: framework packs (and later rules, advisories and secret formats)
delivered as versioned data, outside the Frame release.

A knowledge base is a directory (published as a Hugging Face dataset, mirrored anywhere,
or unpacked locally) holding `manifest.json` and data files. The manifest lists every file
with its SHA-256, size, language and kind; Frame downloads only the files for the
languages a project uses, checks each against the manifest, and caches them. A scan never
goes to the network: it reads what `frame kb pull` cached (pinned per project in
`.frame/kb.lock`), or falls back to the packs built into the wheel.

Files are data only (TOML packs, JSON tables): nothing in a knowledge base executes.
"""

from frame.kb.store import (  # noqa: F401
    DEFAULT_SOURCE, KBError, LOCKFILE, MANIFEST, build, cache_root, kb_pack_dirs, kb_spec_file,
    pull, read_lock, status, write_lock,
)
