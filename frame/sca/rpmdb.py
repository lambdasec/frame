"""Installed packages from an rpm database (AlmaLinux, Rocky Linux, RHEL, Azure Linux, openSUSE).

    var/lib/rpm/rpmdb.sqlite            rpm 4.16+ (EL 9): a `Packages` table of header blobs
    var/lib/rpm/Packages                Berkeley DB hash (EL 8 and older): header blobs on
                                        overflow pages, read as go-rpmdb (Trivy, Syft) reads them
    usr/lib/sysimage/rpm/rpmdb.sqlite   the newer location (Fedora, EL 10)
    usr/lib/sysimage/rpm/Packages.db    NDB (SUSE, openSUSE): rpm's own format (lib/backend/ndb),
                                        slots pointing at blobs, read as go-rpmdb reads it

Each record is an rpm header (an index of tagged entries over a data store); the name, epoch,
version, release and licence are read from it. The `gpg-pubkey` pseudo-packages rpm keeps for
imported signing keys are not packages.
"""

from __future__ import annotations

import sqlite3
import struct
import tempfile
from pathlib import Path
from typing import Dict, Iterator, List, Optional, Tuple

SQLITE_PATHS = ("var/lib/rpm/rpmdb.sqlite", "usr/lib/sysimage/rpm/rpmdb.sqlite")
BDB_PATHS = ("var/lib/rpm/Packages", "usr/lib/sysimage/rpm/Packages")
NDB_PATHS = ("var/lib/rpm/Packages.db", "usr/lib/sysimage/rpm/Packages.db")
RPMDB_PATHS = SQLITE_PATHS + BDB_PATHS + NDB_PATHS

NAME, VERSION, RELEASE, EPOCH, LICENSE, ARCH, SOURCERPM = 1000, 1001, 1002, 1003, 1014, 1022, 1044
DIRINDEXES, BASENAMES, DIRNAMES = 1116, 1117, 1118        # the files a package installed
_INT32, _STRING, _STRING_ARRAY, _I18NSTRING = 4, 6, 8, 9


class RpmDBError(ValueError):
    pass


def parse_header(blob: bytes) -> Dict[int, object]:
    """The entries of an rpm header blob (`il`, `dl`, the index, the data store) Frame needs."""
    if len(blob) < 8:
        raise RpmDBError("header too short")
    il, dl = struct.unpack_from(">II", blob, 0)
    data = 8 + 16 * il
    if il > 100000 or data + dl > len(blob):
        raise RpmDBError("header index out of range")
    out: Dict[int, object] = {}
    for i in range(il):
        tag, typ, off, count = struct.unpack_from(">iIiI", blob, 8 + 16 * i)
        if tag not in (NAME, VERSION, RELEASE, EPOCH, LICENSE, ARCH, SOURCERPM, DIRINDEXES, BASENAMES, DIRNAMES) \
                or not 0 <= off < dl:
            continue
        at = data + off
        if tag == DIRINDEXES and typ == _INT32:
            out[tag] = list(struct.unpack_from(f">{count}i", blob, at))
        elif tag in (BASENAMES, DIRNAMES) and typ == _STRING_ARRAY:
            items = []
            for _ in range(count):
                end = blob.index(b"\0", at)
                items.append(blob[at:end].decode("utf-8", "replace"))
                at = end + 1
            out[tag] = items
        elif typ == _INT32 and count >= 1:
            out[tag] = struct.unpack_from(">i", blob, at)[0]
        elif typ in (_STRING, _STRING_ARRAY, _I18NSTRING):
            end = blob.index(b"\0", at)
            out[tag] = blob[at:end].decode("utf-8", "replace")
    return out


def _sqlite_blobs(db: bytes, wal: Optional[bytes]) -> Iterator[bytes]:
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "rpmdb.sqlite"
        path.write_bytes(db)
        if wal:
            (Path(tmp) / "rpmdb.sqlite-wal").write_bytes(wal)
        con = sqlite3.connect(f"file:{path}?mode=ro", uri=True) if not wal else sqlite3.connect(path)
        try:
            for (blob,) in con.execute("SELECT blob FROM Packages"):
                if blob:
                    yield bytes(blob)
        except sqlite3.DatabaseError as e:
            raise RpmDBError(f"not an rpm sqlite database: {e}") from e
        finally:
            con.close()


_HASH_MAGIC = 0x061561
_P_HASH_UNSORTED, _P_OVERFLOW, _P_HASH = 2, 7, 13
_H_OFFPAGE = 3
_PAGE_HEADER = 26


def _bdb_blobs(db: bytes) -> Iterator[bytes]:
    """Values of a Berkeley DB hash database stored off-page (rpm's headers always are)."""
    for end in "<>":
        if len(db) >= 72 and struct.unpack_from(end + "I", db, 12)[0] == _HASH_MAGIC:
            break
    else:
        raise RpmDBError("not a Berkeley DB hash database")
    pagesize, = struct.unpack_from(end + "I", db, 20)
    last, = struct.unpack_from(end + "I", db, 32)
    if pagesize < 512 or pagesize & (pagesize - 1):
        raise RpmDBError(f"bad page size {pagesize}")

    def page(n: int) -> bytes:
        return db[n * pagesize:(n + 1) * pagesize]

    for n in range(1, last + 1):
        p = page(n)
        if len(p) < _PAGE_HEADER or p[25] not in (_P_HASH, _P_HASH_UNSORTED):
            continue
        entries, = struct.unpack_from(end + "H", p, 20)
        for i in range(1, entries, 2):                         # (key, value) pairs: the values
            off, = struct.unpack_from(end + "H", p, _PAGE_HEADER + 2 * i)
            if off + 12 > len(p) or p[off] != _H_OFFPAGE:
                continue
            pgno, tlen = struct.unpack_from(end + "II", p, off + 4)
            chunks, seen = [], set()
            while pgno and pgno not in seen and pgno <= last:
                seen.add(pgno)
                q = page(pgno)
                if len(q) < _PAGE_HEADER or q[25] != _P_OVERFLOW:
                    break
                nxt, = struct.unpack_from(end + "I", q, 16)
                used, = struct.unpack_from(end + "H", q, 22)        # hf_offset: bytes used on an overflow page
                chunks.append(q[_PAGE_HEADER:_PAGE_HEADER + used])
                pgno = nxt
            blob = b"".join(chunks)
            if len(blob) >= tlen:
                yield blob[:tlen]


# NDB (rpm's lib/backend/ndb/rpmpkg.c): a 32-byte header ("RpmP", version 0, generation, the
# number of slot pages), then 16-byte slots ("Slot", package index, block offset, block count)
# filling the slot pages, each pointing at a blob ("BlbS", package index, checksum, length) in
# 16-byte blocks; the blob's body is the package's header. Little-endian.
_NDB_HEAD, _NDB_SLOT, _NDB_BLOB = b"RpmP", b"Slot", b"BlbS"
_NDB_PAGE, _NDB_BLOCK = 4096, 16


def _ndb_blobs(db: bytes) -> Iterator[bytes]:
    if db[:4] != _NDB_HEAD:
        raise RpmDBError("not an NDB package database")
    version, _generation, slot_pages = struct.unpack_from("<III", db, 4)
    if version != 0:
        raise RpmDBError(f"NDB version {version}")
    slots = slot_pages * (_NDB_PAGE // 16) - 2           # the header takes the first two slots
    for i in range(slots):
        off = 32 + 16 * i
        magic, index, block, count = struct.unpack_from("<4sIII", db, off)
        if magic != _NDB_SLOT:
            raise RpmDBError(f"bad NDB slot {i}")
        if index == 0:                                     # a free slot
            continue
        start = block * _NDB_BLOCK
        bmagic, bindex, _cksum, length = struct.unpack_from("<4sIII", db, start)
        if bmagic != _NDB_BLOB or bindex != index or start + 16 + length > len(db):
            raise RpmDBError(f"bad NDB blob for package {index}")
        yield db[start + 16:start + 16 + length]


def source_name(sourcerpm: str) -> str:
    """`openssl-3.0.7-27.el9.src.rpm` -> `openssl` (name-version-release.src.rpm)."""
    stem = sourcerpm[:-len(".src.rpm")] if sourcerpm.endswith(".src.rpm") else sourcerpm
    parts = stem.rsplit("-", 2)
    return parts[0] if len(parts) == 3 else ""


def read_rpmdb(files: Dict[str, object], owned: Optional[set] = None
               ) -> Tuple[Optional[str], List[Tuple[str, str, str, str]], List[str]]:
    """(the database's path, [(name, source package name, epoch:version-release, licence)],
    warnings). With `owned`, every file a package installed is added to it (relative, no /)."""
    for path in SQLITE_PATHS + BDB_PATHS + NDB_PATHS:
        db = files.get(path)
        if not isinstance(db, bytes):
            continue
        try:
            blobs = (_sqlite_blobs(db, files.get(path + "-wal")) if path.endswith(".sqlite")   # type: ignore[arg-type]
                     else _ndb_blobs(db) if path.endswith(".db") else _bdb_blobs(db))
            out = []
            for blob in blobs:
                h = parse_header(blob)
                name, version, release = h.get(NAME), h.get(VERSION), h.get(RELEASE)
                if not name or not version or name == "gpg-pubkey":
                    continue
                if owned is not None:
                    dirs, idx = h.get(DIRNAMES) or [], h.get(DIRINDEXES) or []
                    for base, d in zip(h.get(BASENAMES) or [], idx):
                        if 0 <= d < len(dirs):
                            owned.add(f"{dirs[d]}{base}".lstrip("/"))
                epoch = h.get(EPOCH)
                evr = f"{version}-{release}" if release else str(version)
                out.append((str(name), source_name(str(h.get(SOURCERPM) or "")) or str(name),
                            f"{epoch}:{evr}" if epoch else evr, str(h.get(LICENSE) or "")))
            return path, out, []
        except (RpmDBError, struct.error, ValueError) as e:
            return path, [], [f"/{path}: {e}"]
    return None, [], []
