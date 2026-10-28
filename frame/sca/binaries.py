"""Dependencies compiled into Go and Rust binaries (ELF), for images and root filesystems.

    Go 1.18+     the build info the linker writes after the magic `\\xff Go buildinf:`: the Go
                 version and the module list `go version -m` prints (`mod`, `dep`, `=>` lines).
                 The standard library is reported as the module `stdlib` at the Go version, which
                 is how OSV names its advisories.
    Rust         the `.dep-v0` section `cargo auditable` embeds (zlib-compressed JSON); a binary
                 built without it carries no dependency list, and is not named.

Older Go binaries keep the module list behind pointers into the data segment; they are counted,
not read. Nothing is guessed from symbol names or strings.
"""

from __future__ import annotations

import json
import struct
import zlib
from dataclasses import dataclass, field
from typing import List, Optional, Tuple

from frame.sca.model import CARGO, GO

GO_MAGIC = b"\xff Go buildinf:"
ELF = b"\x7fELF"


@dataclass
class Binary:
    kind: str                                    # "go" | "go-old" | "rust"
    packages: List[Tuple[str, str, str]] = field(default_factory=list)   # (ecosystem, name, version)
    main: str = ""                               # the main module / root crate
    toolchain: str = ""                          # Go version


def _uvarint(data: bytes, pos: int) -> Tuple[int, int]:
    out = shift = 0
    while pos < len(data):
        b = data[pos]
        pos += 1
        out |= (b & 0x7F) << shift
        if not b & 0x80:
            return out, pos
        shift += 7
    raise ValueError("truncated varint")


def go_modinfo(modinfo: str) -> Tuple[str, List[Tuple[str, str]]]:
    """The main module and (module, version) of each dependency, replacements applied."""
    main, deps = "", []
    for line in modinfo.splitlines():
        parts = line.split("\t")
        if parts[0] == "mod" and len(parts) >= 2:
            main = parts[1]
        elif parts[0] == "dep" and len(parts) >= 3:
            deps.append((parts[1], parts[2]))
        elif parts[0] == "=>" and len(parts) >= 3 and parts[2] and deps:
            deps[-1] = (parts[1], parts[2])          # replaced by this module and version
        elif parts[0] == "=>" and deps:
            deps.pop()                               # replaced by a local directory: not a module version
    return main, deps


def _go(data: bytes) -> Optional[Binary]:
    at = data.find(GO_MAGIC)
    if at < 0:
        return None
    head = data[at:at + 32]
    if len(head) < 32:
        return None
    flags = head[15]
    if not flags & 0x2:                              # pre-1.18: pointers into the data segment
        return Binary("go-old")
    try:
        n, pos = _uvarint(data, at + 32)
        version = data[pos:pos + n].decode("utf-8", "replace")
        n2, pos2 = _uvarint(data, pos + n)
        raw = data[pos2:pos2 + n2]
    except ValueError:
        return None
    if len(raw) >= 33 and raw[-17] == ord("\n"):
        raw = raw[16:-16]                            # the linker's 16-byte sentinels
    main, deps = go_modinfo(raw.decode("utf-8", "replace"))
    out = Binary("go", main=main, toolchain=version)
    go_ver = version.split()[0] if version else ""
    if go_ver.startswith("go") and go_ver[2:3].isdigit():
        out.packages.append((GO, "stdlib", go_ver[2:]))
    for mod, ver in deps:
        if ver and ver != "(devel)":
            out.packages.append((GO, mod, ver.lstrip("v")))
    return out


def _elf_section(data: bytes, wanted: str) -> Optional[bytes]:
    """The bytes of a named section of an ELF file (32/64-bit, either byte order)."""
    if len(data) < 64 or data[:4] != ELF:
        return None
    is64, end = data[4] == 2, "<" if data[5] == 1 else ">"
    try:
        if is64:
            shoff, = struct.unpack_from(end + "Q", data, 0x28)
            shentsize, shnum, shstrndx = struct.unpack_from(end + "HHH", data, 0x3A)
        else:
            shoff, = struct.unpack_from(end + "I", data, 0x20)
            shentsize, shnum, shstrndx = struct.unpack_from(end + "HHH", data, 0x2E)

        def section(i: int) -> Tuple[int, int, int]:
            base = shoff + i * shentsize
            if is64:
                name, _, _, _, off, size = struct.unpack_from(end + "IIQQQQ", data, base)
            else:
                name, _, _, _, off, size = struct.unpack_from(end + "IIIIII", data, base)
            return name, off, size
        if not shoff or shstrndx >= shnum:
            return None
        _, str_off, str_size = section(shstrndx)
        names = data[str_off:str_off + str_size]
        for i in range(shnum):
            name, off, size = section(i)
            label = names[name:names.find(b"\0", name)].decode("ascii", "replace")
            if label == wanted:
                return data[off:off + size]
    except struct.error:
        return None
    return None


def _rust(data: bytes) -> Optional[Binary]:
    sec = _elf_section(data, ".dep-v0")
    if sec is None:
        return None
    try:
        doc = json.loads(zlib.decompress(sec))
    except (zlib.error, ValueError):
        return None
    out = Binary("rust")
    for p in doc.get("packages") or []:
        if not isinstance(p, dict) or not p.get("name") or not p.get("version"):
            continue
        if p.get("root"):
            out.main = p["name"]
        if p.get("source") == "crates.io" and p.get("kind", "runtime") == "runtime":
            out.packages.append((CARGO, p["name"], p["version"]))
    return out


def read_binary(data: bytes) -> Optional[Binary]:
    """The dependencies compiled into an ELF binary, or None if it carries none Frame reads."""
    if data[:4] != ELF:
        return None
    return _go(data) or _rust(data)
