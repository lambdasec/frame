"""Dependencies compiled into Go and Rust binaries (ELF), for images and root filesystems.

    Go 1.18+     the build info the linker writes after the magic `\\xff Go buildinf:`: the Go
                 version and the module list `go version -m` prints (`mod`, `dep`, `=>` lines).
                 The standard library is reported as the module `stdlib` at the Go version, which
                 is how OSV names its advisories.
    Rust         the `.dep-v0` section `cargo auditable` embeds (zlib-compressed JSON); a binary
                 built without it carries no dependency list, and is not named.

Older Go binaries keep the module list behind pointers into the data segment; they are counted,
not read. Nothing is guessed from symbol names or strings.

A Go binary also keeps its function table (`pclntab`, which stack traces need, so `-s -w` does
not strip it). Go's linker drops functions nothing can reach, so a function in the table is one
the program's call graph reaches: the evidence `govulncheck -mode binary` uses. `go_functions`
returns those names as advisories write them (`net/http.Server.Serve`). It is positive evidence
only: an inlined function has no entry of its own, so absence proves nothing.
"""

from __future__ import annotations

import json
import re
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
    functions: frozenset = frozenset()           # Go: functions in the binary, as advisories name them
    goos: str = ""                               # Go: the platform it was built for (`build GOOS=`)
    goarch: str = ""


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
    info = raw.decode("utf-8", "replace")
    main, deps = go_modinfo(info)
    settings = dict(line.split("\t", 1)[1].split("=", 1) for line in info.splitlines()
                    if line.startswith("build\t") and "=" in line)
    out = Binary("go", main=main, toolchain=version, goos=settings.get("GOOS", ""), goarch=settings.get("GOARCH", ""))
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


_PCLN_MAGIC = (0xFFFFFFF0, 0xFFFFFFF1)            # Go 1.18-1.19, Go 1.20+ (same header layout)


def _pclntab(data: bytes) -> Optional[bytes]:
    sec = _elf_section(data, ".gopclntab") or _elf_section(data, ".data.rel.ro.gopclntab")
    if sec is not None:
        return sec
    for magic in _PCLN_MAGIC:                     # no section headers: find the header itself
        for end in "<>":
            at = data.find(struct.pack(end + "I", magic) + b"\0\0")
            if at >= 0 and data[at + 6] in (1, 2, 4) and data[at + 7] in (4, 8):
                return data[at:]
    return None


def go_function_names(data: bytes) -> List[str]:
    """Every function name in a Go 1.18+ binary's pclntab, as the runtime spells it."""
    tab = _pclntab(data)
    if tab is None or len(tab) < 8:
        return []
    for end in "<>":
        magic, = struct.unpack_from(end + "I", tab, 0)
        if magic in _PCLN_MAGIC:
            break
    else:
        return []
    ptr = tab[7]
    word = end + ("Q" if ptr == 8 else "I")
    try:
        nfunc = struct.unpack_from(word, tab, 8)[0]
        funcname_off = struct.unpack_from(word, tab, 8 + 3 * ptr)[0]
        pcln_off = struct.unpack_from(word, tab, 8 + 7 * ptr)[0]
        names = []
        for i in range(nfunc):
            _, funcoff = struct.unpack_from(end + "II", tab, pcln_off + 8 * i)
            _, nameoff = struct.unpack_from(end + "Ii", tab, pcln_off + funcoff)
            start = funcname_off + nameoff
            names.append(tab[start:tab.index(b"\0", start)].decode("utf-8", "replace"))
        return names
    except (struct.error, ValueError):
        return []


_GENERIC = re.compile(r"\[[^\[\]]*\]")
_CLOSURE = re.compile(r"(\.(func|gowrap|deferwrap)\d+(\.\d+)*)+$")
_ESCAPED = re.compile(r"%([0-9a-fA-F]{2})")      # the linker escapes `.` in a path's last element


def advisory_name(runtime_name: str) -> str:
    """`net/http.(*Server).Serve` -> `net/http.Server.Serve`; generics' type arguments and the
    closures inside a function (`F.func1`) belong to the function they are written in."""
    name = _ESCAPED.sub(lambda m: chr(int(m.group(1), 16)), runtime_name)
    while _GENERIC.search(name):
        name = _GENERIC.sub("", name)
    name = name.replace("(*", "").replace(")", "")
    return _CLOSURE.sub("", name)


def read_binary(data: bytes) -> Optional[Binary]:
    """The dependencies compiled into an ELF binary, or None if it carries none Frame reads."""
    if data[:4] != ELF:
        return None
    go = _go(data)
    if go is not None and go.kind == "go":
        go.functions = frozenset(advisory_name(n) for n in go_function_names(data))
        return go
    return go or _rust(data)
