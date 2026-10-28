"""Operating-system packages in a container image or a root filesystem (`frame deps --image`,
`--rootfs`), for matching against OSV's distribution advisories.

    /etc/os-release              the distribution and release: the OSV ecosystem
                                 (`Debian:12`, `Ubuntu:22.04:LTS`, `Alpine:v3.18`)
    /var/lib/dpkg/status         Debian / Ubuntu: installed packages (and `status.d/`, which
                                 distroless images use instead)
    /lib/apk/db/installed        Alpine: installed packages

OSV names distribution packages by their SOURCE package (openssl, not libssl3), so binaries are
grouped under the source package and source version dpkg / apk record (`Source:` / origin).
Only the files above are read from an image: `docker save` layers are applied in order, with
whiteouts (`.wh.<name>`) and opaque directories (`.wh..wh..opq`) honoured. A distribution Frame
has no advisories for (RHEL, SUSE...) is reported as such, never guessed.
"""

from __future__ import annotations

import io
import json
import re
import shutil
import subprocess
import tarfile
import tempfile
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from frame.sca.model import DependencyFile, Package

OS_RELEASE = ("etc/os-release", "usr/lib/os-release")
DPKG_STATUS = "var/lib/dpkg/status"
DPKG_STATUS_D = "var/lib/dpkg/status.d/"
APK_INSTALLED = "lib/apk/db/installed"


class ContainerError(RuntimeError):
    pass


def os_release(text: str) -> Dict[str, str]:
    out = {}
    for line in text.splitlines():
        m = re.match(r"^([A-Z_]+)=(.*)$", line.strip())
        if m:
            v = m.group(2).strip()
            out[m.group(1)] = v[1:-1] if len(v) >= 2 and v[0] == v[-1] and v[0] in "\"'" else v
    return out


def ecosystem_of(release: Dict[str, str]) -> Optional[str]:
    """The OSV ecosystem of a release, or None when Frame has no advisories for it."""
    rid, vid = release.get("ID", "").lower(), release.get("VERSION_ID", "")
    if rid == "debian" and re.fullmatch(r"\d+", vid.split(".")[0] or ""):
        return f"Debian:{vid.split('.')[0]}"
    if rid == "ubuntu" and re.fullmatch(r"\d+\.\d+", vid):
        lts = "LTS" in release.get("VERSION", "")
        return f"Ubuntu:{vid}" + (":LTS" if lts else "")
    if rid == "alpine" and re.fullmatch(r"\d+\.\d+(\.\d+)?", vid):
        major, minor = vid.split(".")[:2]
        return f"Alpine:v{major}.{minor}"
    return None


def _paragraphs(text: str) -> List[Dict[str, str]]:
    out, cur, last = [], {}, None
    for line in text.splitlines():
        if not line.strip():
            if cur:
                out.append(cur)
            cur, last = {}, None
        elif line[0] in " \t" and last:
            cur[last] += "\n" + line.strip()
        elif ":" in line:
            k, v = line.split(":", 1)
            cur[k.strip()], last = v.strip(), k.strip()
    if cur:
        out.append(cur)
    return out


def parse_dpkg(path: str, text: str, ecosystem: str) -> DependencyFile:
    """Installed packages grouped by source package and source version."""
    df = DependencyFile(path, ecosystem, "installed")
    for p in _paragraphs(text):
        status = p.get("Status", "install ok installed")
        if not p.get("Package") or not p.get("Version") or not status.endswith(" installed"):
            continue
        source, version = p["Package"], p["Version"]
        if p.get("Source"):
            m = re.match(r"^(\S+)(?:\s+\(([^)]+)\))?$", p["Source"])
            if m:
                source = m.group(1)
                version = m.group(2) or version
        df.add(Package(ecosystem, source, version))
    return df


def parse_apk(path: str, text: str, ecosystem: str) -> DependencyFile:
    """Installed packages by origin (the source package Alpine's advisories name)."""
    df = DependencyFile(path, ecosystem, "installed")
    for block in re.split(r"\n\s*\n", text):
        fields: Dict[str, str] = {}
        for line in block.splitlines():
            if len(line) > 2 and line[1] == ":" and line[0] not in fields:
                fields[line[0]] = line[2:].strip()
        name, version = fields.get("o") or fields.get("P"), fields.get("V")
        if name and version:
            pkg = df.add(Package(ecosystem, name, version))
            if fields.get("L") and not pkg.license:
                pkg.license = fields["L"]
    return df


def read_files(files: Dict[str, str], origin: str) -> Tuple[List[DependencyFile], List[str]]:
    """From {path in the image: text}: the installed packages, and warnings."""
    release_text = next((files[p] for p in OS_RELEASE if p in files), None)
    if release_text is None:
        return [], [f"{origin}: no /etc/os-release, so the distribution is unknown"]
    release = os_release(release_text)
    eco = ecosystem_of(release)
    pretty = release.get("PRETTY_NAME") or release.get("ID", "?")
    has_pkgs = DPKG_STATUS in files or APK_INSTALLED in files or any(p.startswith(DPKG_STATUS_D) for p in files)
    if eco is None:
        return [], [f"{origin}: {pretty} has no advisories in Frame (Debian, Ubuntu and Alpine are read)"
                    + ("" if has_pkgs else "; no package database found")]
    out: List[DependencyFile] = []
    if DPKG_STATUS in files:
        out.append(parse_dpkg(f"{origin}:/{DPKG_STATUS}", files[DPKG_STATUS], eco))
    status_d = sorted(p for p in files if p.startswith(DPKG_STATUS_D) and not p.endswith(".md5sums"))
    if status_d:
        out.append(parse_dpkg(f"{origin}:/{DPKG_STATUS_D.rstrip('/')}", "\n\n".join(files[p] for p in status_d), eco))
    if APK_INSTALLED in files:
        out.append(parse_apk(f"{origin}:/{APK_INSTALLED}", files[APK_INSTALLED], eco))
    if not out:
        return [], [f"{origin}: {pretty}, but no package database (a scratch or static image?)"]
    return out, []


def _wanted(path: str) -> bool:
    return path in OS_RELEASE or path in (DPKG_STATUS, APK_INSTALLED) or path.startswith(DPKG_STATUS_D)


def read_rootfs(root: Path) -> Tuple[List[DependencyFile], List[str]]:
    root = Path(root)
    files: Dict[str, str] = {}
    for rel in OS_RELEASE + (DPKG_STATUS, APK_INSTALLED):
        p = root / rel
        if p.is_file():
            files[rel] = p.read_text(encoding="utf-8", errors="replace")
    sd = root / DPKG_STATUS_D
    if sd.is_dir():
        for p in sorted(sd.iterdir()):
            if p.is_file():
                files[f"{DPKG_STATUS_D}{p.name}"] = p.read_text(encoding="utf-8", errors="replace")
    return read_files(files, str(root))


def _norm(name: str) -> str:
    return name.lstrip("./")


def read_image_tar(tar_path: Path, origin: Optional[str] = None) -> Tuple[List[DependencyFile], List[str]]:
    """A `docker save` tarball: apply the layers in order, keeping only the files needed."""
    origin = origin or Path(tar_path).name
    files: Dict[str, str] = {}
    with tarfile.open(tar_path) as outer:
        try:
            manifest = json.load(outer.extractfile("manifest.json"))
        except (KeyError, ValueError, TypeError) as e:
            raise ContainerError(f"{tar_path}: not a docker save archive (no manifest.json)") from e
        for layer_name in manifest[0]["Layers"]:
            member = outer.extractfile(layer_name)
            if member is None:
                continue
            data = member.read()
            with tarfile.open(fileobj=io.BytesIO(data)) as layer:
                for m in layer.getmembers():
                    name = _norm(m.name)
                    base, _, leaf = name.rpartition("/")
                    if leaf == ".wh..wh..opq":                  # opaque: drop what lower layers had here
                        files = {k: v for k, v in files.items() if not k.startswith(base + "/")}
                    elif leaf.startswith(".wh."):
                        gone = (base + "/" if base else "") + leaf[4:]
                        files = {k: v for k, v in files.items() if k != gone and not k.startswith(gone + "/")}
                    elif m.isfile() and _wanted(name):
                        f = layer.extractfile(m)
                        if f is not None:
                            files[name] = f.read().decode("utf-8", "replace")
    return read_files(files, origin)


def read_image(ref: str) -> Tuple[List[DependencyFile], List[str]]:
    """An image by reference: `docker save` (runs Docker; the image must be present or pullable)."""
    p = Path(ref)
    if p.is_file():
        return read_image_tar(p, ref)
    if shutil.which("docker") is None:
        raise ContainerError(f"{ref}: reading an image needs docker on PATH (or pass a `docker save` .tar)")
    with tempfile.TemporaryDirectory() as tmp:
        out = Path(tmp) / "image.tar"
        proc = subprocess.run(["docker", "save", "-o", str(out), ref], capture_output=True, text=True, timeout=1200)
        if proc.returncode != 0:
            raise ContainerError(f"{ref}: docker save failed: {(proc.stderr or proc.stdout).strip()[-300:]}")
        return read_image_tar(out, ref)
