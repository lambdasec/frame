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

Language packages installed in the image are read too, from what the package managers leave:

    */site-packages/*.dist-info/METADATA, *.egg-info     Python (PyPI): Name and Version
    */node_modules/<name>/package.json                    npm: name and version
    *.jar (and jars inside it, a Spring Boot or WAR)      Maven: META-INF/maven/**/pom.properties

A jar without `pom.properties` is counted, never named from its file name. A package whose files
an OS package owns (dpkg's `info/*.list`, apk's `F:` lines) is left to the distribution's
advisories: Debian and Alpine patch the Python and Node packages they ship without changing the
upstream version, so matching them against PyPI or npm would report what is already fixed.
"""

from __future__ import annotations

import io
import json
import os
import re
import shutil
import subprocess
import tarfile
import tempfile
from pathlib import Path
import zipfile
from typing import Dict, List, Optional, Set, Tuple, Union

from frame.sca.model import MAVEN, NPM, PYPI, DependencyFile, Package

OS_RELEASE = ("etc/os-release", "usr/lib/os-release")
DPKG_STATUS = "var/lib/dpkg/status"
DPKG_STATUS_D = "var/lib/dpkg/status.d/"
APK_INSTALLED = "lib/apk/db/installed"
DPKG_INFO = "var/lib/dpkg/info/"
_PY_META = re.compile(r"(?:^|/)(?:site|dist)-packages/[^/]+\.(?:dist-info/METADATA|egg-info/PKG-INFO|egg-info)$")
_NPM_JSON = re.compile(r"(?:^|/)node_modules/((?:@[^/]+/)?[^/@.][^/]*)/package\.json$")
MAX_JAR = 512 * 1024 * 1024                  # a larger archive is skipped with a warning


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


def _owned(files: Dict[str, Union[str, bytes]]) -> Set[str]:
    """Paths (relative, no leading /) an OS package installed: dpkg's file lists, apk's folders."""
    out: Set[str] = set()
    for path, text in files.items():
        if path.startswith(DPKG_INFO) and path.endswith(".list") and isinstance(text, str):
            out.update(line.strip().lstrip("/") for line in text.splitlines() if line.strip())
    apk = files.get(APK_INSTALLED)
    if isinstance(apk, str):
        folder = ""
        for line in apk.splitlines():
            if line.startswith("F:"):
                folder = line[2:].strip()
                out.add(folder)
            elif line.startswith("R:") and folder:
                out.add(f"{folder}/{line[2:].strip()}")
    return out


def _headers(text: str) -> Dict[str, str]:
    out: Dict[str, str] = {}
    for line in text.splitlines():
        if not line.strip():
            break                                       # the body (description) follows
        if ":" in line and line[0] not in " \t":
            k, v = line.split(":", 1)
            out.setdefault(k.strip().lower(), v.strip())
    return out


def _pom_properties(text: str) -> Dict[str, str]:
    out = {}
    for line in text.splitlines():
        if "=" in line and not line.lstrip().startswith("#"):
            k, v = line.split("=", 1)
            out[k.strip()] = v.strip()
    return out


def _jar_coordinates(data: bytes, depth: int = 0) -> Tuple[List[Tuple[str, str, str]], int]:
    """Maven coordinates in a jar and the jars inside it, and how many jars had none."""
    coords: List[Tuple[str, str, str]] = []
    unnamed = 0
    try:
        z = zipfile.ZipFile(io.BytesIO(data))
    except (zipfile.BadZipFile, OSError, ValueError):
        return [], 0
    with z:
        found = False
        for name in z.namelist():
            if re.fullmatch(r"META-INF/maven/[^/]+/[^/]+/pom\.properties", name):
                p = _pom_properties(z.read(name).decode("utf-8", "replace"))
                if p.get("groupId") and p.get("artifactId") and p.get("version"):
                    coords.append((p["groupId"], p["artifactId"], p["version"]))
                    found = True
            elif name.endswith(".jar") and depth < 2:
                inner, n = _jar_coordinates(z.read(name), depth + 1)
                coords += inner
                unnamed += n
        if not found:
            unnamed += 1
    return coords, unnamed


def read_language_packages(files: Dict[str, Union[str, bytes]], origin: str,
                           owned: Optional[Set[str]] = None) -> Tuple[List[DependencyFile], List[str]]:
    """PyPI, npm and Maven packages installed in an image, one DependencyFile per place
    (a site-packages directory, the outermost node_modules, a jar), skipping what an OS package
    owns."""
    owned = _owned(files) if owned is None else owned
    groups: Dict[Tuple[str, str], DependencyFile] = {}
    warnings: List[str] = []
    skipped = 0

    def group(eco: str, where: str) -> DependencyFile:
        key = (eco, where)
        if key not in groups:
            groups[key] = DependencyFile(f"{origin}:/{where}", eco, "image")
        return groups[key]

    for path in sorted(files):
        text = files[path]
        m = _PY_META.search(path)
        if m and isinstance(text, str):
            meta_dir = path if path.endswith(".egg-info") else path.rsplit("/", 1)[0]
            if meta_dir in owned:
                skipped += 1
                continue
            h = _headers(text)
            if h.get("name") and h.get("version"):
                group(PYPI, meta_dir.rsplit("/", 1)[0]).add(Package(PYPI, h["name"], h["version"]))
            continue
        m = _NPM_JSON.search(path)
        if m and isinstance(text, str):
            pkg_dir = path.rsplit("/", 1)[0]
            if pkg_dir in owned or path in owned:
                skipped += 1
                continue
            try:
                doc = json.loads(text)
            except ValueError:
                continue
            # a package.json whose name is its directory's (a fixture inside a package is not installed)
            if isinstance(doc, dict) and doc.get("name") == m.group(1) and isinstance(doc.get("version"), str):
                top = path[:path.index("node_modules/") + len("node_modules")]
                group(NPM, top).add(Package(NPM, doc["name"], doc["version"]))
            continue
        if path.endswith(".jar") and isinstance(text, bytes):
            if path in owned:
                skipped += 1
                continue
            coords, unnamed = _jar_coordinates(text)
            for g, a, v in coords:
                group(MAVEN, path).add(Package(MAVEN, f"{g}:{a}", v))
            if unnamed:
                warnings.append(f"{origin}:/{path}: {unnamed} jar(s) without Maven coordinates (pom.properties); "
                                "not identified")
    if skipped:
        warnings.append(f"{origin}: {skipped} language package(s) installed by the OS package manager are "
                        "covered by the distribution's advisories")
    return [groups[k] for k in sorted(groups)], warnings


def _language_file(path: str) -> bool:
    return bool(_PY_META.search(path) or _NPM_JSON.search(path) or path.endswith(".jar")
                or (path.startswith(DPKG_INFO) and path.endswith(".list")))


def read_files(files: Dict[str, Union[str, bytes]], origin: str) -> Tuple[List[DependencyFile], List[str]]:
    """From {path in the image: text, or bytes for a jar}: the installed packages, and warnings."""
    lang, lang_warnings = read_language_packages(files, origin)
    os_files, os_warnings = _read_os(files, origin)
    if lang and os_warnings and not os_files:
        # an image with no distribution (scratch, distroless-static) can still hold language packages
        os_warnings = [w for w in os_warnings if "no /etc/os-release" not in w]
    return os_files + lang, os_warnings + lang_warnings


def _read_os(files: Dict[str, Union[str, bytes]], origin: str) -> Tuple[List[DependencyFile], List[str]]:
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
    return (path in OS_RELEASE or path in (DPKG_STATUS, APK_INSTALLED) or path.startswith(DPKG_STATUS_D)
            or _language_file(path))


_SKIP_ROOT = {"proc", "sys", "dev"}


def read_rootfs(root: Path) -> Tuple[List[DependencyFile], List[str]]:
    root = Path(root)
    files: Dict[str, Union[str, bytes]] = {}
    for rel in OS_RELEASE + (DPKG_STATUS, APK_INSTALLED):
        p = root / rel
        if p.is_file():
            files[rel] = p.read_text(encoding="utf-8", errors="replace")
    sd = root / DPKG_STATUS_D
    if sd.is_dir():
        for p in sorted(sd.iterdir()):
            if p.is_file():
                files[f"{DPKG_STATUS_D}{p.name}"] = p.read_text(encoding="utf-8", errors="replace")
    warnings: List[str] = []
    for dirpath, dirnames, filenames in os.walk(root):       # symlinks are not followed
        rel_dir = os.path.relpath(dirpath, root)
        rel_dir = "" if rel_dir == "." else rel_dir.replace(os.sep, "/")
        if not rel_dir:
            dirnames[:] = [d for d in dirnames if d not in _SKIP_ROOT]
        for name in filenames + [d for d in dirnames if d.endswith(".egg-info")]:
            rel = f"{rel_dir}/{name}" if rel_dir else name
            if rel in files or not _language_file(rel):
                continue
            full = Path(dirpath) / name
            if rel.endswith(".egg-info") and full.is_dir():
                full, rel = full / "PKG-INFO", rel + "/PKG-INFO"
            if not full.is_file() or full.is_symlink():
                continue
            if rel.endswith(".jar"):
                if full.stat().st_size > MAX_JAR:
                    warnings.append(f"{root}:/{rel}: larger than {MAX_JAR >> 20} MB, not read")
                    continue
                files[rel] = full.read_bytes()
            else:
                files[rel] = full.read_text(encoding="utf-8", errors="replace")
    out, more = read_files(files, str(root))
    return out, warnings + more


def _norm(name: str) -> str:
    return name.lstrip("./")


def read_image_tar(tar_path: Path, origin: Optional[str] = None) -> Tuple[List[DependencyFile], List[str]]:
    """A `docker save` tarball: apply the layers in order, keeping only the files needed."""
    origin = origin or Path(tar_path).name
    files: Dict[str, Union[str, bytes]] = {}
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
                        if name.endswith(".jar") and m.size > MAX_JAR:
                            continue
                        f = layer.extractfile(m)
                        if f is not None:
                            data = f.read()
                            files[name] = data if name.endswith(".jar") else data.decode("utf-8", "replace")
    return read_files(files, origin)


def read_image(ref: str) -> Tuple[List[DependencyFile], List[str]]:
    """An image by reference: `docker save` (runs Docker; the image must be present or pullable)."""
    p = Path(ref)
    if p.is_file():
        return read_image_tar(p, ref)
    if shutil.which("docker") is None:
        raise ContainerError(f"{ref}: reading an image needs docker on PATH (or pass a `docker save` .tar)")
    present = subprocess.run(["docker", "image", "inspect", ref], capture_output=True, text=True, timeout=120)
    if present.returncode != 0:                           # `docker save` does not pull
        pulled = subprocess.run(["docker", "pull", ref], capture_output=True, text=True, timeout=1200)
        if pulled.returncode != 0:
            raise ContainerError(f"{ref}: docker pull failed: {(pulled.stderr or pulled.stdout).strip()[-300:]}")
    with tempfile.TemporaryDirectory() as tmp:
        out = Path(tmp) / "image.tar"
        proc = subprocess.run(["docker", "save", "-o", str(out), ref], capture_output=True, text=True, timeout=1200)
        if proc.returncode != 0:
            raise ContainerError(f"{ref}: docker save failed: {(proc.stderr or proc.stdout).strip()[-300:]}")
        return read_image_tar(out, ref)
