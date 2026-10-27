"""Workspace inventory: what a repository contains, before anything is analysed.

One pass over the tree reports the source languages, the frameworks Frame has packs for,
dependency manifests and lockfiles, infrastructure-as-code, container definitions, LLM SDKs
and MCP servers. It decides nothing about vulnerabilities; later stages (SCA, IaC checks,
knowledge-base downloads) read it to know what applies.

Source files are translated without running any analysis, so framework detection is the
same `[pack].detect` logic a scan uses (`Program.packs_applied`), and the AI checks read
the import table each frontend already builds.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Set, Tuple, Union

from frame.sil.scanner import DEFAULT_EXCLUDED_SCAN_DIRS, FrameScanner, language_for_file

# Manifest / lockfile name -> (ecosystem, kind). Lockfiles pin exact versions; manifests
# declare ranges.
MANIFESTS: Dict[str, Tuple[str, str]] = {
    "requirements.txt": ("pypi", "manifest"), "pyproject.toml": ("pypi", "manifest"),
    "setup.py": ("pypi", "manifest"), "setup.cfg": ("pypi", "manifest"), "Pipfile": ("pypi", "manifest"),
    "Pipfile.lock": ("pypi", "lockfile"), "poetry.lock": ("pypi", "lockfile"), "uv.lock": ("pypi", "lockfile"),
    "pdm.lock": ("pypi", "lockfile"),
    "package.json": ("npm", "manifest"), "package-lock.json": ("npm", "lockfile"),
    "npm-shrinkwrap.json": ("npm", "lockfile"), "yarn.lock": ("npm", "lockfile"),
    "pnpm-lock.yaml": ("npm", "lockfile"), "bun.lockb": ("npm", "lockfile"),
    "pom.xml": ("maven", "manifest"), "build.gradle": ("maven", "manifest"),
    "build.gradle.kts": ("maven", "manifest"), "gradle.lockfile": ("maven", "lockfile"),
    "packages.lock.json": ("nuget", "lockfile"), "packages.config": ("nuget", "manifest"),
    "Directory.Packages.props": ("nuget", "manifest"),
    "go.mod": ("go", "manifest"), "go.sum": ("go", "lockfile"),
    "Cargo.toml": ("crates.io", "manifest"), "Cargo.lock": ("crates.io", "lockfile"),
    "Gemfile": ("rubygems", "manifest"), "Gemfile.lock": ("rubygems", "lockfile"),
    "composer.json": ("packagist", "manifest"), "composer.lock": ("packagist", "lockfile"),
    "conanfile.txt": ("conan", "manifest"), "vcpkg.json": ("vcpkg", "manifest"),
}
_REQUIREMENTS = re.compile(r"requirements[-_.\w]*\.txt$")

# Imported modules (canonical prefixes) -> what they say about AI in the code.
LLM_SDKS = ("openai", "anthropic", "@anthropic-ai/sdk", "langchain", "@langchain", "langchain_core",
            "langchain_community", "llama_index", "llamaindex", "google.generativeai", "google.genai",
            "@google/generative-ai", "@google/genai", "mistralai", "@mistralai", "cohere", "groq",
            "litellm", "ollama", "transformers", "dev.langchain4j", "com.openai", "com.anthropic",
            "OpenAI", "Anthropic", "Microsoft.SemanticKernel", "Azure.AI.OpenAI")
MCP_SERVER_SDKS = ("mcp.server", "mcp", "fastmcp", "@modelcontextprotocol/sdk/server",
                   "@modelcontextprotocol/sdk", "ModelContextProtocol",
                   "io.modelcontextprotocol")


@dataclass
class Inventory:
    root: str
    languages: Dict[str, int] = field(default_factory=dict)          # language -> source files
    frameworks: Dict[str, int] = field(default_factory=dict)         # "language/pack" -> files
    manifests: List[Dict[str, str]] = field(default_factory=list)    # {path, ecosystem, kind}
    iac: List[Dict[str, str]] = field(default_factory=list)          # {path, kind}
    containers: List[Dict[str, str]] = field(default_factory=list)   # {path, kind}
    llm_sdks: Dict[str, List[str]] = field(default_factory=dict)     # sdk -> files
    mcp_servers: List[str] = field(default_factory=list)             # files
    truncated: bool = False                                          # frameworks/AI read a prefix only

    @property
    def ecosystems(self) -> List[str]:
        return sorted({m["ecosystem"] for m in self.manifests})

    def to_dict(self) -> dict:
        return {"root": self.root, "languages": self.languages, "frameworks": self.frameworks,
                "ecosystems": self.ecosystems, "manifests": self.manifests, "iac": self.iac,
                "containers": self.containers,
                "ai": {"llm_sdks": self.llm_sdks, "mcp_servers": self.mcp_servers},
                "truncated": self.truncated}


def _excluded(path: Path, root: Path, excluded: Iterable) -> bool:
    return FrameScanner._is_excluded_dir_member(path, root, frozenset(excluded))


def _iac_kind(path: Path) -> Optional[str]:
    """terraform / helm / kubernetes / cloudformation / compose, from the file's name and,
    for YAML/JSON, the keys every such document carries."""
    name, suffix = path.name, path.suffix.lower()
    if suffix == ".tf" or name.endswith(".tf.json"):
        return "terraform"
    if name == "Chart.yaml":
        return "helm"
    if name in ("docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml") \
            or re.fullmatch(r"docker-compose[.-][\w.-]+\.ya?ml", name):
        return "compose"
    if suffix not in (".yaml", ".yml", ".json", ".template"):
        return None
    try:
        head = path.read_text(encoding="utf-8", errors="replace")[:20000]
    except OSError:
        return None
    if "AWSTemplateFormatVersion" in head or re.search(r'["\']?Type["\']?\s*:\s*["\']?AWS::', head):
        return "cloudformation"
    if suffix in (".yaml", ".yml") and re.search(r"(?m)^apiVersion:\s*\S", head) \
            and re.search(r"(?m)^kind:\s*\S", head):
        return "kubernetes"
    return None


def _container_kind(path: Path) -> Optional[str]:
    name = path.name
    if name in ("Dockerfile", "Containerfile") or name.endswith((".Dockerfile", ".dockerfile")) \
            or re.fullmatch(r"(Dockerfile|Containerfile)\.[\w.-]+", name):
        return "dockerfile"
    return None


def _prefix_hit(module: str, prefixes: Iterable[str]) -> Optional[str]:
    for p in prefixes:
        if module == p or module.startswith(p + ".") or module.startswith(p + "/"):
            return p
    return None


def build_inventory(root: Union[str, Path], exclude_dirs: Optional[Iterable] = None,
                    read_sources: bool = True, file_limit: int = 5000) -> Inventory:
    """Inventory of `root`. With `read_sources`, up to `file_limit` source files are
    translated (no analysis) for frameworks and AI imports."""
    base = Path(root).resolve()
    excluded = DEFAULT_EXCLUDED_SCAN_DIRS if exclude_dirs is None else frozenset(exclude_dirs)
    inv = Inventory(root=str(base))
    scanner = FrameScanner(verify=False)
    sources: List[Tuple[Path, str]] = []
    for path in sorted(base.rglob("*")):
        if not path.is_file() or _excluded(path, base, excluded):
            continue
        rel = path.relative_to(base).as_posix()
        name = path.name
        manifest = MANIFESTS.get(name)
        if manifest is None and _REQUIREMENTS.fullmatch(name):
            manifest = ("pypi", "manifest")
        if manifest is None and path.suffix == ".csproj":
            manifest = ("nuget", "manifest")
        if manifest is not None:
            inv.manifests.append({"path": rel, "ecosystem": manifest[0], "kind": manifest[1]})
            continue
        kind = _container_kind(path)
        if kind:
            inv.containers.append({"path": rel, "kind": kind})
            continue
        kind = _iac_kind(path)
        if kind:
            inv.iac.append({"path": rel, "kind": kind})
            continue
        if path.suffix:
            lang = language_for_file(path)
        elif scanner._is_script(path, None):
            lang = language_for_file(path, path.read_text(encoding="utf-8", errors="replace")[:256])
        else:
            lang = None
        if lang:
            inv.languages[lang] = inv.languages.get(lang, 0) + 1
            sources.append((path, rel))

    if read_sources:
        # Only a pack with a `detect` condition says the file uses that framework; the
        # others (language-wide libraries) apply to every file of the language.
        from frame.sil.packs.loader import PackSet
        detecting = {f"{p.language}/{p.name}" for p in PackSet.build(builtin=True).packs if p.has_detect}
        inv.truncated = len(sources) > file_limit
        llm: Dict[str, Set[str]] = {}
        mcp: Set[str] = set()
        for path, rel in sources[:file_limit]:
            try:
                text = path.read_text(encoding="utf-8-sig", errors="replace")
                lang = language_for_file(path, text)
                frontend = scanner._get_frontend(lang)
                program = frontend.translate(text, str(path)) if frontend is not None else None
            except Exception:
                continue
            if program is None:
                continue
            for pack in getattr(program, "packs_applied", []) or []:
                if pack in detecting:
                    inv.frameworks[pack] = inv.frameworks.get(pack, 0) + 1
            modules = {str(v) for v in (getattr(program, "imports", {}) or {}).values()}
            for module in modules:
                sdk = _prefix_hit(module, LLM_SDKS)
                if sdk:
                    llm.setdefault(sdk, set()).add(rel)
                if _prefix_hit(module, MCP_SERVER_SDKS):
                    mcp.add(rel)
        inv.llm_sdks = {k: sorted(v) for k, v in sorted(llm.items())}
        inv.mcp_servers = sorted(mcp)
    inv.languages = dict(sorted(inv.languages.items()))
    inv.frameworks = dict(sorted(inv.frameworks.items()))
    return inv


def _few(items: List[str], n: int = 4) -> str:
    return ", ".join(items[:n]) + (f", +{len(items) - n} more" if len(items) > n else "")


def format_text(inv: Inventory) -> str:
    """A short summary; `-f json` has every path."""
    lines = [f"Inventory of {inv.root}"]
    lines.append("Languages:   " + (", ".join(f"{k} ({v})" for k, v in inv.languages.items()) or "none"))
    lines.append("Frameworks:  " + (", ".join(f"{k} ({v})" for k, v in inv.frameworks.items()) or "none"))
    by_eco: Dict[str, List[str]] = {}
    for m in inv.manifests:
        by_eco.setdefault(m["ecosystem"], []).append(m["path"])
    lines.append("Dependencies: " + ("; ".join(f"{e}: {_few(p)}" for e, p in sorted(by_eco.items())) or "none"))
    by_kind: Dict[str, List[str]] = {}
    for m in inv.iac:
        by_kind.setdefault(m["kind"], []).append(m["path"])
    lines.append("IaC:         " + ("; ".join(f"{k}: {_few(p)}" for k, p in sorted(by_kind.items())) or "none"))
    lines.append("Containers:  " + (_few([m["path"] for m in inv.containers]) or "none"))
    lines.append("LLM SDKs:    " + (", ".join(f"{k} ({len(v)} files)" for k, v in inv.llm_sdks.items()) or "none"))
    lines.append("MCP servers: " + (_few(inv.mcp_servers) or "none"))
    if inv.truncated:
        lines.append("(frameworks and AI imports read from the first files only; raise --file-limit)")
    return "\n".join(lines)


def to_json(inv: Inventory) -> str:
    return json.dumps(inv.to_dict(), indent=2)
