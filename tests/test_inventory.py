"""`frame inventory`: languages, frameworks, dependencies, IaC, containers and AI usage."""

import json

from frame.cli import main as frame_main
from frame.sil.inventory import build_inventory


def write(root, files):
    for rel, text in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text)


TREE = {
    "app/web.py": "from flask import Flask, request\nimport openai\napp = Flask(__name__)\n",
    "app/tools.py": "from mcp.server.fastmcp import FastMCP\nmcp = FastMCP('t')\n",
    "bin/deploy": "#!/usr/bin/env python3\nprint('x')\n",
    "web/index.js": "const express = require('express');\nconst app = express();\n",
    "requirements.txt": "flask==3.0.0\n",
    "web/package.json": "{\"dependencies\": {\"express\": \"^4\"}}\n",
    "web/package-lock.json": "{}\n",
    "infra/main.tf": "resource \"aws_s3_bucket\" \"b\" {}\n",
    "k8s/deploy.yaml": "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: web\n",
    "Dockerfile": "FROM python:3.12\n",
    "README.md": "docs\n",
    "node_modules/x/index.js": "require('express')\n",
}


def test_inventory_finds_each_kind_of_content(tmp_path):
    write(tmp_path, TREE)
    inv = build_inventory(tmp_path)
    assert inv.languages == {"javascript": 1, "python": 3}             # node_modules is excluded
    assert inv.frameworks == {"python/flask-extensions": 1, "python/llm-sdks": 1,   # packs whose detect matched
                              "python/mcp-servers": 1}
    assert {(m["path"], m["ecosystem"], m["kind"]) for m in inv.manifests} == {
        ("requirements.txt", "PyPI", "manifest"), ("web/package.json", "npm", "manifest"),
        ("web/package-lock.json", "npm", "lockfile")}
    assert all(m["read"] for m in inv.manifests)
    assert inv.ecosystems == ["PyPI", "npm"]
    assert {(m["path"], m["kind"]) for m in inv.iac} == {("infra/main.tf", "terraform"),
                                                         ("k8s/deploy.yaml", "kubernetes")}
    assert [m["path"] for m in inv.containers] == ["Dockerfile"]
    assert inv.llm_sdks == {"openai": ["app/web.py"]}
    assert inv.mcp_servers == ["app/tools.py"]


def test_inventory_without_reading_sources(tmp_path):
    write(tmp_path, TREE)
    inv = build_inventory(tmp_path, read_sources=False)
    assert inv.languages["python"] == 3 and not inv.frameworks and not inv.llm_sdks


def test_inventory_cli_json(tmp_path, capsys):
    write(tmp_path, TREE)
    assert frame_main(["inventory", str(tmp_path), "-f", "json"]) == 0
    doc = json.loads(capsys.readouterr().out)
    assert doc["ecosystems"] == ["PyPI", "npm"] and doc["ai"]["mcp_servers"] == ["app/tools.py"]


def test_the_dependency_files_are_the_ones_frame_deps_reads(tmp_path):
    """One catalog: every file `frame deps` reads is listed with `read`, under OSV's ecosystem name
    (`Package.resolved`, `mix.lock`, `pubspec.lock` and `conanfile.py` included); a declaration it
    does not read on its own (`setup.py`, `go.sum`) is listed with `read: false`."""
    from frame.sca.discover import read_dependencies
    files = {"swift/Package.resolved": '{"pins": [], "version": 2}\n', "ex/mix.lock": "%{}\n",
             "dart/pubspec.lock": "packages: {}\n", "cpp/conanfile.py": "requires = []\n",
             "py/setup.py": "from setuptools import setup\nsetup()\n", "go/go.mod": "module x\n\ngo 1.21\n",
             "go/go.sum": "", "dotnet/obj/project.assets.json": "{}\n", "dotnet/project.assets.json": "{}\n"}
    write(tmp_path, files)
    got = {m["path"]: (m["ecosystem"], m["kind"], m["read"]) for m in build_inventory(tmp_path, read_sources=False).manifests}
    assert got == {"swift/Package.resolved": ("SwiftURL", "lockfile", True), "ex/mix.lock": ("Hex", "lockfile", True),
                   "dart/pubspec.lock": ("Pub", "lockfile", True), "cpp/conanfile.py": ("ConanCenter", "manifest", True),
                   "py/setup.py": ("PyPI", "manifest", False), "go/go.mod": ("Go", "lockfile", True),
                   "go/go.sum": ("Go", "lockfile", False),
                   "dotnet/obj/project.assets.json": ("NuGet", "lockfile", True)}
    read = {f["path"] for f in read_dependencies(tmp_path).to_dict().get("files", [])}
    assert read <= {p for p, (_, _, r) in got.items() if r}


def test_the_inventory_catalog_is_strict(tmp_path):
    import pytest
    from frame.sil.specs import inventory_catalog
    text = inventory_catalog.PATH.read_text()
    bad = tmp_path / "inventory.toml"
    bad.write_text(text.replace('kind = "lockfile"', 'kind = "binary"', 1))
    with pytest.raises(ValueError, match="dependency_file"):
        inventory_catalog.load(bad)
