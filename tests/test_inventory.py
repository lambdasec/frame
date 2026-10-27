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
    assert inv.frameworks == {"python/flask-extensions": 1}             # packs whose detect matched
    assert {(m["path"], m["ecosystem"], m["kind"]) for m in inv.manifests} == {
        ("requirements.txt", "pypi", "manifest"), ("web/package.json", "npm", "manifest"),
        ("web/package-lock.json", "npm", "lockfile")}
    assert inv.ecosystems == ["npm", "pypi"]
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
    assert doc["ecosystems"] == ["npm", "pypi"] and doc["ai"]["mcp_servers"] == ["app/tools.py"]
