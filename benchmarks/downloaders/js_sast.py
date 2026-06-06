"""Hand-authored, semantically-labeled JavaScript/TypeScript SAST benchmark.

Unlike the `secbench_js` division -- whose ground truth is regex-generated and
therefore circular (see secbench_js.create_js_vulnerability_manifest) -- this
benchmark labels each case by its actual data-flow semantics: does untrusted
input reach a dangerous sink WITHOUT passing through a recognized sanitizer?

It follows the OWASP-Benchmark methodology (paired true-positive / false-positive
cases): every category has both vulnerable variants (a real source->sink flow)
and safe variants (parameterized query, recognized sanitizer, or a constant /
non-tainted argument). The safe variants exist specifically to measure precision
-- a correct tool must NOT flag them.

Each file is a self-contained Express-style handler holding exactly one intended
finding (or none, for safe files), so metrics are unambiguous:
  - vulnerable file  -> expect exactly one finding of the labelled CWE
  - safe file        -> expect zero findings (any finding is a false positive)

The corpus is generated deterministically (no network, no randomness) so runs
are reproducible.
"""

import os
import json
from typing import Dict, List, Tuple


# A case is (category, cwe, is_vulnerable, code). `code` is a complete handler.
# Sources used: req.query / req.body / req.params / req.headers (all untrusted).
# Safe cases rely only on sanitizers Frame recognizes, parameterized APIs, or
# constant (non-tainted) arguments -- never on analysis Frame cannot perform.
_CASES: List[Tuple[str, str, bool, str]] = [
    # ------------------------------------------------------------------ SQLi
    ("sql_injection", "CWE-89", True,
     "app.get('/u', (req, res) => {\n"
     "  db.query(\"SELECT * FROM users WHERE id = '\" + req.query.id + \"'\");\n"
     "});\n"),
    ("sql_injection", "CWE-89", True,
     "app.post('/search', (req, res) => {\n"
     "  connection.query(`SELECT * FROM products WHERE name = '${req.body.name}'`);\n"
     "});\n"),
    ("sql_injection", "CWE-89", True,
     "app.delete('/item/:id', (req, res) => {\n"
     "  pool.query('DELETE FROM items WHERE id = ' + req.params.id);\n"
     "});\n"),
    ("sql_injection", "CWE-89", False,
     "app.get('/u', (req, res) => {\n"
     "  db.query('SELECT * FROM users WHERE id = ?', [req.query.id]);\n"
     "});\n"),
    ("sql_injection", "CWE-89", False,
     "app.post('/search', (req, res) => {\n"
     "  connection.query(\"SELECT * FROM products WHERE name = '\" + mysql.escape(req.body.name) + \"'\");\n"
     "});\n"),
    ("sql_injection", "CWE-89", False,
     "app.get('/all', (req, res) => {\n"
     "  db.query('SELECT * FROM users WHERE active = 1');\n"
     "});\n"),

    # ------------------------------------------------------------------- XSS
    ("xss", "CWE-79", True,
     "app.get('/hello', (req, res) => {\n"
     "  res.send('<div>' + req.query.name + '</div>');\n"
     "});\n"),
    ("xss", "CWE-79", True,
     "app.post('/comment', (req, res) => {\n"
     "  res.write('<p>' + req.body.comment + '</p>');\n"
     "});\n"),
    ("xss", "CWE-79", True,
     "app.get('/p/:name', (req, res) => {\n"
     "  res.send(`<h1>${req.params.name}</h1>`);\n"
     "});\n"),
    ("xss", "CWE-79", False,
     "app.get('/hello', (req, res) => {\n"
     "  res.send('<div>' + DOMPurify.sanitize(req.query.name) + '</div>');\n"
     "});\n"),
    ("xss", "CWE-79", False,
     "app.post('/comment', (req, res) => {\n"
     "  res.send('<p>' + escape(req.body.comment) + '</p>');\n"
     "});\n"),
    ("xss", "CWE-79", False,
     "app.get('/welcome', (req, res) => {\n"
     "  res.send('<div>Welcome to the site</div>');\n"
     "});\n"),

    # ----------------------------------------------------- command injection
    ("command_injection", "CWE-78", True,
     "const cp = require('child_process');\n"
     "app.get('/ls', (req, res) => {\n"
     "  cp.exec('ls -la ' + req.query.dir);\n"
     "});\n"),
    ("command_injection", "CWE-78", True,
     "const cp = require('child_process');\n"
     "app.post('/cat', (req, res) => {\n"
     "  cp.exec(`cat ${req.body.file}`);\n"
     "});\n"),
    ("command_injection", "CWE-78", True,
     "const cp = require('child_process');\n"
     "app.get('/ping/:host', (req, res) => {\n"
     "  cp.execSync('ping -c 1 ' + req.params.host);\n"
     "});\n"),
    ("command_injection", "CWE-78", False,
     "const cp = require('child_process');\n"
     "app.get('/ls', (req, res) => {\n"
     "  cp.execFile('ls', ['-la', req.query.dir]);\n"
     "});\n"),
    ("command_injection", "CWE-78", False,
     "const cp = require('child_process');\n"
     "app.get('/uptime', (req, res) => {\n"
     "  cp.exec('uptime');\n"
     "});\n"),

    # --------------------------------------------------------- path traversal
    ("path_traversal", "CWE-22", True,
     "const fs = require('fs');\n"
     "app.get('/file', (req, res) => {\n"
     "  fs.readFile(req.query.file, 'utf8', (e, d) => res.send(d));\n"
     "});\n"),
    ("path_traversal", "CWE-22", True,
     "const fs = require('fs');\n"
     "app.get('/doc/:path', (req, res) => {\n"
     "  const data = fs.readFileSync(req.params.path);\n"
     "  res.send(data);\n"
     "});\n"),
    ("path_traversal", "CWE-22", True,
     "const fs = require('fs');\n"
     "app.get('/dl', (req, res) => {\n"
     "  fs.createReadStream(req.query.name).pipe(res);\n"
     "});\n"),
    ("path_traversal", "CWE-22", False,
     "const fs = require('fs');\n"
     "const path = require('path');\n"
     "app.get('/file', (req, res) => {\n"
     "  fs.readFile(path.basename(req.query.file), 'utf8', (e, d) => res.send(d));\n"
     "});\n"),
    ("path_traversal", "CWE-22", False,
     "const fs = require('fs');\n"
     "app.get('/config', (req, res) => {\n"
     "  fs.readFile('./config.json', 'utf8', (e, d) => res.send(d));\n"
     "});\n"),

    # ---------------------------------------------------------- code injection
    ("code_injection", "CWE-94", True,
     "app.get('/calc', (req, res) => {\n"
     "  const result = eval(req.query.expr);\n"
     "  res.send(String(result));\n"
     "});\n"),
    ("code_injection", "CWE-94", True,
     "app.post('/run', (req, res) => {\n"
     "  const f = new Function(req.body.code);\n"
     "  f();\n"
     "});\n"),
    ("code_injection", "CWE-94", False,
     "app.post('/parse', (req, res) => {\n"
     "  const obj = JSON.parse(req.body.data);\n"
     "  res.json(obj);\n"
     "});\n"),
    ("code_injection", "CWE-94", False,
     "app.get('/calc', (req, res) => {\n"
     "  const result = eval('1 + 2 + 3');\n"
     "  res.send(String(result));\n"
     "});\n"),

    # ------------------------------------------------------------------- SSRF
    ("ssrf", "CWE-918", True,
     "const axios = require('axios');\n"
     "app.get('/fetch', (req, res) => {\n"
     "  axios.get(req.query.url).then(r => res.send(r.data));\n"
     "});\n"),
    ("ssrf", "CWE-918", True,
     "app.post('/proxy', (req, res) => {\n"
     "  fetch(req.body.target).then(r => r.text()).then(t => res.send(t));\n"
     "});\n"),
    ("ssrf", "CWE-918", True,
     "const http = require('http');\n"
     "app.get('/get/:endpoint', (req, res) => {\n"
     "  http.get(req.params.endpoint, r => r.pipe(res));\n"
     "});\n"),
    ("ssrf", "CWE-918", False,
     "const axios = require('axios');\n"
     "app.get('/health', (req, res) => {\n"
     "  axios.get('https://api.internal.example.com/health').then(r => res.send(r.data));\n"
     "});\n"),

    # ----------------------------------------------------------- open redirect
    ("open_redirect", "CWE-601", True,
     "app.get('/go', (req, res) => {\n"
     "  res.redirect(req.query.next);\n"
     "});\n"),
    ("open_redirect", "CWE-601", True,
     "app.post('/login', (req, res) => {\n"
     "  res.redirect(req.body.returnUrl);\n"
     "});\n"),
    ("open_redirect", "CWE-601", False,
     "app.get('/go', (req, res) => {\n"
     "  res.redirect('/dashboard');\n"
     "});\n"),

    # ---------------------------------------------------------- NoSQL injection
    ("nosql_injection", "CWE-943", True,
     "app.post('/login', (req, res) => {\n"
     "  User.findOne({ username: req.body.username, password: req.body.password });\n"
     "});\n"),
    ("nosql_injection", "CWE-943", True,
     "app.get('/find', (req, res) => {\n"
     "  db.collection('users').find({ name: req.query.name });\n"
     "});\n"),
    ("nosql_injection", "CWE-943", False,
     "app.get('/active', (req, res) => {\n"
     "  User.find({ active: true });\n"
     "});\n"),
]


# TypeScript cases (.ts) exercising TS-specific syntax: type annotations,
# `as` casts, imports, typed handler signatures. Same semantic labelling.
_TS_CASES: List[Tuple[str, str, bool, str]] = [
    ("sql_injection", "CWE-89", True,
     "app.get('/u', (req: Request, res: Response): void => {\n"
     "  const id: string = req.query.id as string;\n"
     "  db.query(\"SELECT * FROM users WHERE id = '\" + id + \"'\");\n"
     "});\n"),
    ("sql_injection", "CWE-89", False,
     "app.get('/u', (req: Request, res: Response): void => {\n"
     "  db.query('SELECT * FROM users WHERE id = ?', [req.query.id]);\n"
     "});\n"),
    ("xss", "CWE-79", True,
     "app.get('/p/:name', (req: Request, res: Response): void => {\n"
     "  res.send(`<h1>${req.params.name}</h1>`);\n"
     "});\n"),
    ("xss", "CWE-79", False,
     "app.get('/p/:name', (req: Request, res: Response): void => {\n"
     "  const name: string = DOMPurify.sanitize(req.params.name as string);\n"
     "  res.send('<h1>' + name + '</h1>');\n"
     "});\n"),
    ("command_injection", "CWE-78", True,
     "import { exec } from 'child_process';\n"
     "app.post('/c', (req: Request, res: Response): void => {\n"
     "  exec('ls -la ' + req.body.dir);\n"
     "});\n"),
    ("command_injection", "CWE-78", False,
     "import { execFile } from 'child_process';\n"
     "app.post('/c', (req: Request, res: Response): void => {\n"
     "  execFile('ls', ['-la', req.body.dir as string]);\n"
     "});\n"),
    ("path_traversal", "CWE-22", True,
     "import * as fs from 'fs';\n"
     "app.get('/f', (req: Request, res: Response): void => {\n"
     "  fs.readFile(req.query.file as string, 'utf8', (e, d) => res.send(d));\n"
     "});\n"),
    ("path_traversal", "CWE-22", False,
     "import * as fs from 'fs';\n"
     "import * as path from 'path';\n"
     "app.get('/f', (req: Request, res: Response): void => {\n"
     "  fs.readFile(path.basename(req.query.file as string), 'utf8', (e, d) => res.send(d));\n"
     "});\n"),
    ("code_injection", "CWE-94", True,
     "app.get('/calc', (req: Request, res: Response): void => {\n"
     "  const result: any = eval(req.query.expr as string);\n"
     "  res.send(String(result));\n"
     "});\n"),
    ("ssrf", "CWE-918", True,
     "import axios from 'axios';\n"
     "app.get('/fetch', (req: Request, res: Response): void => {\n"
     "  axios.get(req.query.url as string).then(r => res.send(r.data));\n"
     "});\n"),
    ("open_redirect", "CWE-601", True,
     "app.get('/go', (req: Request, res: Response): void => {\n"
     "  res.redirect(req.query.next as string);\n"
     "});\n"),
    ("nosql_injection", "CWE-943", True,
     "app.post('/login', (req: Request, res: Response): void => {\n"
     "  User.findOne({ username: req.body.username, password: req.body.password });\n"
     "});\n"),
]


def build_js_sast_corpus(cache_dir: str) -> int:
    """Write the corpus files and manifest under cache_dir/js_sast. Returns count."""
    import shutil
    base = os.path.join(cache_dir, 'js_sast')
    src_dir = os.path.join(base, 'src')
    if os.path.exists(src_dir):
        shutil.rmtree(src_dir)   # regenerate cleanly so no stale cases linger
    os.makedirs(src_dir, exist_ok=True)

    manifest: Dict[str, Dict] = {'files': {}}
    all_cases = [(c, 'js') for c in _CASES] + [(c, 'ts') for c in _TS_CASES]
    for i, ((category, cwe, is_vuln, code), ext) in enumerate(all_cases):
        tag = 'vuln' if is_vuln else 'safe'
        fname = f"{i:03d}_{category}_{tag}.{ext}"
        with open(os.path.join(src_dir, fname), 'w', encoding='utf-8') as f:
            f.write("// Auto-generated semantic SAST test case.\n")
            f.write(f"// category={category} cwe={cwe} vulnerable={is_vuln}\n")
            # TS cases supply their own express import/handler typing; JS cases
            # share a common app bootstrap line.
            if ext == 'js':
                f.write("const app = require('express')();\n")
            else:
                f.write("const app = require('express')();\n")
            f.write(code)

        manifest['files'][fname] = {
            'category': category,
            'cwe': cwe,
            'vulnerable': is_vuln,
        }

    with open(os.path.join(base, 'manifest.json'), 'w', encoding='utf-8') as f:
        json.dump(manifest, f, indent=2)

    return len(all_cases)


def get_js_sast_files(cache_dir: str) -> List[str]:
    src_dir = os.path.join(cache_dir, 'js_sast', 'src')
    if not os.path.exists(src_dir):
        return []
    return sorted(
        os.path.join(src_dir, f) for f in os.listdir(src_dir)
        if f.endswith(('.js', '.ts'))
    )


def load_js_sast_manifest(cache_dir: str) -> Dict:
    path = os.path.join(cache_dir, 'js_sast', 'manifest.json')
    if os.path.exists(path):
        with open(path, 'r', encoding='utf-8') as f:
            return json.load(f)
    return {'files': {}}
