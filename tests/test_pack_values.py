"""Pack rules match values, never variable names: what a value is comes from evidence in the code
(an import, a declared type, a framework's documented global, the registration a callback is
passed to), and a variable that merely shares a library's conventional name is not that value."""

import json

import pytest

from frame.sil.packs.schema import PackError, parse_pack
from frame.sil.scanner import FrameScanner


def _cwes(code, lang="javascript", name="a.js"):
    return {v.cwe_id for v in FrameScanner(language=lang, verify=False).scan(code, name).vulnerabilities}


@pytest.mark.parametrize("event, flagged", [("message", True), ("resize", False)])
def test_window_message_listeners_receive_attacker_data(event, flagged):
    code = ("window.addEventListener('" + event + "', function (e) {\n"
            "  document.getElementById('p').innerHTML = e.data;\n});\n")
    assert ("CWE-79" in _cwes(code)) == flagged


def test_a_worker_message_comes_from_its_own_page():
    assert "CWE-79" not in _cwes("self.addEventListener('message', (e) => { document.body.innerHTML = e.data; });\n")


def test_a_variable_assigned_in_a_callback_is_the_enclosing_one():
    code = ("const { app, BrowserWindow, ipcMain } = require('electron');\nlet win;\n"
            "app.whenReady().then(() => { win = new BrowserWindow({}); });\n"
            "ipcMain.on('go', (event, url) => { win.loadURL(url); });\n")
    assert "CWE-601" in _cwes(code)
    shadowed = code.replace("{ win = new BrowserWindow({}); }", "{ let win = new BrowserWindow({}); }")
    assert "CWE-601" not in _cwes(shadowed)                     # its own `win`: the outer one stays null


def test_an_arrow_shares_its_methods_this_a_function_does_not():
    code = ("import { Component } from '@angular/core';\nimport { DomSanitizer } from '@angular/platform-browser';\n"
            "import { ActivatedRoute } from '@angular/router';\n@Component({ selector: 'x', template: '' })\n"
            "export class C {\n  html: any;\n  constructor(private route: ActivatedRoute, private sanitizer: DomSanitizer) {}\n"
            "  ngOnInit() {\n    this.route.queryParams.subscribe({cb});\n  }\n}\n")
    arrow = code.replace("{cb}", "(p) => { this.html = this.sanitizer.bypassSecurityTrustHtml(p.msg); }")
    assert "CWE-79" in _cwes(arrow, "typescript", "c.ts")
    plain = code.replace("{cb}", "function (p) { this.html = this.sanitizer.bypassSecurityTrustHtml(p.msg); }")
    assert "CWE-79" not in _cwes(plain, "typescript", "c.ts")    # `this` is not the component there


def test_a_route_read_inside_an_expression_is_the_request_types():
    code = ("import { Component } from '@angular/core';\nimport { DomSanitizer } from '@angular/platform-browser';\n"
            "import { ActivatedRoute } from '@angular/router';\n@Component({ selector: 'x', template: '' })\n"
            "export class C {\n  html: any;\n  constructor(private route: ActivatedRoute, private sanitizer: DomSanitizer) {}\n"
            "  ngOnInit() {\n    const v = this.route.snapshot.queryParamMap.get('bio') || '';\n"
            "    this.html = this.sanitizer.bypassSecurityTrustHtml(v);\n  }\n}\n")
    assert "CWE-79" in _cwes(code, "typescript", "c.ts")
    data = code.replace("this.route.snapshot.queryParamMap.get('bio')", "this.route.snapshot.data['bio']")
    assert "CWE-79" not in _cwes(data, "typescript", "c.ts")      # route data is the application's


def test_a_framework_global_is_a_value(tmp_path):
    (tmp_path / "package.json").write_text(json.dumps({"dependencies": {"sails": "1.5.0"}}))
    ctl = tmp_path / "api" / "controllers"
    ctl.mkdir(parents=True)
    (ctl / "P.js").write_text(
        "module.exports = {\n  find: async function (req, res) {\n"
        "    await sails.getDatastore('pg').sendNativeQuery('SELECT ' + req.param('q'));\n"
        "    const db = { sendNativeQuery() {} };\n    db.sendNativeQuery(req.param('q'));\n"
        "    return res.ok();\n  }\n};\n")
    results = FrameScanner(verify=False).scan_directory(str(tmp_path), None)
    assert sorted(v.line for r in results for v in r.vulnerabilities if v.cwe_id == "CWE-89") == [3]


def test_pack_globals_are_javascript_and_named():
    with pytest.raises(PackError, match="globals"):
        parse_pack({"pack": {"name": "x", "language": "python", "globals": {"app": "x"}}}, "t.toml")
    with pytest.raises(PackError, match="globals"):
        parse_pack({"pack": {"name": "x", "language": "javascript", "globals": {"not a name": "x"}}}, "t.toml")


@pytest.mark.parametrize("code, flagged", [
    ("const Redis = require('ioredis');\nconst r = new Redis();\n", True),
    ("const cache = makeCache();\n", False),                    # a `.eval` method of something else
])
def test_redis_eval_on_a_client(code, flagged):
    src = (code + "require('express')().post('/k', async (req, res) => {\n"
           "  await " + ("r" if flagged else "cache") + ".eval(\"return '\" + req.body.k + \"'\", 0);\n  res.send('ok');\n});\n")
    assert ("CWE-94" in _cwes(src)) == flagged
