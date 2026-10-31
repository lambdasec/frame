"""Facts read from what calls do, never from names: a `replace` chain that neutralizes every
HTML-significant character escapes (`& < > " '` each replaced by a character reference or
removed, every occurrence: a JS `g` regex or `replaceAll`, Python `str.replace`); a jQuery
collection's selector and traversal methods return its elements, not their argument; a regex
literal's flags are part of what it means (`m` voids the anchors of a guard)."""

import pytest

from frame.sil.scanner import FrameScanner


def _cwes(code, lang="javascript", name="a.js"):
    return {v.cwe_id for v in FrameScanner(language=lang, verify=False).scan(code, name).vulnerabilities}


JS = """const express = require("express");
const app = express();
function escapeHtml(s) {{
  return String(s){chain};
}}
app.get("/g", (req, res) => {{ res.send("<h1>" + escapeHtml(req.query.name) + "</h1>"); }});
"""
FULL = ('.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")'
        '.replace(/"/g, "&quot;").replace(/\'/g, "&#39;")')


@pytest.mark.parametrize("chain, escaped", [
    (FULL, True),
    ('.replace(/[&<>"\']/g, "")', True),                          # removing them: a character class
    ('.replaceAll("&", "&amp;").replaceAll("<", "&lt;").replaceAll(">", "&gt;").replaceAll(\'"\', "&quot;")'
     '.replaceAll("\'", "&#x27;")', True),
    (FULL.replace("/</g", "/</"), False),                         # no `g`: only the first `<`
    (FULL.replace('.replace(/\'/g, "&#39;")', ""), False),        # a quote left
    (FULL.replace('"&lt;"', '"<b>"'), False),                     # replaced by markup
    (FULL.replace("/</g", '"<"'), False),                         # a string pattern: the first one only
])
def test_js_replace_chains_escape_only_when_they_neutralize_every_character(chain, escaped):
    assert ("CWE-79" not in _cwes(JS.format(chain=chain))) == escaped


PY = """from django.http import HttpResponse
from django.urls import path
def esc(s):
    return s{chain}
def h(request):
    return HttpResponse("<p>" + esc(request.GET["n"]) + "</p>")
urlpatterns = [path("x/", h)]
"""
PY_FULL = ('.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace(\'"\', "&quot;")'
           '.replace("\'", "&#x27;")')


@pytest.mark.parametrize("chain, escaped", [
    (PY_FULL, True),
    (PY_FULL.replace('.replace("<", "&lt;")', ""), False),
    (PY_FULL.replace('"&gt;"', '"]"'), False),                    # not a character reference
])
def test_python_str_replace_chains(chain, escaped):
    assert ("CWE-79" not in _cwes(PY.format(chain=chain), "python", "views.py")) == escaped


COLLECTION = """var $this = $(this),
    $links = $this.find("li.tab a"),
    $active;
{body}
function resize() {{ $links = $this.find("li.tab a"); }}
"""


@pytest.mark.parametrize("body, flagged", [
    # a selector matches elements of the document; the hash never becomes markup
    ("$active = $($links.filter('[href=\"' + location.hash + '\"]'));", False),
    ("$links.html(location.hash);", True),                        # a sink on the collection
    ("$($links.add(location.hash));", True),                      # add() parses an HTML string
    ("$(location.hash);", True),
])
def test_jquery_collections_in_variables(body, flagged):
    assert ("CWE-79" in _cwes(COLLECTION.format(body=body))) == flagged


@pytest.mark.parametrize("guard, flagged", [("/^[a-z]+$/.test(n)", False), ("/^[a-z]+$/m.test(n)", True)])
def test_a_multiline_regex_does_not_anchor_a_guard(guard, flagged):
    code = ("const express = require('express'); const app = express();\napp.get('/', (req, res) => {\n"
            "  const n = req.query.n;\n  if (" + guard + ") { require('child_process').exec('ls ' + n); }\n"
            "  res.send('ok');\n});\n")
    assert ("CWE-78" in _cwes(code)) == flagged


def test_aiopg_classes_annotated_from_their_modules():
    code = ("from aiohttp import web\nfrom aiopg.connection import Connection\n\n"
            "async def create(conn: Connection, name: str):\n"
            "    async with conn.cursor() as cur:\n"
            "        await cur.execute(\"INSERT INTO s (name) VALUES ('%s')\" % name)\n\n"
            "async def handler(request: web.Request):\n"
            "    data = await request.post()\n    await create(request.app['db'], data['name'])\n"
            "    return web.Response(text='ok')\n\napp = web.Application()\n"
            "app.router.add_post('/s', handler)\n")
    assert "CWE-89" in _cwes(code, "python", "views.py")
