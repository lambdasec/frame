"""`res.render("view", {...})` is an XSS sink only for the data the template prints raw.

Each positive is paired with the nearest escaped idiom; an unreadable or unknown template
keeps every value a sink, as before.
"""

import pytest

from frame.sil.scanner import FrameScanner
from frame.sil.templates import raw_data_keys

ROUTE = ("const express = require('express');\nconst router = express.Router();\n"
         "router.get('/p', (req, res) => {{\n  res.render('page', {data});\n}});\n")


def xss_lines(tmp_path, template, data, name="page.ejs", extra=None):
    (tmp_path / "views").mkdir(exist_ok=True)
    if template is not None:
        (tmp_path / "views" / name).write_text(template)
    for rel, text in (extra or {}).items():
        (tmp_path / "views" / rel).write_text(text)
    route = tmp_path / "routes" / "r.js"
    route.parent.mkdir(exist_ok=True)
    route.write_text(ROUTE.format(data=data))
    r = FrameScanner(language="javascript").scan_file(str(route))
    return [v.line for v in r.vulnerabilities if v.cwe_id == "CWE-79"]


DATA = "{ q: req.query.q, n: 1 }"


@pytest.mark.parametrize("template,name", [
    ("<h1><%- q %></h1>", "page.ejs"),
    ("<h1>{{{ q }}}</h1>", "page.hbs"),
    ("<h1>{{ q | safe }}</h1>", "page.njk"),
    ("p!= q", "page.pug"),
    ("p !{q}", "page.pug"),
])
def test_raw_output_of_a_tainted_value_is_reported(tmp_path, template, name):
    assert xss_lines(tmp_path, template, DATA, name)


@pytest.mark.parametrize("template,name", [
    ("<h1><%= q %></h1>", "page.ejs"),
    ("<h1>{{ q }}</h1>", "page.hbs"),
    ("<h1>{{ q }}</h1>", "page.njk"),
    ("p= q", "page.pug"),
    ("p #{q}", "page.pug"),
])
def test_escaped_output_is_not_reported(tmp_path, template, name):
    assert not xss_lines(tmp_path, template, DATA, name)


def test_only_the_raw_key_is_a_sink(tmp_path):
    tpl = "<%= q %> <%- n %>"
    assert xss_lines(tmp_path, tpl, "{ q: req.query.q, n: 1 }") == []
    assert xss_lines(tmp_path, tpl, "{ q: 'x', n: req.query.n }")


def test_loop_variable_inherits_the_data_key(tmp_path):
    tpl = "<% items.forEach(function (i) { %><p><%- i.body %></p><% }) %>"
    assert xss_lines(tmp_path, tpl, "{ items: req.query.items }")
    tpl2 = "<% for (const i of items) { %><p><%= i.body %></p><% } %>"
    assert not xss_lines(tmp_path, tpl2, "{ items: req.query.items }")


def test_handlebars_each_block_with_raw_body(tmp_path):
    raw = "{{#each items}}<p>{{{body}}}</p>{{/each}}"
    assert xss_lines(tmp_path, raw, "{ items: req.query.items }", "page.hbs")
    esc = "{{#each items}}<p>{{body}}</p>{{/each}}"
    assert not xss_lines(tmp_path, esc, "{ items: req.query.items }", "page.hbs")


def test_missing_template_keeps_every_value_a_sink(tmp_path):
    assert xss_lines(tmp_path, None, DATA)


def test_unresolvable_include_keeps_every_value_a_sink(tmp_path):
    assert xss_lines(tmp_path, "<%- include('missing') %><%= q %>", DATA)


def test_resolvable_include_is_read(tmp_path):
    assert xss_lines(tmp_path, "<%- include('part') %>", DATA, extra={"part.ejs": "<%- q %>"})
    assert not xss_lines(tmp_path, "<%- include('part') %>", DATA, extra={"part.ejs": "<%= q %>"})


def test_autoescape_off_keeps_every_value_a_sink(tmp_path):
    assert xss_lines(tmp_path, "{% autoescape false %}{{ q }}{% endautoescape %}", DATA, "page.njk")


def test_spread_data_is_conservative(tmp_path):
    assert xss_lines(tmp_path, "<%= q %>", "{ ...req.query }")


def test_layout_raw_output_counts(tmp_path):
    assert xss_lines(tmp_path, "<%= q %>", DATA, extra={"layout.ejs": "<%- q %>"})


def test_raw_data_keys_api(tmp_path):
    (tmp_path / "views").mkdir()
    (tmp_path / "views" / "a.ejs").write_text("<%= x %><%- y.z %>")
    src = str(tmp_path / "routes" / "r.js")
    assert raw_data_keys("a", src) == frozenset({"y"})
    assert raw_data_keys("nope", src) is None


def test_engine_with_escaping_turned_off_keeps_every_value_a_sink(tmp_path):
    (tmp_path / "package.json").write_text("{}")
    (tmp_path / "server.js").write_text("swig.setDefaults({ autoescape: false });\n")
    assert xss_lines(tmp_path, "<h1>{{ q }}</h1>", DATA, "page.html")


def test_engine_default_escaping_still_narrows(tmp_path):
    (tmp_path / "package.json").write_text("{}")
    (tmp_path / "server.js").write_text("swig.setDefaults({ autoescape: true });\n")
    assert not xss_lines(tmp_path, "<h1>{{ q }}</h1>", DATA, "page.html")
