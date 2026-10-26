"""JS/TS frontend facts that the framework packs and fixtures rely on."""

import pytest

from frame.sil.frontends.javascript_frontend import JavaScriptFrontend


def _calls(src, proc="anonymous"):
    p = JavaScriptFrontend().translate(src, "t.js")
    out = []
    for name, pr in p.procedures.items():
        if proc and name != proc:
            continue
        for nd in pr.nodes.values():
            out += [i for i in nd.instrs if type(i).__name__ == "Call"]
    return p, out


def _names(src, proc="anonymous"):
    return [str(getattr(c.func, "value", c.func)) for c in _calls(src, proc)[1]]


def test_fluent_setters_keep_the_receiver_in_the_call_name():
    names = _names("app.get('/', (req, res) => { res.status(200).send(x); });")
    assert "res.send" in names


def test_non_html_content_type_is_not_an_html_send():
    names = _names("app.get('/', (req, res) => { res.type('text').send(x); });")
    assert "res.send" not in names


def test_jquery_chain_is_named_after_the_method():
    names = _names("function f(v) { $('#a').find('li').html(v); }", proc="f")
    assert "$.html" in names


def test_returned_call_is_also_a_call_statement():
    names = _names("app.get('/', (req, h) => { return h.redirect(req.query.to); });")
    assert "h.redirect" in names


def test_object_literal_handlers_are_registered_via_the_callee_and_key():
    p, _ = _calls("server.route({ method: 'GET', handler: (request, h) => 1 });", proc="")
    assert any("server.route.handler" in pr.registered_via for pr in p.procedures.values())


def test_graphql_resolver_maps_register_their_functions():
    p, _ = _calls("const resolvers = { Query: { a: (parent, args) => 1 }, Book: { b: (parent, args) => 2 } };", proc="")
    via = [pr.registered_via for pr in p.procedures.values() if pr.registered_via]
    assert len(via) == 2 and all(v == ["graphql.resolver"] for v in via)


def test_options_object_of_a_package_call_becomes_named_arguments():
    _, calls = _calls("const x = require('libxmljs');\nfunction f(t) { x.parseXml(t, { noent: true }); }", proc="f")
    call = [c for c in calls if "parseXml" in str(c.func)][0]
    assert call.kwarg_names == [None, None, "noent"]


def test_project_modules_do_not_get_named_arguments():
    _, calls = _calls("const x = require('./local');\nfunction f(t) { x.run(t, { a: 1 }); }", proc="f")
    assert all(c.kwarg_names is None for c in calls)


@pytest.mark.parametrize("src", [
    "function f(req) { const x = req.query.p.split(',')[1]; document.write(x); }",
    "function f() { const x = decodeURIComponent(location.hash.slice(1)); document.write(x); }",
    "function f() { const x = new URLSearchParams(location.search).get('q'); document.write(x); }",
])
def test_string_methods_on_inline_request_data_stay_tainted(src):
    from frame.sil.scanner import FrameScanner
    result = FrameScanner(language="javascript").scan(src, "t.js")
    assert any(v.cwe_id == "CWE-79" for v in result.vulnerabilities)
