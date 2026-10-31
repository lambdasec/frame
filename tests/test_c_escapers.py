"""A C/C++ HTML escaper is credited by what its body does, never by its name: a loop over the
input whose switch replaces each of `& < > " '` with a character reference. In a directory scan a
function defined in one translation unit is the same symbol in the others (the linker's rule)."""

import pytest

from frame.sil.analyzers.c_escapers import escapers
from frame.sil.frontends.c_frontend import CppFrontend
from frame.sil.scanner import FrameScanner

ESCAPER = """#include <string>
std::string {name}(const std::string &in) {{
    std::string out;
    for (char c : in) {{
        switch (c) {{
{cases}
        default: out += c;
        }}
    }}
    return out;
}}
"""
FIVE = "\n".join(f"        case {c}: out += \"{e}\"; break;" for c, e in (
    ("'&'", "&amp;"), ("'<'", "&lt;"), ("'>'", "&gt;"), ("'\"'", "&quot;"), ("'\\''", "&#39;")))


def _chars(cases, name="esc"):
    src = ESCAPER.format(name=name, cases=cases).encode()
    return escapers(CppFrontend().parser.parse(src), src).get(name, set())


def test_a_switch_escaper_neutralizes_its_cases():
    assert _chars(FIVE) == set("&<>\"'")
    assert _chars(FIVE.replace('"&lt;"', "c")) == set("&>\"'")        # `<` appended as is


SERVER = """#include <httplib.h>
#include "util.h"
int main() {
    httplib::Server svr;
    svr.Get("/s", [](const httplib::Request &req, httplib::Response &res) {
        res.set_content("<h1>" + esc(req.get_param_value("q")) + "</h1>", "text/html");
    });
    svr.listen("0.0.0.0", 8080);
}
"""


FOUR = "\n".join(FIVE.splitlines()[:-1])                          # no `'`: unsafe in single-quoted attributes


@pytest.mark.parametrize("cases, flagged", [(FIVE, False), (FOUR, True)])
def test_an_escaper_in_another_file_sanitizes(tmp_path, cases, flagged):
    (tmp_path / "util.h").write_text("#include <string>\nstd::string esc(const std::string &in);\n")
    (tmp_path / "util.cpp").write_text('#include "util.h"\n' + ESCAPER.format(name="esc", cases=cases))
    (tmp_path / "server.cpp").write_text(SERVER)
    results = FrameScanner(verify=False).scan_directory(str(tmp_path), None)
    assert ("CWE-79" in {v.cwe_id for r in results for v in r.vulnerabilities}) == flagged


def test_a_name_alone_is_not_an_escaper():
    code = SERVER.replace('#include "util.h"\n', "std::string esc(const std::string &in) { return in; }\n")
    found = {v.cwe_id for v in FrameScanner(language="cpp", verify=False).scan(code, "server.cpp").vulnerabilities}
    assert "CWE-79" in found
