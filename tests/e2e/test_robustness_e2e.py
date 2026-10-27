"""Frame on the messy trees real repositories contain, through the real CLI process.

Each test is one small scenario with one assertion: a vulnerable file sits next to something awkward
(a file that does not parse, a binary, a symlink loop, 2000 files, ...) and must still be reported,
without a traceback and within a sane time. Every subprocess has a timeout, so a hang fails the test
instead of the run. A scenario Frame handles wrongly today is a strict xfail that names the bug.
"""

import json
import os
import subprocess
import sys
import time

import pytest

from e2e_helpers import write_tree

VULN_PY = '''import os
from flask import Flask, request

app = Flask(__name__)


@app.route("/x")
def x():
    os.system("echo " + request.args.get("q", ""))
    return "ok"
'''
VULN_LINE = 9           # the os.system line of VULN_PY
CLEAN_PY = "def add(a, b):\n    return a + b\n"

# Frame bugs these scenarios expose (see the report); each xfail below names one.
CRASH_ON_BAD_ENCODING = pytest.mark.xfail(
    strict=True, reason="scan_file reads files with strict utf-8: one undecodable file aborts the whole scan")


def frame(*args, cwd=None, timeout=180):
    return subprocess.run([sys.executable, "-m", "frame.cli", *args], capture_output=True, text=True,
                          cwd=str(cwd) if cwd else None, timeout=timeout)


def scan_json(target, *flags, cwd=None, timeout=180):
    """(CompletedProcess, document) for `frame scan TARGET -f json --fail-on none ...`."""
    done = frame("scan", str(target), "-f", "json", "--fail-on", "none", *flags, cwd=cwd, timeout=timeout)
    try:
        doc = json.loads(done.stdout)
    except ValueError:
        doc = {}
    return done, doc


def findings(doc):
    files = doc["files"] if "files" in doc else ([doc] if doc else [])
    return [dict(v, _file=f.get("filename", "")) for f in files for v in f.get("vulnerabilities", [])]


def reported(doc):
    return sorted((v.get("path") or v["_file"], v["line"], v["cwe_id"]) for v in findings(doc))


def warnings(doc):
    files = doc["files"] if "files" in doc else ([doc] if doc else [])
    return [(f.get("filename", ""), w) for f in files for w in f.get("warnings", [])]


# ---- files that do not parse ------------------------------------------------------------

def test_syntax_error_file_does_not_hide_the_vulnerable_file_next_to_it(tmp_path):
    write_tree(tmp_path, {"broken.py": "def f(:\n    if\n", "app.py": VULN_PY})
    _, doc = scan_json(tmp_path)
    assert ("app.py", VULN_LINE, "CWE-78") in reported(doc)


def test_syntax_error_file_does_not_crash_the_scan(tmp_path):
    write_tree(tmp_path, {"broken.py": "def f(:\n    if\n", "app.py": VULN_PY})
    done = frame("scan", str(tmp_path), "-f", "json")
    assert done.returncode == 1 and "Traceback" not in done.stderr          # 1 = findings at/above --fail-on


def test_vulnerability_before_a_syntax_error_in_the_same_file_is_still_reported(tmp_path):
    write_tree(tmp_path, {"app.py": VULN_PY + "\n\ndef broken(:\n    pass\n"})
    _, doc = scan_json(tmp_path)
    assert {c for _, _, c in reported(doc)} == {"CWE-78"}


@pytest.mark.xfail(strict=True, reason="a file that does not parse is scanned as if it were clean, with no warning")
def test_syntax_error_file_produces_a_warning(tmp_path):
    write_tree(tmp_path, {"broken.py": "def f(:\n    if\n", "app.py": VULN_PY})
    _, doc = scan_json(tmp_path)
    assert any("broken.py" in name and ("pars" in w.lower() or "syntax" in w.lower()) for name, w in warnings(doc))


def test_truncated_c_file_is_still_analysed(tmp_path):
    write_tree(tmp_path, {"a.c": '#include <stdlib.h>\nint main(void){ system(getenv("X")); \n'})
    _, doc = scan_json(tmp_path)
    assert [c for _, _, c in reported(doc)] == ["CWE-78"]


# ---- empty and odd content --------------------------------------------------------------

def test_empty_and_whitespace_only_files_do_not_stop_the_scan(tmp_path):
    write_tree(tmp_path, {"empty.py": "", "blank.py": "  \n\n\t\n", "empty.c": "", "empty.js": "\n", "app.py": VULN_PY})
    _, doc = scan_json(tmp_path)
    assert [c for _, _, c in reported(doc)] == ["CWE-78"]


def test_a_tree_of_only_empty_files_is_clean(tmp_path):
    write_tree(tmp_path, {"a.py": "", "b.c": "", "c.java": "", "d.cs": "", "e.ts": " "})
    assert frame("scan", str(tmp_path)).returncode == 0


def test_nul_bytes_in_a_source_file_do_not_hide_its_finding(tmp_path):
    (tmp_path / "app.py").write_text(VULN_PY + "\x00\x00junk\n", encoding="utf-8")
    _, doc = scan_json(tmp_path)
    assert [c for _, _, c in reported(doc)] == ["CWE-78"]


# ---- encodings and line endings ---------------------------------------------------------

@CRASH_ON_BAD_ENCODING
def test_binary_file_named_py_does_not_abort_a_directory_scan(tmp_path):
    write_tree(tmp_path, {"app.py": VULN_PY})
    (tmp_path / "blob.py").write_bytes(bytes(range(256)) * 20)
    _, doc = scan_json(tmp_path)
    assert [c for _, _, c in reported(doc)] == ["CWE-78"]


@CRASH_ON_BAD_ENCODING
def test_binary_file_scanned_alone_is_not_a_traceback(tmp_path):
    (tmp_path / "blob.py").write_bytes(bytes(range(256)) * 20)
    assert "Traceback" not in frame("scan", str(tmp_path / "blob.py")).stderr


@CRASH_ON_BAD_ENCODING
def test_latin1_file_with_a_finding_is_scanned(tmp_path):
    (tmp_path / "app.py").write_bytes(VULN_PY.replace('"ok"', '"caf\xe9"').encode("latin-1"))
    _, doc = scan_json(tmp_path)
    assert [c for _, _, c in reported(doc)] == ["CWE-78"]


def test_crlf_line_endings_keep_line_numbers(tmp_path):
    (tmp_path / "app.py").write_bytes(VULN_PY.replace("\n", "\r\n").encode())
    _, doc = scan_json(tmp_path)
    assert [ln for _, ln, _ in reported(doc)] == [VULN_LINE]


def test_mixed_line_endings_keep_line_numbers(tmp_path):
    lines = VULN_PY.split("\n")
    text = "".join(line + ("\r\n" if i % 2 else "\n") for i, line in enumerate(lines))
    (tmp_path / "app.py").write_bytes(text.encode())
    _, doc = scan_json(tmp_path)
    assert [ln for _, ln, _ in reported(doc)] == [VULN_LINE]


def test_bare_cr_line_endings_keep_line_numbers(tmp_path):
    (tmp_path / "app.py").write_bytes(VULN_PY.replace("\n", "\r").encode())
    _, doc = scan_json(tmp_path)
    assert [ln for _, ln, _ in reported(doc)] == [VULN_LINE]


def test_utf8_bom_does_not_shift_the_reported_line(tmp_path):
    (tmp_path / "app.py").write_bytes(b"\xef\xbb\xbf" + VULN_PY.encode())
    _, doc = scan_json(tmp_path)
    assert [ln for _, ln, _ in reported(doc)] == [VULN_LINE]


def test_unicode_identifiers_and_strings_are_scanned(tmp_path):
    src = VULN_PY.replace("def x", "def ünïcode_ñame").replace('"ok"', '"héllo ✓ 日本語"')
    (tmp_path / "app.py").write_text(src, encoding="utf-8")
    _, doc = scan_json(tmp_path)
    assert [ln for _, ln, _ in reported(doc)] == [VULN_LINE]


def test_path_with_spaces_and_unicode_is_scanned(tmp_path):
    write_tree(tmp_path, {"sp ace ü/sub dir/my app.py": VULN_PY})
    _, doc = scan_json(tmp_path)
    assert [p for p, _, _ in reported(doc)] == ["sp ace ü/sub dir/my app.py"]


# ---- generated and enormous input --------------------------------------------------------

def test_minified_javascript_is_skipped_with_a_warning(tmp_path):
    (tmp_path / "bundle.js").write_text("var a=" + "+".join(["'x'"] * 50000) + ";\n")
    _, doc = scan_json(tmp_path)
    assert any("minified" in w.lower() for _, w in warnings(doc))


def test_minified_file_does_not_stop_the_vulnerable_file_next_to_it(tmp_path):
    write_tree(tmp_path, {"app.py": VULN_PY})
    (tmp_path / "bundle.js").write_text("var a=" + "+".join(["'x'"] * 50000) + ";\n")
    _, doc = scan_json(tmp_path)
    assert [p for p, _, _ in reported(doc)] == ["app.py"]


def test_a_python_file_with_one_very_long_line_is_skipped_with_a_warning_not_silently(tmp_path):
    (tmp_path / "data.py").write_text(VULN_PY + "BLOB = '" + "a" * 5000 + "'\n")
    _, doc = scan_json(tmp_path)
    assert any("data.py" in name and w for name, w in warnings(doc))


def test_20k_line_generated_file_finishes_and_reports(tmp_path):
    body = "".join(f"def f{i}(a):\n    b = a + {i}\n    return b\n\n" for i in range(5000))
    (tmp_path / "big.py").write_text(VULN_PY + "\n\n" + body)
    started = time.time()
    _, doc = scan_json(tmp_path, timeout=120)
    assert [c for _, _, c in reported(doc)] == ["CWE-78"] and time.time() - started < 90


def test_2000_tiny_files_finish_in_reasonable_time_and_keep_the_finding(tmp_path):
    for i in range(2000):
        (tmp_path / f"m{i}.py").write_text(f"def f{i}(a):\n    return a + {i}\n")
    (tmp_path / "vuln.py").write_text(VULN_PY)
    started = time.time()
    _, doc = scan_json(tmp_path, timeout=300)
    assert [p for p, _, _ in reported(doc)] == ["vuln.py"] and time.time() - started < 120


def test_50_level_deep_directory_is_walked(tmp_path):
    deep = tmp_path.joinpath(*[f"d{i}" for i in range(50)])
    deep.mkdir(parents=True)
    (deep / "deep.py").write_text(VULN_PY)
    _, doc = scan_json(tmp_path)
    assert len(reported(doc)) == 1 and reported(doc)[0][0].endswith("d49/deep.py")


# ---- the file system --------------------------------------------------------------------

def test_symlink_loop_terminates_and_the_real_file_is_found(tmp_path):
    write_tree(tmp_path, {"a/app.py": VULN_PY})
    os.symlink(str(tmp_path), str(tmp_path / "a" / "back"))
    os.symlink("loop2", str(tmp_path / "loop1"))
    os.symlink("loop1", str(tmp_path / "loop2"))
    _, doc = scan_json(tmp_path, timeout=60)
    assert [p for p, _, _ in reported(doc)] == ["a/app.py"]


def test_symlink_to_a_directory_outside_the_root_is_not_followed(tmp_path):
    outside = write_tree(tmp_path / "outside", {"leak.py": VULN_PY})
    root = write_tree(tmp_path / "root", {"ok.py": CLEAN_PY})
    os.symlink(str(outside), str(root / "ext"))
    _, doc = scan_json(root)
    assert reported(doc) == []


def test_dangling_symlink_directory_and_fifo_named_like_sources_are_ignored(tmp_path):
    write_tree(tmp_path, {"good.py": VULN_PY})
    (tmp_path / "isdir.py").mkdir()
    os.symlink("/nonexistent/target.py", str(tmp_path / "dangling.py"))
    os.mkfifo(str(tmp_path / "pipe.py"))
    _, doc = scan_json(tmp_path, timeout=60)
    assert [p for p, _, _ in reported(doc)] == ["good.py"]


def test_read_only_directory_can_be_scanned(tmp_path):
    root = write_tree(tmp_path / "ro", {"app.py": VULN_PY})
    os.chmod(root, 0o555)
    try:
        _, doc = scan_json(root)
    finally:
        os.chmod(root, 0o755)
    assert [p for p, _, _ in reported(doc)] == ["app.py"]


@pytest.mark.skipif(os.geteuid() == 0, reason="root reads files whatever their mode")
def test_unreadable_file_does_not_stop_the_scan(tmp_path):
    write_tree(tmp_path, {"a.py": VULN_PY, "b.py": VULN_PY})
    os.chmod(tmp_path / "b.py", 0)
    try:
        _, doc = scan_json(tmp_path)
    finally:
        os.chmod(tmp_path / "b.py", 0o644)
    assert "a.py" in [p for p, _, _ in reported(doc)]


def test_default_excludes_skip_dependency_and_vcs_directories(tmp_path):
    write_tree(tmp_path, {"app.py": VULN_PY, "node_modules/pkg/x.py": VULN_PY, ".venv/lib/y.py": VULN_PY,
                          ".git/hooks/h.py": VULN_PY})
    _, doc = scan_json(tmp_path)
    assert [p for p, _, _ in reported(doc)] == ["app.py"]


def test_no_default_excludes_scans_them(tmp_path):
    write_tree(tmp_path, {"app.py": VULN_PY, "node_modules/pkg/x.py": VULN_PY, ".venv/lib/y.py": VULN_PY,
                          ".git/hooks/h.py": VULN_PY})
    _, doc = scan_json(tmp_path, "--no-default-excludes")
    assert len(reported(doc)) == 4


def test_file_without_an_extension_is_scanned_when_named_directly(tmp_path):
    write_tree(tmp_path, {"script": VULN_PY})
    _, doc = scan_json(tmp_path / "script")
    assert [c for _, _, c in reported(doc)] == ["CWE-78"]


@pytest.mark.xfail(strict=True, reason="a directory scan ignores extensionless files, shebang scripts included")
def test_extensionless_python_script_is_scanned_in_a_directory_scan(tmp_path):
    write_tree(tmp_path, {"deploy-tool": "#!/usr/bin/env python3\n" + VULN_PY, "README": "docs\n"})
    done, doc = scan_json(tmp_path)
    assert done.returncode == 0 and [c for _, _, c in reported(doc)] == ["CWE-78"]


# ---- stability --------------------------------------------------------------------------

def test_single_file_and_directory_scans_agree_on_fingerprints(tmp_path):
    write_tree(tmp_path, {"app.py": VULN_PY, "util.py": CLEAN_PY})
    _, whole = scan_json(tmp_path, "--root", str(tmp_path))
    _, alone = scan_json(tmp_path / "app.py", "--root", str(tmp_path))
    assert [v["fingerprint"] for v in findings(whole)] == [v["fingerprint"] for v in findings(alone)] != []


def _stable(doc):
    if isinstance(doc, dict):
        return {k: _stable(v) for k, v in doc.items() if "time" not in k}
    if isinstance(doc, list):
        return [_stable(v) for v in doc]
    return doc


def test_scanning_twice_gives_identical_json_apart_from_timing(tmp_path):
    write_tree(tmp_path, {"app.py": VULN_PY, "weak.py": "import hashlib\nh = hashlib.md5(b'x')\n",
                          "c/run.c": '#include <stdlib.h>\nint main(void){ system(getenv("X")); return 0; }\n'})
    _, first = scan_json(tmp_path, "--root", str(tmp_path))
    _, second = scan_json(tmp_path, "--root", str(tmp_path))
    assert _stable(first) == _stable(second) and findings(first)


def test_relative_target_from_another_working_directory_gives_the_same_paths(tmp_path):
    write_tree(tmp_path, {"proj/app.py": VULN_PY})
    _, here = scan_json("proj", "--root", str(tmp_path / "proj"), cwd=tmp_path)
    _, there = scan_json(tmp_path / "proj", "--root", str(tmp_path / "proj"), cwd=tmp_path / "proj")
    assert reported(here) == reported(there) == [("app.py", VULN_LINE, "CWE-78")]


def test_dot_target_scans_the_working_directory(tmp_path):
    write_tree(tmp_path, {"app.py": VULN_PY})
    _, doc = scan_json(".", cwd=tmp_path)
    assert [p for p, _, _ in reported(doc)] == ["app.py"]


# ---- C/C++ projects: files are analysed independently ----------------------------------------

def test_c_project_scan_equals_the_union_of_scanning_each_file_alone(tmp_path):
    from projects_c import CASES
    vulnerable, _ = CASES["project_with_headers_independent_units"]
    write_tree(tmp_path, vulnerable)
    _, whole = scan_json(tmp_path, "--root", str(tmp_path))
    alone = []
    for rel in sorted(vulnerable):
        if rel.endswith(".c"):
            _, doc = scan_json(tmp_path / rel, "--root", str(tmp_path))
            alone += reported(doc)
    assert reported(whole) == sorted(alone) and alone


# ---- C/C++ frontend regressions found while writing the C matrix ------------------------------

def _c_cwes(tmp_path, name, source):
    (tmp_path / name).write_text(source)
    _, doc = scan_json(tmp_path)
    return sorted(c for _, _, c in reported(doc) if c)


def test_nul_terminating_a_buffer_at_the_read_count_is_not_an_attacker_controlled_index(tmp_path):
    src = '''#include <unistd.h>

void handle(int fd)
{
    char line[200];
    ssize_t n = read(fd, line, sizeof(line) - 1);
    if (n <= 0) {
        return;
    }
    line[n] = '\\0';
}
'''
    assert "CWE-787" not in _c_cwes(tmp_path, "a.c", src)


def test_buffer_released_after_being_read_into_is_not_an_unclassified_taint_flow(tmp_path):
    src = '''#include <stdio.h>
#include <stdlib.h>

int slurp(const char *path)
{
    char *buf = malloc(4096);
    if (buf == NULL) {
        return -1;
    }
    FILE *fp = fopen(path, "r");
    if (fp == NULL) {
        free(buf);
        return -1;
    }
    fread(buf, 1, 4095, fp);
    fclose(fp);
    free(buf);
    return 0;
}
'''
    (tmp_path / "a.c").write_text(src)
    _, doc = scan_json(tmp_path)
    assert [v for v in findings(doc) if not v.get("cwe_id")] == []


def test_member_allocated_in_a_constructor_and_freed_in_the_destructor_is_not_a_leak(tmp_path):
    src = '''#include <cstddef>

class Scratch {
public:
    explicit Scratch(std::size_t n) { data_ = new unsigned char[n]; }
    ~Scratch() { delete[] data_; }

private:
    unsigned char *data_;
};
'''
    assert "CWE-401" not in _c_cwes(tmp_path, "a.cpp", src)


def test_allocation_stored_through_an_out_parameter_is_not_a_leak(tmp_path):
    src = '''#include <stdlib.h>
#include <string.h>

struct header {
    char *key;
};

int parse(const char *line, struct header *out)
{
    out->key = strdup(line);
    return out->key != NULL ? 0 : -1;
}
'''
    assert "CWE-401" not in _c_cwes(tmp_path, "a.c", src)


def test_macro_sized_array_is_bounds_checked_like_a_literal_one(tmp_path):
    src = '''#define SLOTS (16 * 2)

void fill(const unsigned char *src)
{
    unsigned char slots[SLOTS];
    for (int i = 0; i <= SLOTS; i++) {
        slots[i] = src[i];
    }
}
'''
    assert "CWE-787" in _c_cwes(tmp_path, "a.c", src)


def test_redefined_macro_size_is_not_guessed(tmp_path):
    src = '''#ifdef BIG
#define SLOTS 64
#else
#define SLOTS 8
#endif

void fill(const unsigned char *src)
{
    unsigned char slots[SLOTS];
    for (int i = 0; i < 8; i++) {
        slots[i] = src[i];
    }
}
'''
    assert _c_cwes(tmp_path, "a.c", src) == []


def test_call_in_a_return_statement_is_a_sink_call(tmp_path):
    src = '''#include <stdlib.h>

int run(void)
{
    char *cmd = getenv("JOB");
    return system(cmd);
}
'''
    assert "CWE-78" in _c_cwes(tmp_path, "a.c", src)
