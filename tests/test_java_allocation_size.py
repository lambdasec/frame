"""Java allocations sized by a peer (CWE-770): a length or count read off a binary stream or
buffer (`DataInputStream.readInt`, `ByteBuffer.getInt`; Kafka's `ByteUtils.readVarint` through
the `kafka-protocol` pack) or from a request, reaching an array size, a capacity constructor or
`ByteBuffer.allocate` with nothing on the path bounding it.

A number read off the wire (`wire_size`) is not text: it is reported only as an allocation size,
never at an injection sink. Each positive is paired with the nearest correct idiom. The real
cases are Apache Kafka's (examples/java-allocation, CVE-2026-114349 and CVE-2026-111551).
"""

import shutil
from pathlib import Path

import pytest

from frame.sil.scanner import FrameScanner

_HEADER = ("import java.io.*;\nimport java.nio.ByteBuffer;\nimport java.util.*;\nimport java.sql.*;\n"
           "import javax.servlet.http.*;\n")


def _method(body, params="DataInputStream in"):
    return (_HEADER + "class W extends HttpServlet {\n  static final int MAX = 1 << 20;\n"
            f"  Object read({params}) throws Exception {{\n{body}  }}\n}}\n")


def findings(code):
    r = FrameScanner(language="java").scan(code, "W.java")
    assert not r.errors, r.errors
    return sorted((v.line, v.cwe_id) for v in r.vulnerabilities)


@pytest.mark.parametrize("body,line", [
    ("    int n = in.readInt();\n    return new ArrayList<>(n);\n", 10),
    ("    int n = in.readInt();\n    return new byte[n];\n", 10),
    ("    int n = in.readInt();\n    return ByteBuffer.allocate(n);\n", 10),
    ("    int n = in.readUnsignedShort();\n    return new HashMap<String, String>(n);\n", 10),
    ("    long n = in.readLong();\n    return new long[(int) n][4];\n", 10),
    ("    int n = in.readInt();\n    StringBuilder b = new StringBuilder(n);\n    return b;\n", 10),
])
def test_a_size_read_off_a_stream_sizes_an_allocation(body, line):
    assert findings(_method(body)) == [(line, "CWE-770")]


def test_a_size_in_a_byte_buffer_too():
    assert findings(_method("    int n = buf.getInt();\n    return new int[n];\n", "ByteBuffer buf")) == [(10, "CWE-770")]


@pytest.mark.parametrize("body", [
    # an upper bound on the path (Kafka's fixes)
    "    int n = in.readInt();\n    if (n < 0 || n > MAX) throw new IOException(\"size\");\n    return new ArrayList<>(n);\n",
    "    int n = in.readInt();\n    if (n > MAX)\n      throw new IOException(\"size\");\n    return new byte[n];\n",
    # the bytes actually available (Kafka's readFrom(ByteBuffer) overload)
    "    int n = in.readInt();\n    if (in.available() < n) throw new EOFException();\n    return ByteBuffer.allocate(n);\n",
    # capped
    "    int n = Math.min(in.readInt(), MAX);\n    return new byte[n];\n",
    # constant sizes
    "    return new byte[1024];\n",
    "    return new ArrayList<>(16);\n",
])
def test_a_bounded_or_constant_size_is_not_reported(body):
    assert findings(_method(body)) == []


def test_copy_constructors_are_not_allocation_sizes():
    """`new ArrayList<>(c)` and `new StringBuilder(s)` copy; they are not capacities."""
    body = ("    String s = req.getParameter(\"q\");\n    StringBuilder b = new StringBuilder(s);\n"
            "    List<String> xs = new ArrayList<>(Arrays.asList(req.getParameterValues(\"v\")));\n"
            "    return b.toString() + xs;\n")
    assert [f for f in findings(_method(body, "HttpServletRequest req")) if f[1] == "CWE-770"] == []


def test_a_number_off_the_wire_is_not_injection():
    """A wire size concatenated into SQL is a number, not attacker text."""
    body = ("    int n = in.readInt();\n    Connection c = DriverManager.getConnection(\"jdbc:h2:mem:\");\n"
            "    return c.createStatement().executeQuery(\"SELECT * FROM t LIMIT \" + n);\n")
    assert findings(_method(body)) == []


def test_request_data_parsed_to_a_size_is_still_a_size():
    """`Integer.parseInt` clears text injection, not an attacker-chosen allocation size."""
    body = "    int n = Integer.parseInt(req.getParameter(\"n\"));\n    return new byte[n];\n"
    assert findings(_method(body, "HttpServletRequest req")) == [(10, "CWE-770")]


EXAMPLE = Path(__file__).parent.parent / "examples" / "java-allocation"


def _scan_dir(d, *extra):
    import json
    import subprocess
    import sys
    out = subprocess.run([sys.executable, "-m", "frame.cli", "scan", str(d), "--root", str(d), "-f", "json", *extra],
                         capture_output=True, text=True, cwd=str(d))
    data = json.loads(out.stdout)
    return sorted((Path(v["path"]).name, v["line"], v["cwe_id"]) for f in data["files"] for v in f["vulnerabilities"])


def test_kafka_before_and_after_its_fixes(tmp_path):
    """The three Kafka sites, reduced from the commits before the fixes: each is found, the
    readFrom(ByteBuffer) overload that compared the size with the bytes it had is not, and the
    fixed code is clean. DefaultRecord's size comes from Kafka's ByteUtils, so it needs the
    kafka-protocol pack."""
    shutil.copytree(EXAMPLE, tmp_path / "ex")
    before, after = tmp_path / "ex" / "before", tmp_path / "ex" / "after"
    assert _scan_dir(before) == [("AssignmentInfo.java", 15, "CWE-770"), ("DefaultRecord.java", 17, "CWE-770"),
                                 ("ListDeserializer.java", 14, "CWE-770")]
    assert _scan_dir(after) == []
    assert [f[0] for f in _scan_dir(before, "--no-packs")] == ["AssignmentInfo.java", "ListDeserializer.java"]
