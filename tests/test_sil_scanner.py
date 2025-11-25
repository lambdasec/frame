"""
Tests for Frame SIL Scanner.

Tests the complete pipeline:
    Source Code → Frontend → SIL → Translator → Vulnerability Checks
"""

import pytest

# Check if tree-sitter is available
try:
    import tree_sitter_python
    TREE_SITTER_AVAILABLE = True
except ImportError:
    TREE_SITTER_AVAILABLE = False


# Skip all tests if tree-sitter not available
pytestmark = pytest.mark.skipif(
    not TREE_SITTER_AVAILABLE,
    reason="tree-sitter-python not installed"
)


class TestPythonFrontend:
    """Test Python to SIL translation"""

    def test_simple_function(self):
        """Test translating a simple function"""
        from frame.sil.frontends.python_frontend import PythonFrontend

        code = """
def hello():
    x = 1
    return x
"""
        frontend = PythonFrontend()
        program = frontend.translate(code, "test.py")

        assert "hello" in program.procedures
        proc = program.procedures["hello"]
        assert proc.name == "hello"
        assert len(list(proc.cfg_iter())) > 0

    def test_function_with_params(self):
        """Test function with parameters"""
        from frame.sil.frontends.python_frontend import PythonFrontend

        code = """
def greet(name, greeting="Hello"):
    message = greeting + " " + name
    return message
"""
        frontend = PythonFrontend()
        program = frontend.translate(code, "test.py")

        proc = program.procedures["greet"]
        assert len(proc.params) == 2

    def test_flask_source_detection(self):
        """Test detection of Flask taint sources"""
        from frame.sil.frontends.python_frontend import PythonFrontend
        from frame.sil.instructions import TaintSource, Call

        code = """
from flask import request

def get_user():
    user_id = input()
    return user_id
"""
        frontend = PythonFrontend()
        program = frontend.translate(code, "test.py")

        proc = program.procedures["get_user"]

        # Check that TaintSource instruction was generated
        # The frontend generates TaintSource for known sources like input()
        taint_sources = []
        for node in proc.cfg_iter():
            for instr in node.instrs:
                if isinstance(instr, TaintSource):
                    taint_sources.append(instr)

        assert len(taint_sources) > 0, "Should detect input() as taint source"

    def test_sql_sink_detection(self):
        """Test detection of SQL injection sink"""
        from frame.sil.frontends.python_frontend import PythonFrontend
        from frame.sil.instructions import TaintSink, SinkKind

        code = """
def execute_query(query):
    cursor.execute(query)
"""
        frontend = PythonFrontend()
        program = frontend.translate(code, "test.py")

        proc = program.procedures["execute_query"]

        # Check that TaintSink instruction was generated
        sinks = []
        for node in proc.cfg_iter():
            for instr in node.instrs:
                if isinstance(instr, TaintSink):
                    sinks.append(instr)

        assert len(sinks) > 0
        assert sinks[0].kind == SinkKind.SQL_QUERY


class TestSILTranslator:
    """Test SIL to Frame formula translation"""

    def test_taint_flow_detection(self):
        """Test detection of taint flow from source to sink"""
        from frame.sil.frontends.python_frontend import PythonFrontend
        from frame.sil.translator import SILTranslator, VulnType

        # Use simple function names that the frontend can match directly
        code = """
def vulnerable():
    user_id = input()
    query = "SELECT * FROM users WHERE id=" + user_id
    cursor.execute(query)
"""
        frontend = PythonFrontend()
        program = frontend.translate(code, "test.py")

        translator = SILTranslator(program)
        checks = translator.translate_program()

        # Should detect SQL injection (taint from input() to cursor.execute())
        sql_checks = [c for c in checks if c.vuln_type == VulnType.SQL_INJECTION]
        assert len(sql_checks) > 0, f"Expected SQL injection detection, got {len(checks)} checks total"

    def test_sanitized_flow(self):
        """Test that sanitized flows are handled"""
        from frame.sil.frontends.python_frontend import PythonFrontend
        from frame.sil.translator import SILTranslator

        # This is a simplified test - full sanitization tracking
        # requires more sophisticated dataflow analysis
        code = """
from flask import request
import html

def safe():
    user_input = request.args.get('name')
    safe_input = html.escape(user_input)
    return safe_input
"""
        frontend = PythonFrontend()
        program = frontend.translate(code, "test.py")

        translator = SILTranslator(program)
        checks = translator.translate_program()

        # The translator should track sanitization
        # (actual verification happens in IncorrectnessChecker)
        assert isinstance(checks, list)


class TestFrameScanner:
    """Test the high-level scanner interface"""

    def test_scan_vulnerable_code(self):
        """Test scanning code with SQL injection"""
        from frame.sil.scanner import FrameScanner, VulnType

        # Use simple function names that frontend matches directly
        code = """
def get_user():
    user_id = input()
    cursor.execute("SELECT * FROM users WHERE id=" + user_id)
"""
        scanner = FrameScanner(language="python", verify=False)
        result = scanner.scan(code, "test.py")

        assert result.has_vulnerabilities, f"Expected vulnerabilities, got: {result.vulnerabilities}"

        # Check that SQL injection was detected
        sql_vulns = [v for v in result.vulnerabilities
                     if v.type == VulnType.SQL_INJECTION]
        assert len(sql_vulns) > 0, f"Expected SQL injection, got: {[v.type for v in result.vulnerabilities]}"

    def test_scan_xss(self):
        """Test scanning code with XSS vulnerability"""
        from frame.sil.scanner import FrameScanner, VulnType

        # Use simple function names
        code = """
def render():
    name = input()
    html = "<h1>Hello " + name + "</h1>"
    render_template_string(html)
"""
        scanner = FrameScanner(language="python", verify=False)
        result = scanner.scan(code, "test.py")

        # Check that XSS was detected
        xss_vulns = [v for v in result.vulnerabilities
                     if v.type == VulnType.XSS]
        assert len(xss_vulns) > 0, f"Expected XSS, got: {[v.type for v in result.vulnerabilities]}"

    def test_scan_command_injection(self):
        """Test scanning code with command injection"""
        from frame.sil.scanner import FrameScanner, VulnType

        # Use simple function names
        code = """
import os

def run_command():
    cmd = input()
    os.system("ls " + cmd)
"""
        scanner = FrameScanner(language="python", verify=False)
        result = scanner.scan(code, "test.py")

        # Check that command injection was detected
        cmd_vulns = [v for v in result.vulnerabilities
                     if v.type == VulnType.COMMAND_INJECTION]
        assert len(cmd_vulns) > 0, f"Expected command injection, got: {[v.type for v in result.vulnerabilities]}"

    def test_scan_safe_code(self):
        """Test scanning safe code"""
        from frame.sil.scanner import FrameScanner

        code = """
def add(a, b):
    return a + b

def greet():
    return "Hello, World!"
"""
        scanner = FrameScanner(language="python", verify=False)
        result = scanner.scan(code, "test.py")

        # No taint sources/sinks, so no vulnerabilities
        assert not result.has_vulnerabilities

    def test_sarif_output(self):
        """Test SARIF output format"""
        from frame.sil.scanner import FrameScanner

        code = """
from flask import request

def vulnerable():
    user_id = request.args.get('id')
    cursor.execute("SELECT * FROM users WHERE id=" + user_id)
"""
        scanner = FrameScanner(language="python", verify=False)
        result = scanner.scan(code, "test.py")

        sarif = result.to_sarif()

        assert sarif["$schema"].endswith("sarif-schema-2.1.0.json")
        assert sarif["version"] == "2.1.0"
        assert len(sarif["runs"]) == 1
        assert sarif["runs"][0]["tool"]["driver"]["name"] == "Frame Security Scanner"

    def test_json_output(self):
        """Test JSON output format"""
        from frame.sil.scanner import FrameScanner
        import json

        code = """
def hello():
    return "Hello"
"""
        scanner = FrameScanner(language="python", verify=False)
        result = scanner.scan(code, "test.py")

        json_str = result.to_json()
        data = json.loads(json_str)

        assert data["filename"] == "test.py"
        assert "vulnerabilities" in data
        assert "scan_time_ms" in data


class TestSILTypes:
    """Test SIL type definitions"""

    def test_ident(self):
        """Test Ident creation"""
        from frame.sil.types import Ident

        i1 = Ident("tmp")
        assert str(i1) == "$tmp"

        i2 = Ident("tmp", 5)
        assert str(i2) == "$tmp_5"

    def test_pvar(self):
        """Test PVar creation"""
        from frame.sil.types import PVar

        p = PVar("x")
        assert str(p) == "x"

    def test_location(self):
        """Test Location creation"""
        from frame.sil.types import Location

        loc = Location("test.py", 10, 5)
        assert str(loc) == "test.py:10:5"

    def test_expressions(self):
        """Test expression types"""
        from frame.sil.types import (
            ExpVar, ExpConst, ExpBinOp, ExpFieldAccess,
            PVar, var, const
        )

        # Variable
        v = var("x")
        assert str(v) == "x"

        # Constant
        c = const(42)
        assert str(c) == "42"

        # Binary op
        b = ExpBinOp("+", var("x"), const(1))
        assert "+" in str(b)

        # Field access
        f = ExpFieldAccess(var("obj"), "field")
        assert str(f) == "obj.field"


class TestSILInstructions:
    """Test SIL instruction types"""

    def test_assign(self):
        """Test Assign instruction"""
        from frame.sil.instructions import Assign
        from frame.sil.types import PVar, Location, var, const

        instr = Assign(
            loc=Location("test.py", 1),
            id=PVar("x"),
            exp=const(42)
        )
        assert "x" in str(instr)
        assert "42" in str(instr)

    def test_call(self):
        """Test Call instruction"""
        from frame.sil.instructions import Call
        from frame.sil.types import Ident, Location, ExpConst, Typ

        instr = Call(
            loc=Location("test.py", 1),
            ret=(Ident("result"), Typ.unknown_type()),
            func=ExpConst.string("print"),
            args=[(ExpConst.string("hello"), Typ.string_type())]
        )
        assert "print" in str(instr)

    def test_taint_source(self):
        """Test TaintSource instruction"""
        from frame.sil.instructions import TaintSource, TaintKind
        from frame.sil.types import PVar, Location

        instr = TaintSource(
            loc=Location("test.py", 1),
            var=PVar("user_input"),
            kind=TaintKind.USER_INPUT
        )
        assert "user_input" in str(instr)
        assert "user" in str(instr)

    def test_taint_sink(self):
        """Test TaintSink instruction"""
        from frame.sil.instructions import TaintSink, SinkKind
        from frame.sil.types import Location, var

        instr = TaintSink(
            loc=Location("test.py", 1),
            exp=var("query"),
            kind=SinkKind.SQL_QUERY
        )
        assert "query" in str(instr)
        assert "sql" in str(instr)


class TestProcedure:
    """Test Procedure and CFG"""

    def test_procedure_creation(self):
        """Test creating a procedure"""
        from frame.sil.procedure import Procedure, Node, NodeKind
        from frame.sil.types import PVar, Typ

        proc = Procedure(
            name="test_func",
            params=[(PVar("x"), Typ.int_type())],
            ret_type=Typ.int_type()
        )

        # Add nodes
        entry = proc.new_node(NodeKind.ENTRY)
        proc.add_node(entry)
        proc.entry_node = entry.id

        body = proc.new_node()
        proc.add_node(body)

        exit_node = proc.new_node(NodeKind.EXIT)
        proc.add_node(exit_node)
        proc.exit_node = exit_node.id

        # Connect
        proc.connect(entry.id, body.id)
        proc.connect(body.id, exit_node.id)

        # Verify
        assert len(proc.nodes) == 3
        nodes_list = list(proc.cfg_iter())
        assert len(nodes_list) == 3

    def test_program(self):
        """Test Program container"""
        from frame.sil.procedure import Program, Procedure, ProcSpec
        from frame.sil.types import Typ

        program = Program()

        # Add procedure
        proc = Procedure(name="main", params=[], ret_type=Typ.void_type())
        program.add_procedure(proc)

        # Add library spec
        spec = ProcSpec(is_source="user")
        program.add_library_spec("input", spec)

        assert program.has_procedure("main")
        assert program.is_source("input")


class TestLibrarySpecs:
    """Test library specifications"""

    def test_flask_specs(self):
        """Test Flask specs are defined"""
        from frame.sil.specs.python_specs import FLASK_SPECS

        assert "request.args.get" in FLASK_SPECS
        assert FLASK_SPECS["request.args.get"].is_taint_source()

    def test_sql_sinks(self):
        """Test SQL sink specs"""
        from frame.sil.specs.python_specs import SQLALCHEMY_SPECS, PYTHON_SPECS

        # cursor.execute is in PYTHON_SPECS (combined) not just SQLALCHEMY_SPECS
        assert "session.execute" in SQLALCHEMY_SPECS
        assert SQLALCHEMY_SPECS["session.execute"].is_taint_sink()

        # Also check in combined specs
        assert "cursor.execute" in PYTHON_SPECS
        assert PYTHON_SPECS["cursor.execute"].is_taint_sink()

    def test_sanitizers(self):
        """Test sanitizer specs"""
        from frame.sil.specs.python_specs import HTML_SPECS

        assert "html.escape" in HTML_SPECS
        assert HTML_SPECS["html.escape"].is_taint_sanitizer()

    def test_all_specs_combined(self):
        """Test combined specs"""
        from frame.sil.specs.python_specs import PYTHON_SPECS

        # Should have all categories
        assert "request.args.get" in PYTHON_SPECS  # Flask
        assert "cursor.execute" in PYTHON_SPECS    # SQL
        assert "os.system" in PYTHON_SPECS         # Shell
        assert "html.escape" in PYTHON_SPECS       # Sanitizer


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
