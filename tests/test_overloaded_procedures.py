"""Procedures sharing a name (overloads, a Python property getter/setter, the
two arms of a C `#ifdef`) used to replace each other in Program.procedures, so
only the last body was ever analysed and the others' bugs were invisible. And a
delegating overload (`g(in) { return g(bytes, 0); }`) looked like a call to
itself, so it was reported as unbounded recursion (CWE-674).
"""

import pytest

from frame.sil.procedure import Procedure, Program
from frame.sil.scanner import FrameScanner


def findings(code, language, name):
    r = FrameScanner(language=language).scan(code, name)
    assert not r.errors, r.errors
    return {(v.cwe_id, v.line) for v in r.vulnerabilities}


def cwes(code, language, name):
    return {c for c, _ in findings(code, language, name)}


# ---- every overload's body is analysed -----------------------------------

def test_java_first_overload_is_analysed():
    code = ("import javax.servlet.http.*;\n"
            "class A {\n"
            "  void f(HttpServletRequest r) throws Exception {\n"
            "    Runtime.getRuntime().exec(r.getParameter(\"c\"));\n"
            "  }\n"
            "  void f(int n) {\n"
            "  }\n"
            "}\n")
    assert ("CWE-78", 4) in findings(code, "java", "A.java")


def test_java_constructor_overloads_are_all_analysed():
    code = ("import javax.servlet.http.*;\n"
            "class A {\n"
            "  A(HttpServletRequest r) throws Exception {\n"
            "    Runtime.getRuntime().exec(r.getParameter(\"c\"));\n"
            "  }\n"
            "  A() {\n"
            "  }\n"
            "}\n")
    assert "CWE-78" in cwes(code, "java", "A.java")


def test_cpp_first_overload_is_analysed():
    code = ("#include <cstdlib>\n"
            "#include <cstdio>\n"
            "void f(const char* s) {\n"
            "    system(s);\n"
            "}\n"
            "void f(int n) {\n"
            "}\n"
            "int main() {\n"
            "    char buf[64];\n"
            "    fgets(buf, 64, stdin);\n"
            "    f(buf);\n"
            "    return 0;\n"
            "}\n")
    assert "CWE-78" in cwes(code, "cpp", "a.cpp")


def test_csharp_overloads_are_kept_apart():
    from frame.sil.frontends.csharp_frontend import CSharpFrontend
    program = CSharpFrontend().translate(
        "class A {\n  public void F(string s) { }\n  public void F(int n) { }\n}\n", "A.cs")
    assert sorted(program.procedures) == ["A.F", "A.F#2"]


def test_python_property_setter_is_analysed():
    code = ("import os\n"
            "class C:\n"
            "    @property\n"
            "    def cmd(self):\n"
            "        return self._cmd\n"
            "\n"
            "    @cmd.setter\n"
            "    def cmd(self, value):\n"
            "        os.system(input())\n")
    assert "CWE-78" in cwes(code, "python", "c.py")


# ---- delegation between overloads is not recursion -----------------------

@pytest.mark.parametrize("code", [
    # commons-io EndianUtils.readSwappedLong
    ("class E {\n"
     "  long g(java.io.InputStream in) {\n"
     "    return g(new byte[8], 0);\n"
     "  }\n"
     "  long g(byte[] b, int o) {\n"
     "    return 1;\n"
     "  }\n"
     "}\n"),
    # commons-lang3 StringUtils.appendIfMissing (varargs overload)
    ("class S {\n"
     "  String a(String s, CharSequence x, CharSequence... xs) {\n"
     "    return a(s, x, false, xs);\n"
     "  }\n"
     "  String a(String s, CharSequence x, boolean ic, CharSequence... xs) {\n"
     "    return s;\n"
     "  }\n"
     "}\n"),
])
def test_java_overload_delegation_is_not_recursion(code):
    assert "CWE-674" not in cwes(code, "java", "A.java")


def test_java_real_recursion_in_an_overload_is_still_reported():
    code = ("class R {\n"
            "  int h(int n) {\n"
            "    return h(n - 1);\n"
            "  }\n"
            "  int h(String s, int k) {\n"
            "    return 0;\n"
            "  }\n"
            "}\n")
    assert "CWE-674" in cwes(code, "java", "R.java")


def test_same_arity_overloads_resolve_by_argument_type():
    # h(n - 1) is an int argument: it calls h(int) itself, with no base case.
    code = ("class R {\n"
            "  int h(int n) {\n"
            "    return h(n - 1);\n"
            "  }\n"
            "  int h(String s) {\n"
            "    return 0;\n"
            "  }\n"
            "}\n")
    assert "CWE-674" in cwes(code, "java", "R.java")


def test_same_arity_call_to_the_other_overload_is_not_recursion():
    code = ("class R {\n"
            "  int h(int n) {\n"
            "    String s = \"v\" + n;\n"
            "    return h(s);\n"
            "  }\n"
            "  int h(String s) {\n"
            "    return 0;\n"
            "  }\n"
            "}\n")
    assert "CWE-674" not in cwes(code, "java", "R.java")


def _recursion(cls_head, body, extra=""):
    code = f"{cls_head} {{\n{body}{extra}}}\n"
    return "CWE-674" in cwes(code, "java", "R.java")


@pytest.mark.parametrize("head,body,extra,expected", [
    # Closed class, one candidate: an argument of unknown type still resolves.
    ("class R", "  int f(Object o) {\n    return f(o.getClass());\n  }\n", "", True),
    # Widening int -> long in a closed class.
    ("class R", "  long g(long x) {\n    return g(1);\n  }\n", "", True),
    # Open class, inexact match: a superclass g(String) could be more specific.
    ("class R extends B", "  int f(Object o) {\n    return f(\"x\");\n  }\n", "", False),
    # Open class, exact match: nothing inherited can beat it.
    ("class R extends B", "  int f(String s) {\n    return f(s.trim());\n  }\n", "", True),
    # null fits both reference overloads: ambiguous, so no claim.
    ("class R", "  void k(String s) {\n    k(null);\n  }\n",
     "  void k(Integer i) {\n  }\n", False),
    # A boxed argument picks the matching overload.
    ("class R", "  void k(Integer i) {\n    k(i);\n  }\n",
     "  void k(String s) {\n  }\n", True),
    # Varargs: f(a, b) inside f(String...) with String arguments.
    ("class R", "  void v(String... xs) {\n    v(\"a\", \"b\");\n  }\n", "", True),
    # A primitive argument cannot bind to a String parameter.
    ("class R", "  void w(String s) {\n    w(3);\n  }\n", "  void w(int n) {\n  }\n", False),
])
def test_java_overload_resolution_matrix(head, body, extra, expected):
    assert _recursion(head, body, extra) == expected


def test_resolver_convertibility():
    prog = Program()
    prog.class_supertypes = {"Sub": ["Base"], "Base": []}
    conv = prog.java_convertible
    assert conv("int", "long") == "yes" and conv("long", "int") == "no"
    assert conv("int", "Integer") == "yes" and conv("Integer", "long") == "yes"
    assert conv("String", "CharSequence") == "yes" and conv("String", "Integer") == "no"
    assert conv("null", "String") == "yes" and conv("null", "int") == "no"
    assert conv("Sub", "Base") == "yes" and conv("Base", "Sub") == "no"
    assert conv("Unknown", "Base") == "maybe" and conv(None, "int") == "maybe"
    assert conv("byte[]", "byte[]") == "yes" and conv("int[]", "long[]") == "no"
    assert conv("byte[]", "Object") == "yes" and conv("byte[]", "String") == "no"


# ---- the bookkeeping itself ----------------------------------------------

def _proc(name, n, varargs=False):
    p = Procedure(name=name, params=[(None, None)] * n)
    p.has_varargs = varargs
    return p


def test_add_procedure_keeps_overloads_and_records_arities():
    prog = Program()
    a, b, c = _proc("A.f", 1), _proc("A.f", 2), _proc("A.f", 1, varargs=True)
    for p in (a, b, c):
        prog.add_procedure(p)
    assert [a.name, b.name, c.name] == ["A.f", "A.f#2", "A.f#3"]
    assert a.overload_arities == b.overload_arities == [(1, False), (2, False), (1, True)]
    assert a.simple_name == b.simple_name == c.simple_name == "f"
    # Two arguments: f(x, y) and the varargs f(x, ...) both accept -> ambiguous.
    assert not b.accepts_arity(2) and not c.accepts_arity(2)
    # Three arguments: only the varargs overload.
    assert c.accepts_arity(3) and not a.accepts_arity(3)
    # Re-adding the same object is a no-op.
    prog.add_procedure(a)
    assert len(prog.procedures) == 3


def test_unique_procedure_accepts_any_arity():
    prog = Program()
    p = _proc("A.g", 2)
    prog.add_procedure(p)
    assert p.name == "A.g" and p.accepts_arity(5) and p.overload_arities == []


@pytest.mark.parametrize("call", ["toInputStream(java.io.ByteArrayInputStream::new)",
                                  "toInputStream(1, 2)"])
def test_call_with_another_arity_is_an_inherited_overload_not_recursion(call):
    # commons-io ByteArrayOutputStream.toInputStream(): the 1-arg overload is
    # declared in the superclass, not in this file.
    code = ("class B extends AbstractB {\n"
            "  public java.io.InputStream toInputStream() {\n"
            f"    return {call};\n"
            "  }\n"
            "}\n")
    assert "CWE-674" not in cwes(code, "java", "B.java")


def test_same_arity_call_with_another_argument_type_is_not_recursion():
    # Tomcat ServletFileUpload.parseParameterMap(HttpServletRequest) delegates
    # to the inherited parseParameterMap(RequestContext).
    code = ("class U extends FileUploadBase {\n"
            "  public java.util.Map parseParameterMap(HttpServletRequest request) {\n"
            "    return parseParameterMap(new ServletRequestContext(request));\n"
            "  }\n"
            "}\n")
    assert "CWE-674" not in cwes(code, "java", "U.java")


def test_same_type_argument_is_still_recursion():
    code = ("class U {\n"
            "  int f(String s) {\n"
            "    String t = s + \"x\";\n"
            "    return f(t);\n"
            "  }\n"
            "}\n")
    assert "CWE-674" in cwes(code, "java", "U.java")


# ---- the expression types overload resolution relies on -------------------

def _call_arg_types(body, extra_fields=""):
    from frame.sil.frontends.java_frontend import JavaFrontend
    from frame.sil.instructions import Call
    code = ("class T {\n" + extra_fields +
            "  int own() {\n    return 1;\n  }\n"
            "  void f(int i, long l, String s, Integer boxed, byte[] bs, char c) {\n"
            f"    sink({body});\n"
            "  }\n"
            "}\n")
    program = JavaFrontend().translate(code, "T.java")
    calls = [i for p in program.procedures.values() for n in p.nodes.values()
             for i in n.instrs if isinstance(i, Call) and i.get_full_name() == "sink"]
    assert len(calls) == 1
    return calls[0].arg_types[0]


@pytest.mark.parametrize("expr,expected", [
    ("1", "int"), ("1L", "long"), ("1.5", "double"), ("1.5f", "float"), ("true", "boolean"),
    ("'x'", "char"), ("\"s\"", "String"), ("null", "null"),
    ("i", "int"), ("l", "long"), ("s", "String"), ("boxed", "Integer"), ("bs", "byte[]"),
    ("i - 1", "int"), ("i + l", "long"), ("c + 1", "int"), ("i * 2.0", "double"),
    ("boxed + 1", "int"), ("s + i", "String"), ("i < l", "boolean"), ("!true", "boolean"),
    ("-i", "int"), ("(long) i", "long"), ("(i)", "int"), ("i > 0 ? 1 : 2", "int"),
    ("new StringBuilder()", "StringBuilder"), ("new int[3]", "int[]"),
    ("s.trim()", "String"), ("s.length()", "int"), ("s.split(\",\")", "String[]"),
    ("own()", "int"), ("this.fld", "long"), ("this", "T"),
    ("unknown()", None), ("i > 0 ? s : null", None),
])
def test_java_expression_types(expr, expected):
    assert _call_arg_types(expr, "  long fld;\n") == expected
