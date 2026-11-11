"""Metamorphic tests for C and C++: a vulnerability rewritten without changing its meaning is still found.

The C/C++ side of tests/test_metamorphic.py. An adversarial review of the C frontend found
ordinary constructs lowered wrongly or not at all: a struct field written as a variable named
`<receiver>_<field>` that no read looked up, a labelled statement dropped with its body, `goto`
ending the path (so the code after the label was never analysed), a call written under a `(void)`
cast, in a ternary or `&&` statement, a comma list or any condition never becoming a call (so no
sink saw it), a `switch` condition skipped and its arms entered unguarded, `sizeof` read as 0, a
brace list that held a call or a field read lowered as its text, `new T(x)` dropping x, and in
C++ range-for, try/catch, `if (init; cond)` declarations, structured bindings, `os << x`, lambdas
bound to a name, namespace functions marked as methods of a class named after the namespace,
and a default-constructed container lowered as a null pointer.

Each seed flow (attacker data reaching a sink) is rewritten by every transform below and the
finding must survive; the same transform applied to a constant must stay clean, so a fix cannot
buy recall with noise. A guard written inside each construct must still clear the flow.

A transform Frame does not handle yet is in KNOWN_GAPS with the reason, as a strict xfail: fixing
it makes the test pass and CI asks for the entry to be removed. None is left: macro expansion, field
strong updates and path facts, struct fields through pointer arguments, lambda captures, constructor
and setter members, container elements and `using` resolution each have positives and their nearest
safe twins below.
"""

import re

import pytest

from frame.sil.scanner import FrameScanner

C_HEAD = """#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#define RUN(x) system(x)
struct S { char *name; struct S *next; int n; };
int run(int n) {
    char buf[64];
    char *q = getenv("Q");
{body}
    return 0;
}
"""
C_SINKS = {
    "CWE-78": "system(v);",
    "CWE-22": 'fopen(v, "r");',
}
# Each transform: statements that leave q's value in v.
C_TRANSFORMS = {
    "plain": ["char *v = q;"],
    "chained-assignment": ["char *v, *w;", "v = w = q;"],
    "chained-declaration": ["char *w;", "char *v = w = q;"],
    "comma-value": ["char *v;", "v = (n++, q);"],
    "comma-statement": ["char *v;", "n = 1, v = q;"],
    "ternary": ['char *v = q ? q : "x";'],
    "ternary-alternative": ['char *v = !q ? "x" : q;'],
    "cast": ["char *v = (char *)(void *)q;"],
    "parenthesized": ["char *v = ((q));"],
    "address-of-alias": ["char *w = q;", "char **pp = &w;", "char *v = *pp;"],
    "store-through-alias": ["char *w;", "char **pp = &w;", "*pp = q;", "char *v = w;"],
    "struct-field": ["struct S s;", "s.name = q;", "char *v = s.name;"],
    "struct-arrow": ["struct S s;", "struct S *p = &s;", "p->name = q;", "char *v = p->name;"],
    "struct-arrow-alias": ["struct S s;", "struct S *p = &s;", "p->name = q;", "char *v = s.name;"],
    "arrow-chain": ["struct S *p = malloc(sizeof *p);", "if (!p) return 1;", "p->next = p;",
                    "p->next->name = q;", "char *v = p->next->name;"],
    "struct-initializer": ["struct S s = { .name = q, .n = 1 };", "char *v = s.name;"],
    "struct-positional-initializer": ["struct S s = { q, NULL, 0 };", "char *v = s.name;"],
    "chained-field-assignment": ["struct S s;", "char *v = s.name = q;"],
    "field-overwritten-on-one-branch": ["struct S s;", 's.name = "x";', "if (n) s.name = q;", "char *v = s.name;"],
    "field-overwritten-then-tainted": ["struct S s;", "s.name = q;", 's.name = "x";', "s.name = q;",
                                       "char *v = s.name;"],
    "array-of-strings": ['char *arr[2] = {q, "x"};', "char *v = arr[0];"],
    "array-of-calls": ['char *arr[2] = {getenv("Q"), "x"};', "char *v = arr[0];"],
    "array-element-write": ["char *arr[2];", "arr[0] = q;", "char *v = arr[0];"],
    "do-while": ['char *v = "x";', "do {", "    v = q;", "} while (0);"],
    "switch-fallthrough": ['char *v = "x";', "switch (n) {", "case 0:", "    v = q;", "case 1:", "    break;",
                           "default:", "    break;", "}"],
    "switch-default": ['char *v = "x";', "switch (n) {", "case 0:", "    break;", "default:", "    v = q;", "}"],
    "switch-block": ['char *v = "x";', "switch (n) {", "case 0: {", "    v = q;", "    break;", "}", "}"],
    "goto": ['char *v = "x";', "goto L;", "L:", "    v = q;"],
    "goto-backward": ['char *v = "x";', "int tries = 0;", "again:", "if (tries++ < 2) goto again;", "v = q;"],
    "labeled": ['char *v = "x";', "L:", "    v = q;"],
    "for-multiple": ['char *v = "x";', "int i, j;", "for (i = 0, j = 1; i < n; i++, j++) {", "    v = q;", "}"],
    "for-init-assignment": ["char *v;", "int i;", "for (i = 0, v = q; i < n; i++) {", "}"],
    "for-update-assignment": ['char *v = "x";', "int i;", "for (i = 0; i < 1; i++, v = q) {", "}"],
    "for-init-call": ["char *v;", "for (v = strdup(q); n > 0; n--) {", "}"],
    "while": ['char *v = "x";', "while (n-- > 0) {", "    v = q;", "}"],
    "if-condition-assignment": ["char *v;", "if ((v = q) == NULL) {", "    return 1;", "}"],
    "while-condition-assignment": ["char *v;", "while ((v = q) != NULL) {", "    break;", "}"],
    "strcpy-into": ["char v[64];", "strcpy(v, q);"],
    "snprintf-into": ["char v[64];", 'snprintf(v, sizeof v, "ls %s", q);'],
    "memcpy-into": ["char v[64];", "memcpy(v, q, 10);"],
    "strdup": ["char *v = strdup(q);"],
    "pointer-arithmetic": ["char *v = q + 1;"],
    "if-else": ["char *v;", "if (n) {", "    v = q;", "} else {", '    v = "x";', "}"],
    "nested-block": ['char *v = "x";', "{", "    { v = q; }", "}"],
    "ifdef": ['char *v = "x";', "#ifdef X", "    v = q;", "#endif"],
    "if-else-preprocessor": ['char *v = "x";', "#if X", '    v = "y";', "#else", "    v = q;", "#endif"],
    "sizeof-branch": ['char *v = "x";', "if (sizeof(buf) > 4) v = q;"],
    "sizeof-loop": ['char *v = "x";', "for (size_t i = 0; i < sizeof(buf); i++) {", "    v = q;", "    break;", "}"],
}
# Sink calls written inside an expression or a statement other than a call statement.
C_INLINE = {
    "void-cast": ("(void)system(q);", "CWE-78"),
    "ternary-statement": ("n ? system(q) : 0;", "CWE-78"),
    "and-statement": ("n && system(q);", "CWE-78"),
    "or-statement": ("n || system(q);", "CWE-78"),
    "comma-call": ("n = 0, system(q);", "CWE-78"),
    "if-condition-call": ("if (system(q) != 0) { return 1; }", "CWE-78"),
    "while-condition-call": ("while (system(q)) { break; }", "CWE-78"),
    "for-condition-call": ("for (; system(q); ) { break; }", "CWE-78"),
    "do-condition-call": ("do { n++; } while (system(q));", "CWE-78"),
    "switch-condition-call": ("switch (system(q)) { default: break; }", "CWE-78"),
    "return-ternary-call": ("return n ? system(q) : 0;", "CWE-78"),
    "labeled-call": ("L: system(q);", "CWE-78"),
    "call-after-goto": ("goto L;\nL:\n    system(q);", "CWE-78"),
    "popen-cast": ('(void)popen(q, "r");', "CWE-78"),
    "execl-cast": ('(void)execl("/bin/sh", "sh", "-c", q, (char *)NULL);', "CWE-78"),
    "execv-shell-vector": ('char *args[] = {"/bin/sh", "-c", q, NULL};\n    execv("/bin/sh", args);', "CWE-78"),
    "execv-vector-written": ('char *args[4];\n    args[0] = "/bin/sh";\n    args[1] = "-c";\n    args[2] = q;\n'
                             '    args[3] = NULL;\n    execv("/bin/sh", args);', "CWE-78"),
    "fopen-condition": ('if (!fopen(q, "r")) return 1;', "CWE-22"),
    "function-macro": ("RUN(q);", "CWE-78"),
}

KNOWN_GAPS: dict = {
}


def _scan(code, lang="c"):
    r = FrameScanner(language=lang).scan(code, "a.c" if lang == "c" else "a.cpp")
    assert not r.errors, r.errors
    return {v.cwe_id for v in r.vulnerabilities}


def _c(lines, head=C_HEAD):
    return head.replace("{body}", "\n".join("    " + ln for ln in lines))


def _gap(name):
    reason = KNOWN_GAPS.get(name)
    return [pytest.mark.xfail(reason=reason, strict=True)] if reason else []


def _constant(lines):
    """The transform applied to a constant instead of the attacker's value."""
    return [re.sub(r'\bq\b|getenv\("Q"\)', '"localhost"', ln) for ln in lines]


@pytest.mark.parametrize("transform,cwe", [
    pytest.param(t, c, id=f"{t}-{c}", marks=_gap(t)) for t in C_TRANSFORMS for c in C_SINKS])
def test_c_flow_survives_the_rewrite(transform, cwe):
    assert cwe in _scan(_c(C_TRANSFORMS[transform] + [C_SINKS[cwe].replace("{v}", "v")]))


@pytest.mark.parametrize("transform", list(C_TRANSFORMS))
def test_c_rewrite_of_a_constant_stays_clean(transform):
    found = _scan(_c(_constant(C_TRANSFORMS[transform]) + list(C_SINKS.values())))
    assert not found & set(C_SINKS), found


@pytest.mark.parametrize("transform", [pytest.param(t, id=t, marks=_gap(t)) for t in C_INLINE])
def test_c_inline_flow_survives_the_rewrite(transform):
    stmt, cwe = C_INLINE[transform]
    assert cwe in _scan(_c([stmt]))


@pytest.mark.parametrize("transform", list(C_INLINE))
def test_c_inline_rewrite_of_a_constant_stays_clean(transform):
    stmt, cwe = C_INLINE[transform]
    assert cwe not in _scan(_c(_constant([stmt])))


# The nearest safe idioms: each must stay clean of the command / format / path findings.
_TAINT = {"CWE-78", "CWE-22", "CWE-134"}
C_SAFE = {
    # a guard written inside each construct still clears the flow (`q` is the checked value)
    "goto-guard": ['if (strcmp(q, "status") != 0) goto bad;', "system(q);", "return 0;", "bad:", "return 1;"],
    "labeled-guard": ["check:", 'if (strcmp(q, "status") != 0) return 1;', "system(q);"],
    "switch-condition-guard": ['switch (strcmp(q, "status")) {', "case 0: system(q); break;", "default: break;", "}"],
    "validation-loop-goto": ["for (char *p = q; *p; p++) {", "    if (!isalnum((unsigned char)*p)) goto bad;", "}",
                             "system(q);", "return 0;", "bad:", "return 1;"],
    "ternary-statement-guard": ['strcmp(q, "status") == 0 ? system(q) : 0;'],
    "and-statement-guard": ['strcmp(q, "status") == 0 && system(q);'],
    "or-statement-guard": ['strcmp(q, "status") != 0 || system(q);'],
    # a constant switch selects the safe case
    "switch-constant-selects-safe": ['char *v = q;', "switch (7) {", "case 6:", "    break;", "default:",
                                     '    v = "ls";', "}", "system(v);"],
    # an argument vector runs its program without a shell: the other elements are arguments
    "execv-vector-no-shell": ['char *args[] = {"/bin/ping", "-c", "1", q, NULL};', 'execv("/bin/ping", args);'],
    "execvp-vector-cast-no-shell": ['char *args[] = {"ping", "--", (char *)q, NULL};', 'execvp("ping", args);'],
    # bounded and numeric forms
    "snprintf-bounded": ['snprintf(buf, sizeof buf, "%s", q);', 'printf("%s", buf);'],
    "number": ["int k = atoi(q);", 'snprintf(buf, sizeof buf, "kill %d", k);', "system(buf);"],
    # the written value is a constant
    "field-constant": ["struct S s;", 's.name = "ls";', "system(s.name);"],
    "store-through-alias-constant": ["char *w = q;", "char **pp = &w;", '*pp = "ls";', "system(w);"],
    "field-strong-update": ["struct S s;", "s.name = q;", 's.name = "ls";', "system(s.name);"],
    # `p->name` with `p = &s` is `s.name`: one location, overwritten
    "field-strong-update-through-pointee": ["struct S s;", "struct S *p = &s;", "p->name = q;", 'p->name = "ls";',
                                            "system(s.name);"],
    # a macro whose expansion runs a constant / checks its argument first
    "macro-ignores-argument": ['#define SAFE_RUN(x) system("ls")', "SAFE_RUN(q);"],
    "macro-guarded": ['#define RUN_STATUS(x) do { if (strcmp(x, "status") == 0) system(x); } while (0)',
                      "RUN_STATUS(q);"],
}


@pytest.mark.parametrize("case", [pytest.param(c, id=c, marks=_gap(c)) for c in C_SAFE])
def test_c_safe_idiom_stays_clean(case):
    found = _scan(_c(C_SAFE[case]))
    assert not found & _TAINT, found


# Memory-safety findings through the same constructs (the heap, null, bounds and integer checks).
C_MEMORY = {
    "uaf-void-free": (["char *p = malloc(10);", "(void)free(p);", "p[0] = 'a';"], "CWE-416"),
    "uaf-after-label": (["char *p = malloc(10);", "free(p);", "goto out;", "out:", "p[0] = 'a';"], "CWE-416"),
    "uaf-labeled-statement": (["char *p = malloc(10);", "free(p);", "L: p[0] = 'a';"], "CWE-416"),
    "double-free-goto": (["char *p = malloc(10);", "if (n) {", "    free(p);", "    goto fail;", "}",
                          "return 1;", "fail:", "free(p);"], "CWE-415"),
    "double-free-ternary": (["char *p = malloc(10);", "free(p);", "n ? free(p) : (void)0;"], "CWE-415"),
    "double-free-comma": (["char *p = malloc(10);", "free(p);", "n = 1, free(p);"], "CWE-415"),
    "oob-labeled": (["int a[10];", "L: a[10] = 1;"], "CWE-787"),
    "oob-after-goto": (["int a[10];", "goto L;", "L:", "a[10] = 1;"], "CWE-787"),
    "oob-increment": (["int a[10];", "a[10]++;"], "CWE-787"),
    "integer-overflow-field": (["struct S s;", 's.n = atoi(getenv("N"));', "int m = s.n * 1000;",
                                "char *p = malloc(m);", "free(p);"], "CWE-190"),
    "format-void-cast": (['char *f = getenv("F");', "(void)printf(f);"], "CWE-134"),
    "uninit-labeled": (["int x;", "L: return x;"], "CWE-457"),
    "leak-on-goto": (["char *p = malloc(10);", "if (n) goto out;", "free(p);", "out:", "return 1;"], "CWE-401"),
    "field-null-path-fact": (["struct { char *p; } s;", "s.p = NULL;", "*s.p = 1;"], "CWE-476"),
    "field-null-subscript": (["struct { char *p; } s;", "s.p = NULL;", "s.p[0] = 1;"], "CWE-476"),
    "field-null-arrow": (["struct S s;", "s.next = NULL;", "s.next->n = 1;"], "CWE-476"),
}
C_MEMORY_SAFE = {
    "free-reallocated": (["char *p = malloc(10);", "free(p);", "p = malloc(10);", "if (!p) return 1;",
                          "p[0] = 'a';", "free(p);"], "CWE-416"),
    "free-once-per-path": (["char *p = malloc(10);", "if (n) goto fail;", "free(p);", "return 1;", "fail:",
                            "free(p);"], "CWE-415"),
    "null-checked-goto": (["char *p = malloc(4);", "if (p == NULL) goto out;", "*p = 1;", "free(p);", "out:",
                           "return 0;"], "CWE-476"),
    "in-bounds": (["int a[10];", "a[9] = 1;", "a[9]++;"], "CWE-787"),
    "init-after-goto": (["int x;", "goto L;", "L:", "x = 1;", "return x;"], "CWE-457"),
    "freed-after-label": (["char *p = malloc(10);", "if (n) goto out;", "p[0] = 1;", "out:", "free(p);"], "CWE-401"),
    "void-cast-free-no-leak": (["char *p = malloc(10);", "(void)free(p);"], "CWE-401"),
    # the field's null fact is decided per path, and forgotten when the field or its struct changes
    "field-null-checked": (["struct { char *p; } s;", "s.p = NULL;", "if (s.p) *s.p = 1;"], "CWE-476"),
    "field-reassigned": (["struct { char *p; } s;", "s.p = NULL;", "s.p = buf;", "*s.p = 1;"], "CWE-476"),
    "field-struct-reassigned": (["struct S s, t;", "s.name = NULL;", "t.name = buf;", "s = t;", "*s.name = 1;"],
                                "CWE-476"),
    "field-struct-escapes": (["struct S s;", "s.name = NULL;", "struct S *p = &s;", "p->next = NULL;",
                              "scanf(\"%p\", &s.name);", "*s.name = 1;"], "CWE-476"),
}


@pytest.mark.parametrize("case", [pytest.param(c, id=c, marks=_gap(c)) for c in C_MEMORY])
def test_c_memory_finding_survives_the_rewrite(case):
    lines, cwe = C_MEMORY[case]
    assert cwe in _scan(_c(lines))


@pytest.mark.parametrize("case", list(C_MEMORY_SAFE))
def test_c_memory_safe_rewrite_stays_clean(case):
    lines, cwe = C_MEMORY_SAFE[case]
    assert cwe not in _scan(_c(lines))


# ---------------------------------------------------------------------------------------------
# C++

CPP_HEAD = """#include <cstdlib>
#include <cstdio>
#include <cstring>
#include <string>
#include <sstream>
#include <vector>
#include <memory>
#include <map>
struct Box { std::string s; char *p; };
class Runner {
public:
    std::string cmd;
    Runner(const std::string &c) : cmd(c) {}
    void go() { std::system(this->cmd.c_str()); }
    void set(const char *c) { this->cmd = c; }
};
namespace ns { inline void sh(const char *c) { system(c); } }
template <typename T> void tsh(T c) { system(c); }
int run(int n) {
    const char *q = std::getenv("Q");
{body}
    return 0;
}
"""
CPP_SINK = "system(v);"
CPP_TRANSFORMS = {
    "plain": ["const char *v = q;"],
    "auto": ["auto v = q;"],
    "auto-reference": ["const auto &w = q;", "auto v = w;"],
    "reference": ["const char *w = q;", "const char *&r = w;", "const char *v = r;"],
    "string-c-str": ["std::string s = q;", "const char *v = s.c_str();"],
    "string-constructor": ["std::string s(q);", "const char *v = s.c_str();"],
    "string-braces": ["std::string s{q};", "const char *v = s.c_str();"],
    "string-concatenation": ['std::string s = std::string("ls ") + q;', "const char *v = s.c_str();"],
    "string-plus-assign": ['std::string s = "ls ";', "s += q;", "const char *v = s.c_str();"],
    "string-append": ['std::string s = "ls ";', "s.append(q);", "const char *v = s.c_str();"],
    "ostringstream": ["std::ostringstream os;", 'os << "ls " << q;', "std::string s = os.str();",
                      "const char *v = s.c_str();"],
    "range-for": ["std::vector<std::string> xs{q};", 'const char *v = "x";', "for (const auto &x : xs) {",
                  "    v = x.c_str();", "}"],
    "range-for-array": ["const char *arr[] = {q};", 'const char *v = "x";', "for (auto x : arr) {", "    v = x;", "}"],
    "structured-binding": ["std::pair<const char *, int> pr{q, 1};", "auto [first, second] = pr;",
                           "const char *v = first;"],
    "new-expression": ["char *w = new char[64];", "strcpy(w, q);", "char *v = w;"],
    "new-constructor-arguments": ["std::unique_ptr<std::string> u(new std::string(q));", "const char *v = u->c_str();"],
    "make-unique": ["auto u = std::make_unique<std::string>(q);", "const char *v = u->c_str();"],
    "member-field": ['Runner r("x");', "r.cmd = q;", "const char *v = r.cmd.c_str();"],
    "struct-field": ["Box b;", "b.p = (char *)q;", "const char *v = b.p;"],
    "struct-pointer-field": ["Box *b = new Box();", "b->p = (char *)q;", "const char *v = b->p;"],
    "static-cast": ["const char *v = static_cast<const char *>(q);"],
    "reinterpret-cast": ["const char *v = reinterpret_cast<const char *>(q);"],
    "const-cast": ["char *v = const_cast<char *>(q);"],
    "try": ['const char *v = "x";', "try {", "    v = q;", "} catch (...) {", "}"],
    "catch": ['const char *v = "x";', "try {", "    n = 1;", "} catch (const std::exception &e) {", "    v = q;", "}"],
    "if-declaration": ['const char *v = "x";', "if (const char *t = q) {", "    v = t;", "}"],
    "if-init-statement": ['const char *v = "x";', "if (const char *t = q; t != nullptr) {", "    v = t;", "}"],
    "nullptr-ternary": ['const char *v = q != nullptr ? q : "x";'],
    "string-ternary": ['std::string s = n ? std::string(q) : std::string("x");', "const char *v = s.c_str();"],
}
# Calls that reach the sink through a C++ construct.
CPP_CALLS = {
    "namespace-function": ["ns::sh(q);"],
    "template-function": ["tsh(q);"],
    "lambda-bound-to-name": ["auto f = [](const char *c) { system(c); };", "f(q);"],
    "throw-after-sink": ["system(q);", "if (n) throw 1;"],
    "cpp-lambda-capture": ["auto f = [&]() { return q; };", "system(f());"],
    "cpp-constructor-field": ["Runner r(q);", "r.go();"],
    "cpp-container-element": ["std::vector<std::string> xs;", "xs.push_back(q);", "system(xs[0].c_str());"],
    "lambda-copy-capture": ["auto f = [q]() { system(q); };", "f();"],
    "lambda-default-copy-capture": ["auto f = [=]() { system(q); };", "f();"],
    "lambda-init-capture": ["auto f = [c = q]() { system(c); };", "f();"],
    "lambda-returns-captured": ["auto f = [q]() { return q; };", "const char *v = f();", "system(v);"],
    "setter-field": ['Runner r("x");', "r.set(q);", "r.go();"],
    "container-emplace-back": ["std::vector<std::string> xs;", "xs.emplace_back(q);", "system(xs.at(0).c_str());"],
    "container-insert": ["std::vector<std::string> xs;", "xs.insert(xs.end(), q);", "system(xs.front().c_str());"],
    "container-range-for": ["std::vector<std::string> xs;", "xs.push_back(q);", "for (const auto &x : xs) {",
                            "    system(x.c_str());", "}"],
    "container-deque-front": ["std::deque<std::string> xs;", "xs.push_front(q);", "system(xs.front().c_str());"],
    "map-subscript-write": ["std::map<std::string, std::string> m;", 'm["k"] = q;', 'system(m["k"].c_str());'],
    "map-insert": ["std::map<std::string, std::string> m;", 'm.insert({"k", q});', 'system(m.at("k").c_str());'],
}
CPP_SAFE = {
    "guard-in-try": ["try {", '    if (strcmp(q, "status") != 0) return 1;', "} catch (...) {", "    return 1;", "}",
                     "system(q);"],
    "guard-after-if-init": ['if (size_t k = strlen(q); strcmp(q, "status") != 0) return 1;', "system(q);"],
    "guard-in-switch-init": ['switch (int k = 0; strcmp(q, "status")) {', "case 0: system(q); break;",
                             "default: break;", "}"],
    "throw-guard": ['if (strcmp(q, "status") != 0) throw 1;', "system(q);"],
    "lambda-given-constant": ["auto f = [](const char *c) { system(c); };", 'f("ls");'],
    # a lambda reads only what it captures: q is not captured, its own constant is run
    "lambda-captures-other": ['const char *k = "ls";', "auto f = [k]() { system(k); };", "f();"],
    # another container holds the attacker's element
    "container-other": ["std::vector<std::string> xs, ys;", "xs.push_back(q);", 'ys.push_back("ls");',
                        "system(ys[0].c_str());"],
}
# A default-constructed object is not a null pointer.
CPP_OBJECTS = {
    "vector-subscript": ["std::vector<int> xs;", "xs.push_back(1);", "return xs[0];"],
    "map-subscript": ["std::map<std::string, int> m;", 'm["k"] = 1;', 'return m["k"];'],
    "string-subscript": ["std::string s;", 's += "a";', "return s[0];"],
}


def _cpp(lines):
    return CPP_HEAD.replace("{body}", "\n".join("    " + ln for ln in lines))


@pytest.mark.parametrize("transform", [pytest.param(t, id=t, marks=_gap(t)) for t in CPP_TRANSFORMS])
def test_cpp_flow_survives_the_rewrite(transform):
    assert "CWE-78" in _scan(_cpp(CPP_TRANSFORMS[transform] + [CPP_SINK]), "cpp")


@pytest.mark.parametrize("transform", list(CPP_TRANSFORMS))
def test_cpp_rewrite_of_a_constant_stays_clean(transform):
    assert "CWE-78" not in _scan(_cpp(_constant(CPP_TRANSFORMS[transform]) + [CPP_SINK]), "cpp")


@pytest.mark.parametrize("case", [pytest.param(c, id=c, marks=_gap(c)) for c in CPP_CALLS])
def test_cpp_call_reaches_the_sink(case):
    assert "CWE-78" in _scan(_cpp(CPP_CALLS[case]), "cpp")


@pytest.mark.parametrize("case", list(CPP_CALLS))
def test_cpp_call_of_a_constant_stays_clean(case):
    assert "CWE-78" not in _scan(_cpp(_constant(CPP_CALLS[case])), "cpp")


@pytest.mark.parametrize("case", list(CPP_SAFE))
def test_cpp_safe_idiom_stays_clean(case):
    assert "CWE-78" not in _scan(_cpp(CPP_SAFE[case]), "cpp")


@pytest.mark.parametrize("case", list(CPP_OBJECTS))
def test_cpp_default_constructed_object_is_not_null(case):
    assert "CWE-476" not in _scan(_cpp(CPP_OBJECTS[case]), "cpp")


# Whole programs: the flow crosses a function, a method or a macro.
PROGRAMS = {
    "cpp-this-method": ("cpp", '''#include <cstdlib>
class H { public:
  void handle() { const char *q = std::getenv("Q"); this->run(q); }
  void run(const char *c) { system(c); } };'''),
    "cpp-unqualified-method": ("cpp", '''#include <cstdlib>
class H { public:
  void handle() { const char *q = std::getenv("Q"); run(q); }
  void run(const char *c) { system(c); } };'''),
    "cpp-out-of-line-method": ("cpp", '''#include <cstdlib>
class H { public: void handle(); void run(const char *c); };
void H::handle() { const char *q = std::getenv("Q"); run(q); }
void H::run(const char *c) { system(c); }'''),
    "cpp-object-method": ("cpp", '''#include <cstdlib>
class H { public: void run(const char *c) { system(c); } };
void go() { H h; h.run(std::getenv("Q")); }'''),
    "cpp-this-field": ("cpp", '''#include <cstdlib>
#include <string>
class H { public: std::string cmd;
  void handle() { this->cmd = std::getenv("Q"); system(this->cmd.c_str()); } };'''),
    "c-object-macro": ("c", '''#include <stdlib.h>
#define ARG data
void run(void) { char *data = getenv("Q"); system(ARG); }'''),
    "c-object-macro-callee": ("c", '''#include <stdlib.h>
#define run_shell system
void run(void) { run_shell(getenv("Q")); }'''),
    "c-global-struct-field": ("c", '''#include <stdlib.h>
struct C { char *cmd; } cfg;
void run(void) { cfg.cmd = getenv("Q"); system(cfg.cmd); }'''),
    "c-field-through-pointer-argument": ("c", '''#include <stdlib.h>
struct C { char *cmd; };
static void go(struct C *c) { system(c->cmd); }
void run(void) { struct C c; c.cmd = getenv("Q"); go(&c); }'''),
    "c-field-filled-by-callee": ("c", '''#include <stdlib.h>
struct C { char *cmd; };
static void fill(struct C *c) { c->cmd = getenv("Q"); }
void run(void) { struct C c; fill(&c); system(c.cmd); }'''),
    "c-field-by-value-argument": ("c", '''#include <stdlib.h>
struct C { char *cmd; };
static void go(struct C c) { system(c.cmd); }
void run(void) { struct C c; c.cmd = getenv("Q"); go(c); }'''),
    "c-value-macro": ("c", '''#include <stdlib.h>
#define INPUT() getenv("Q")
void run(void) { char *v = INPUT(); system(v); }'''),
    "c-statement-macro": ("c", '''#include <stdlib.h>
#define SH(c) do { if (c) system(c); } while (0)
void run(void) { SH(getenv("Q")); }'''),
    "c-nested-macro": ("c", '''#include <stdlib.h>
#define INNER(x) system(x)
#define OUTER(x) INNER(x)
void run(void) { OUTER(getenv("Q")); }'''),
    "c-pasting-macro": ("c", '''#include <stdlib.h>
#define CALL(f, ...) f(__VA_ARGS__)
#define SYS(x) sys ## tem(x)
void run(void) { CALL(SYS, getenv("Q")); }'''),
    "cpp-using-declaration": ("cpp", '''#include <cstdlib>
namespace ns { void sh(const char *c) { system(c); } }
using ns::sh;
void run() { sh(std::getenv("Q")); }'''),
    "cpp-using-namespace": ("cpp", '''#include <cstdlib>
namespace ns { void sh(const char *c) { system(c); } }
void run() { using namespace ns; sh(std::getenv("Q")); }'''),
}
# The nearest safe programs: each must stay clean of CWE-78.
SAFE_PROGRAMS = {
    # a callee given a copy writes the copy, never the caller's struct
    "c-field-filled-in-a-copy": ("c", '''#include <stdlib.h>
struct C { char *cmd; };
static void fill(struct C c) { c.cmd = getenv("Q"); }
void run(void) { struct C c; c.cmd = "ls"; fill(c); system(c.cmd); }'''),
    # the caller overwrites what the callee filled in
    "c-field-filled-then-overwritten": ("c", '''#include <stdlib.h>
struct C { char *cmd; };
static void fill(struct C *c) { c->cmd = getenv("Q"); }
void run(void) { struct C c; fill(&c); c.cmd = "ls"; system(c.cmd); }'''),
    # the callee reads a field the caller did not taint
    "c-other-field-through-pointer": ("c", '''#include <stdlib.h>
struct C { char *cmd; char *name; };
static void go(struct C *c) { system(c->cmd); }
void run(void) { struct C c; c.cmd = "ls"; c.name = getenv("Q"); go(&c); }'''),
    # a macro that recurses is expanded once and never again (no hang, no invented call)
    "c-recursive-macro": ("c", '''#include <stdlib.h>
#define LOOP(x) LOOP(x)
void run(void) { LOOP(getenv("Q")); }'''),
    # a macro defined twice (two #ifdef arms): which applies is unknown, so it is not expanded
    "c-macro-defined-twice": ("c", '''#include <stdlib.h>
#ifdef A
#define RUN(x) system(x)
#else
#define RUN(x) puts(x)
#endif
void run(void) { RUN(getenv("Q")); }'''),
    # without the using-directive in force the call is the global function
    "cpp-using-out-of-scope": ("cpp", '''#include <cstdlib>
#include <cstdio>
namespace ns { void sh(const char *c) { system(c); } }
void other() { using namespace ns; }
void sh(const char *c) { puts(c); }
void run() { sh(std::getenv("Q")); }'''),
    # the constructor stores a constant; the setter is never called with attacker data
    "cpp-member-set-to-constant": ("cpp", '''#include <cstdlib>
#include <string>
class R { public: std::string cmd; R(const char *c) : cmd("ls") { (void)c; } void go() { system(cmd.c_str()); } };
void run() { R r(std::getenv("Q")); r.go(); }'''),
}


@pytest.mark.parametrize("case", [pytest.param(c, id=c, marks=_gap(c)) for c in PROGRAMS])
def test_program_flow_is_found(case):
    lang, code = PROGRAMS[case]
    assert "CWE-78" in _scan(code, lang)


@pytest.mark.parametrize("case", list(PROGRAMS))
def test_program_with_a_constant_stays_clean(case):
    lang, code = PROGRAMS[case]
    assert "CWE-78" not in _scan(re.sub(r'(?:std::)?getenv\("Q"\)', '"ls"', code), lang)


@pytest.mark.parametrize("case", list(SAFE_PROGRAMS))
def test_safe_program_stays_clean(case):
    lang, code = SAFE_PROGRAMS[case]
    assert "CWE-78" not in _scan(code, lang)


def test_cpp_call_through_using_namespace():
    code = ("#include <cstdlib>\nnamespace ns { void sh(const char *c) { system(c); } }\nusing namespace ns;\n"
            'void run() { const char *q = std::getenv("Q"); sh(q); }\n')
    assert "CWE-78" in _scan(code, "cpp")
