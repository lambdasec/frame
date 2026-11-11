"""No C or C++ syntax silently loses data on its way to SIL (the C/C++ side of tests/test_lowering_coverage.py).

The C frontend lowers each expression node it knows; anything else falls back to a variable named
by the node's source text, so whatever data the node carried is lost without a trace. A brace list
holding a call or a field read, `new T(x)`, a declaration used as a condition and a raw string
were lowered that way, and whole statements were dropped (labelled statements, C++ range-for,
try/catch, throw, `[[attribute]]` statements). The frontend records every node type that reaches
the fallback, every statement kind it has no lowering for (`statement:<type>`), every assignment
target it cannot write (`assignment:<type>`) and every declarator it cannot name
(`declarator:<type>`) in `Program.unlowered_syntax`; a syntax zoo of everyday forms must reach it
only with node types that carry no data.
"""

import pytest

from frame.sil.frontends.c_frontend import CFrontend, CppFrontend

# Node types that may reach the fallback: they carry no data a finding could depend on.
C_ALLOWED: set = set()
CPP_ALLOWED: set = set()

C_ZOO = r'''
#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define RUN(x) system(x)
#define N 16
struct S { char *name; struct S *next; int n; char data[8]; };
struct P { int x; int y; };
union U { int i; char c; };
enum E { A, B };
typedef int myint;
static int g;
int run(int argc, char **argv, struct S *sp, ...) {
    char buf[N];
    char *q = getenv("Q");
    char *a, *b;
    a = b = q;
    int n = 0, m = 1;
    n += 2; n -= 1; n *= 3; n /= 2; n %= 5; n <<= 1; n >>= 1; n &= 7; n |= 8; n ^= 1;
    n++; --m; n = (m++, n);
    char *t = n ? q : "x";
    char *u = n ?: q;
    char *v = (char *)(void *)q;
    char **pp = &a;
    *pp = q;
    struct S s = { .name = q, .n = 1 };
    struct S s2 = { q, 0 };
    struct S *p = &s;
    p->next = sp;
    p->next->name = q;
    s.n++;
    sp->n--;
    s.data[0] = 'x';
    p->data[1] = q[0];
    char *arr[] = { q, "x", NULL };
    int nums[3] = { 1, 2, 3 };
    int grid[2][2] = { { 1, 2 }, { 3, 4 } };
    grid[1][1] = 5;
    arr[1] = q;
    nums[n % 3] += 1;
    (*pp)[0] = 'a';
    union U un;
    un.i = 3;
    enum E e = B;
    myint mi = (myint)n;
    size_t len = sizeof(buf) + sizeof buf + sizeof(struct S) + sizeof(int);
    const char *lit = "a" "b";
    char *cl = (char[]){ 'a', 'b', 0 };
    struct S *lit2 = &(struct S){ .name = q };
    va_list ap;
    va_start(ap, sp);
    int va = va_arg(ap, int);
    va_end(ap);
    size_t off = offsetof(struct P, y);
    int gen = _Generic(n, int: 1, default: 0);
    char c = "abc"[1];
    if (n > 1 && m < 2 || !q) { n = 0; } else if (n) { n = 1; } else n = 2;
    while (n-- > 0) { if (n == 3) continue; if (n == 2) break; }
    do { n++; } while (n < 3);
    for (int i = 0, j = 1; i < N; i++, j++) { buf[i] = 0; }
    for (;;) { break; }
    switch (n) {
    case 0:
        n = 1;
    case 1: {
        n = 2;
        break;
    }
    default:
        break;
    }
    goto done;
done:
    ;
    n ? (void)RUN(q) : (void)0;
    n && system(q);
    (void)printf("%s", q);
    strcpy(buf, q);
    snprintf(buf, sizeof buf, "%s", q);
    int r = (int)strlen(q) > 3 ? 1 : -1;
    g = r;
lab:
    n = 0;
#ifdef X
    n = 1;
#else
    n = 2;
#endif
    return a[0] + b[0] + t[0] + u[0] + v[0] + (int)len + lit[0] + cl[0] + lit2->n + mi + e + un.c + s2.n
        + grid[0][0] + va + (int)off + gen + c;
}
'''

CPP_ZOO = r'''
#include <chrono>
#include <cstdlib>
#include <functional>
#include <map>
#include <memory>
#include <sstream>
#include <string>
#include <vector>
using namespace std::string_literals;
namespace ns { inline int f(int x) { return x; } }
enum class Color { Red, Green };
template <typename T> T id(T x) { return x; }
template <typename... Args> int count(Args... args) { return sizeof...(Args) + (args + ... + 0); }
struct Box { std::string s; int n = 0; Box(const std::string &v) : s(v), n(1) {} int get() const { return this->n; } };
class Runner : public Box {
public:
    using Box::Box;
    void go() { std::system(this->s.c_str()); }
};
int run(const char *q, std::vector<std::string> xs, std::map<std::string, int> m, Color c) {
    auto a = std::string(q);
    std::string b{q};
    std::string cs(q);
    const std::string &r = b;
    auto &r2 = cs;
    std::ostringstream os;
    os << "x" << q << 1;
    std::string s = os.str() + a + r + r2;
    s += q;
    for (const auto &x : xs) { s += x; }
    for (auto &[k, v] : m) { s += k; v++; }
    for (auto x : {1, 2, 3}) { (void)x; }
    auto [first, second] = std::make_pair(q, 1);
    auto f = [&](int z) -> int { return z + (int)s.size(); };
    auto g = [=]() mutable { return q; };
    int n = f(1) + ns::f(2) + id<int>(3) + count(1, 2) + second;
    std::unique_ptr<Box> up(new Box(q));
    auto sp = std::make_shared<Runner>(q);
    Box *raw = new Box{q};
    int *arr = new int[n];
    delete raw;
    delete[] arr;
    up->n = static_cast<int>(n);
    long l = reinterpret_cast<long>(q);
    const char *cc = const_cast<char *>(q);
    Box *dyn = dynamic_cast<Box *>(up.get());
    if (auto it = m.find(s); it != m.end()) { n += it->second; }
    if (const char *t = q) { s += t; }
    switch (int k = n; k) { case 1: n = 2; break; default: break; }
    try { n = std::stoi(s); } catch (const std::exception &e) { n = -1; } catch (...) { throw; }
    if (n < 0) throw std::runtime_error("bad");
    std::function<int(int)> fn = f;
    bool ok = n == 0 ? true : false;
    bool found = s.find("x") != std::string::npos;
    bool red = c == Color::Red;
    auto rawstr = R"(C:\path)";
    auto lit = "abc"s;
    auto ms = std::chrono::milliseconds(5);
    auto *pn = &n;
    *pn = sizeof(Box);
    std::vector<int> v{1, 2, 3};
    v.push_back(n);
    m[s] = n;
    sp->go();
    [[maybe_unused]] int unused = 0;
    static_assert(sizeof(int) >= 2, "int");
    using Str = std::string;
    Str alias = s;
    n += alignof(int) + (int)noexcept(n);
    int *np = nullptr;
    return n + l + (cc ? 1 : 0) + (dyn ? 1 : 0) + (ok ? 1 : 0) + (int)alias.size() + (g() ? 1 : 0) + fn(2)
        + (found ? 1 : 0) + (red ? 1 : 0) + rawstr[0] + (int)lit.size() + (int)ms.count() + (np ? 1 : 0)
        + (first ? 1 : 0);
}
'''


@pytest.mark.parametrize("frontend,code,name,allowed", [
    pytest.param(CFrontend, C_ZOO, "zoo.c", C_ALLOWED, id="c"),
    pytest.param(CppFrontend, CPP_ZOO, "zoo.cpp", CPP_ALLOWED, id="cpp"),
])
def test_zoo_lowers_every_data_carrying_node(frontend, code, name, allowed):
    program = frontend().translate(code, name)
    assert program.syntax_error_line is None, "the zoo must parse"
    unexpected = {k: n for k, n in (program.unlowered_syntax or {}).items() if k not in allowed}
    assert not unexpected, f"node types lowered as their source text (or dropped): {unexpected}"


def test_the_fallback_is_recorded():
    # The tripwire itself: a construct the frontend does not lower must show up.
    program = CFrontend().translate('int f(void) { int x; asm("mov %1, %0" : "=r"(x) : "r"(1)); return x; }',
                                    "a.c")
    assert "gnu_asm_expression" in (program.unlowered_syntax or {})


def test_an_unknown_statement_is_recorded():
    program = CppFrontend().translate("int f() { co_return 1; }", "a.cpp")
    assert any(k.startswith("statement:") for k in (program.unlowered_syntax or {}))
