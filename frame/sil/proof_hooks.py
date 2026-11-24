"""Call-site argument hooks: the spy for Java and C# sinks that cannot be proxied.

The Java and C# reproduction runners spy an injected sink INTERFACE with a dynamic proxy.
A sink the project calls directly -- a JDK or .NET static method (`Runtime.exec`,
`Process.Start`), a constructor (`new ObjectInputStream(..)`), a method of a concrete or
sealed library class -- has no seam to put a proxy in, and replacing its code needs bytecode
or IL instrumentation, which CI runtimes refuse to attach at run time.

Both runners compile the project from source, so the spy goes in the source instead: in the
temporary copy, every argument of the sink call at the flagged call site is wrapped in an
identity function (`frameproof.Spy.arg(x)` in Java, `global::FrameProof.Spy.Arg(x)` in C#).
The wrapper returns its argument unchanged, so the program means what it meant, except that
when an argument carries the marker it records the hit and throws, so the sink never runs
with attacker data. The hook sits in the project's own call, so a hit proves the marker
reached that call through the project; a driver that calls the sink itself is never
wrapped. Pure core-library code: nothing is downloaded or attached.

Calls are found in the syntax tree (tree-sitter), never in the text: the invocations named
like the sink method, or the object creations of the sink's type, on the call-site line.
When the line holds none (a fixed copy where the call moved), every such call in the file
is hooked, so a fix that only shifts lines is not mistaken for one that removed the flow.
Literals, lambdas, method references and `ref`/`out` arguments are left alone: they carry
no attacker data, and wrapping them could change overload resolution or inference.
"""

from __future__ import annotations

from typing import List, NamedTuple, Optional, Tuple

CONSTRUCTOR_NAMES = {"<init>", ".ctor", "ctor", "new", "constructor"}


class Sink(NamedTuple):
    type_name: str          # simple type name ("Runtime", "Process", "ObjectInputStream")
    method: str             # method name, or "" for a constructor


class Hooked(NamedTuple):
    source: str
    calls: int              # how many sink calls were hooked
    on_line: bool           # True when they were on the call-site line


def sink_of(function: str) -> Optional[Sink]:
    """The sink's simple type and method from a canonical id (`java.lang.Runtime.exec`,
    `System.Diagnostics.Process.Start`, `java.io.ObjectInputStream.<init>`, `new X`)."""
    fn = (function or "").replace("/", ".").replace("::", ".").strip().strip(".")
    if fn.startswith("new "):
        return Sink(_simple(fn[4:]), "") if fn[4:].strip() else None
    if "." not in fn:
        return None
    head, _, last = fn.rpartition(".")
    if last in CONSTRUCTOR_NAMES:
        return Sink(_simple(head), "") if head else None
    if head.endswith(".<init>") or head.endswith(".ctor"):
        return None
    return Sink(_simple(head), last)


def _simple(type_text: str) -> str:
    t = type_text.split("<", 1)[0].strip()
    return t.rsplit(".", 1)[-1]


def _parser(language: str):
    import tree_sitter
    if language == "java":
        import tree_sitter_java as grammar
    else:
        import tree_sitter_c_sharp as grammar
    lang = tree_sitter.Language(grammar.language())
    try:
        return tree_sitter.Parser(lang)
    except TypeError:                               # older bindings
        p = tree_sitter.Parser()
        p.set_language(lang)
        return p


_INVOCATION = {"java": "method_invocation", "csharp": "invocation_expression"}
_CREATION = {"java": ("object_creation_expression",),
             "csharp": ("object_creation_expression",)}
_SKIP_ARG = {"lambda_expression", "method_reference", "anonymous_method_expression",
             "implicit_object_creation_expression", "default_expression",
             "collection_expression", "stackalloc_expression", "null_literal", "true", "false"}
_WRAP = {"java": "frameproof.Spy.arg(", "csharp": "global::FrameProof.Spy.Arg("}


def _call_name(node, language: str) -> str:
    if language == "java":
        name = node.child_by_field_name("name")
        return name.text.decode("utf-8", "replace") if name is not None else ""
    fn = node.child_by_field_name("function")
    while fn is not None and fn.type in ("member_access_expression", "conditional_access_expression",
                                         "member_binding_expression"):
        fn = fn.child_by_field_name("name") or (fn.named_children[-1] if fn.named_children else None)
    if fn is not None and fn.type == "generic_name":
        fn = fn.named_children[0] if fn.named_children else None
    return fn.text.decode("utf-8", "replace") if fn is not None else ""


def _created_type(node) -> str:
    t = node.child_by_field_name("type")
    return _simple(t.text.decode("utf-8", "replace")) if t is not None else ""


def _arguments(node, language: str) -> List:
    """The argument expressions of a call that may carry data, in source order."""
    args = node.child_by_field_name("arguments")
    if args is None:
        return []
    out = []
    for a in args.named_children:
        expr = a
        if language == "csharp":
            if a.type != "argument":
                continue
            if any(c.type in ("ref", "out", "in") for c in a.children):
                continue
            expr = a.named_children[-1] if a.named_children else None
            if expr is None:
                continue
        if expr.type in _SKIP_ARG or expr.type.endswith("literal") and expr.type != "interpolated_string_expression":
            continue
        out.append(expr)
    return out


def _sink_calls(root, language: str, sink: Sink) -> List:
    kinds = _CREATION[language] if not sink.method else (_INVOCATION[language],)
    found, stack = [], [root]
    while stack:
        n = stack.pop()
        if n.type in kinds:
            if sink.method and _call_name(n, language) == sink.method:
                found.append(n)
            elif not sink.method and _created_type(n) == sink.type_name:
                found.append(n)
        stack.extend(n.children)
    return found


def hook_call_site(source: str, language: str, line: int, sink: Sink) -> Optional[Hooked]:
    """Wrap the arguments of the sink calls at ``line`` (1-based) of ``source``, or of every
    sink call in the file when the line has none. None when the file has no such call."""
    language = "java" if language == "java" else "csharp"
    data = source.encode("utf-8")
    tree = _parser(language).parse(data)
    calls = _sink_calls(tree.root_node, language, sink)
    if not calls:
        return None
    here = [c for c in calls if c.start_point[0] + 1 <= line <= c.end_point[0] + 1]
    chosen = here or calls
    edits: List[Tuple[int, int, str]] = []       # (position, order, text)
    for call in chosen:
        for arg in _arguments(call, language):
            edits.append((arg.start_byte, 1, _WRAP[language]))
            edits.append((arg.end_byte, 0, ")"))
    if not edits:
        return None
    # apply from the end; at one position close an inner wrap before opening the next
    out = data
    for pos, _order, text in sorted(edits, key=lambda e: (e[0], e[1]), reverse=True):
        out = out[:pos] + text.encode("utf-8") + out[pos:]
    return Hooked(out.decode("utf-8"), len(chosen), bool(here))


# The generated Java `Main` exits with this when the driver ran and the marker did not reach
# the sink; any other failing exit (a missing class, a JVM error) means it did not run.
JAVA_NOT_REACHED = 3


JAVA_SPY = """package frameproof;

/** Generated by Frame: records attacker-marked data reaching a hooked sink call. */
public final class Spy {
    public static String MARKER = "";
    public static String CALLSITE = "";
    public static volatile boolean seen = false;
    public static volatile boolean via = false;

    /** Thrown once the marker is seen, so the sink never runs with it. */
    public static final class Stop extends Error {
        public Stop() { super("frame: marker reached the sink"); }
    }

    public static <T> T arg(T v) { check(v); return v; }
    public static boolean arg(boolean v) { return v; }
    public static char arg(char v) { return v; }
    public static byte arg(byte v) { return v; }
    public static short arg(short v) { return v; }
    public static int arg(int v) { return v; }
    public static long arg(long v) { return v; }
    public static float arg(float v) { return v; }
    public static double arg(double v) { return v; }

    static void check(Object v) {
        if (!carries(v)) return;
        StackTraceElement[] st = Thread.currentThread().getStackTrace();
        // [0] getStackTrace, [1] check, [2] arg, [3] the hooked call
        String caller = st.length > 3 ? st[3].getClassName() : "";
        String simple = caller.substring(caller.lastIndexOf('.') + 1);
        seen = true;
        via = simple.equals(CALLSITE) || simple.startsWith(CALLSITE + "$");
        throw new Stop();
    }

    static boolean carries(Object v) {
        if (v == null) return false;
        String s;
        if (v instanceof byte[]) s = new String((byte[]) v, java.nio.charset.StandardCharsets.ISO_8859_1);
        else if (v instanceof char[]) s = new String((char[]) v);
        else if (v instanceof Object[]) s = java.util.Arrays.deepToString((Object[]) v);
        else s = String.valueOf(v);
        return s.contains(MARKER);
    }
}
"""


def java_hook_main(driver: str, callsite_class: str, marker: str) -> str:
    """`Main.java` for a hooked sink: run the driver, exit 0 only when the marker reached the
    hooked call from the call-site class."""
    body = "\n            ".join(driver.splitlines()) or ";"
    return (
        "public class Main {\n"
        f"    static final String MARKER = \"{marker}\";\n"
        f"    static final int NOT_REACHED = {JAVA_NOT_REACHED};\n"
        "    public static void main(String[] args) {\n"
        "        frameproof.Spy.MARKER = MARKER;\n"
        f"        frameproof.Spy.CALLSITE = \"{callsite_class}\";\n"
        f"        try {{ {body} }} catch (Throwable _t) {{ /* Stop, or the project's own fault */ }}\n"
        "        System.exit(frameproof.Spy.seen && frameproof.Spy.via ? 0 : NOT_REACHED);\n"
        "    }\n"
        "}\n"
    )


CSHARP_SPY = """using System;
using System.Linq;

namespace FrameProof {
    // Generated by Frame: records attacker-marked data reaching a hooked sink call.
    public static class Spy {
        public static string Marker = "";
        public static string CallSite = "";
        public static bool Seen, Via;

        public sealed class Stop : Exception {
            public Stop() : base("frame: marker reached the sink") { }
        }

        public static T Arg<T>(T v) {
            if (!Carries(v)) return v;
            var t = new System.Diagnostics.StackTrace().GetFrame(1)?.GetMethod()?.DeclaringType;
            bool via = false;
            for (; t != null && !via; t = t.DeclaringType)
                via = t.Name == CallSite;
            Seen = true;
            Via = via;
            throw new Stop();
        }

        static bool Carries(object v) {
            if (v == null) return false;
            string s;
            if (v is byte[] b) s = System.Text.Encoding.Latin1.GetString(b);
            else if (v is string str) s = str;
            else if (v is System.Collections.IEnumerable e)
                s = string.Join(",", e.Cast<object>().Select(x => x?.ToString()));
            else s = v.ToString();
            return s != null && s.Contains(Marker);
        }
    }
}
"""


def csharp_hook_test(driver: str, callsite_class: str, marker: str) -> str:
    """The xUnit test for a hooked sink: run the driver, pass only when the marker reached
    the hooked call from the call-site class."""
    body = "\n            ".join(driver.splitlines()) or ";"
    return (
        "using System;\nusing Xunit;\n\n"
        "public class ReproTest {\n"
        f"    const string MARKER = \"{marker}\";\n"
        "    [Fact] public void Reproduces() {\n"
        "        global::FrameProof.Spy.Marker = MARKER;\n"
        f"        global::FrameProof.Spy.CallSite = \"{callsite_class}\";\n"
        "        global::FrameProof.Spy.Seen = false; global::FrameProof.Spy.Via = false;\n"
        f"        try {{ {body} }} catch (Exception) {{ /* Stop, or the project's own fault */ }}\n"
        "        Assert.True(global::FrameProof.Spy.Seen && global::FrameProof.Spy.Via,\n"
        "                    \"the marker must reach the sink through the project\");\n"
        "    }\n"
        "}\n"
    )
