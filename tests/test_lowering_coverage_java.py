"""No Java syntax silently loses data on its way to SIL (the Java side of tests/test_lowering_coverage.py).

The Java frontend lowers each expression node it knows; anything else falls back to a variable
named by the node's source text, so whatever data the node carried is lost without a trace. A
compound assignment, a ternary, a chained assignment, an array initializer and an instanceof
binding were all lowered that way, or worse, dropped (`synchronized`, `do`, labelled statements,
switch rules). The frontend records every node type that reaches the fallback, and every
statement kind it has no lowering for (`statement:<type>`), in `Program.unlowered_syntax`; a
syntax zoo of everyday forms must reach it only with node types that carry no data.
"""

from frame.sil.frontends.java_frontend import JavaFrontend

# Node types that may reach the fallback: they carry no data a finding could depend on.
JAVA_ALLOWED = {
    "class_literal",       # `String.class`
    "lambda_expression",   # a function value outside a call or declaration (its body is not run here)
    "method_reference",    # `this::find`: a function value (its flow is a known gap, test_metamorphic_java)
}

JAVA_ZOO = '''
import java.io.*;
import java.util.*;
import java.util.function.*;

public class Zoo {
    private static final Set<String> ALLOWED = Set.of("a", "b");
    private String field;
    private String[] slots = new String[4];

    record Point(int x, int y) {}

    String run(String q, Object o, int n, List<String> items) throws Exception {
        String a, b;
        a = b = q;
        String s = "x";
        s += q;
        s -= 0 == 1 ? "" : "";
        n <<= 2;
        n += 1;
        int i = 0, j = 0x1F + 0b101 + 017 + 1_000 + 10L > 0 ? 1 : 2;
        i++;
        --j;
        String t = n > 0 ? q : "none";
        String u = ALLOWED.contains(q) ? q : "id";
        String[] arr = {q, "b"};
        String[] arr2 = new String[]{q, a};
        String[][] grid = {{q}, {"x"}};
        byte[] buf = new byte[n];
        arr[0] = q;
        grid[0][0] = q;
        this.slots[1] = q;
        slots[i++] = q;
        if (o instanceof String str && !str.isEmpty()) {
            field = str;
        }
        if (o instanceof Point(int px, var py)) {
            n = px + py;
        }
        BufferedReader br = new BufferedReader(new StringReader(q));
        String line;
        while ((line = br.readLine()) != null) {
            s = s + line;
        }
        for (i = 0, j = 1; i < n; i++, j++) {
            s = s + i;
        }
        do {
            n--;
        } while ((n = n - 1) > 0);
        synchronized (this) {
            field = q;
        }
        outer:
        for (String it : items) {
            if (it.isEmpty()) continue outer;
            break outer;
        }
        switch (n) {
            case 1 -> s = q;
            case 2, 3 -> { s = a; }
            default -> s = "d";
        }
        switch (n) {
            case 1: s = q; break;
            case 2:
            case 3: s = b;
            default: s = "x";
        }
        String w = switch (n) {
            case 1 -> q;
            default -> {
                String z = q.trim();
                yield z;
            }
        };
        Object k = switch (o) {
            case String str2 -> str2;
            case Point(int x, int y) -> x;
            default -> "none";
        };
        Class<?> c = String.class;
        Function<String, String> f = String::trim;
        Supplier<String> sup = () -> q;
        String r = ((String) o).trim() + ((CharSequence) q).length() + (q).length();
        new StringBuilder(q).insert(0, q);
        new File(q);
        assert q != null : "q";
        System.out.println(t + u + w + k + c + f + sup + r + arr2 + i + j);
        return (s = q);
    }
}
'''


def test_java_zoo_lowers_every_data_carrying_node():
    program = JavaFrontend().translate(JAVA_ZOO, "Zoo.java")
    unexpected = {k: n for k, n in (program.unlowered_syntax or {}).items() if k not in JAVA_ALLOWED}
    assert not unexpected, f"node types lowered as their source text (or dropped): {unexpected}"


def test_the_fallback_is_recorded():
    # The tripwire itself: a construct the frontend does not lower must show up.
    program = JavaFrontend().translate(
        "class A { Object m() { return String.class; } }", "A.java")
    assert "class_literal" in (program.unlowered_syntax or {})

