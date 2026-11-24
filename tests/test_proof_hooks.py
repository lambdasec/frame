"""Call-site argument hooks: the Java/C# spy for sinks with no interface to proxy.

The rewrite is pure (tree-sitter), so it is tested here without a JDK or the .NET SDK;
the compile-and-run is `tests/test_reproduction_exemplars.py` (CI's reproduction job).
"""

from frame.sil.proof_deps import DepsRun, DepsReproSpec, _driver_ran, fix_proof
from frame.sil.proof_hooks import (
    Sink, csharp_hook_test, hook_call_site, java_hook_main, sink_of,
)


def test_sink_of_reads_methods_and_constructors():
    assert sink_of("java.lang.Runtime.exec") == Sink("Runtime", "exec")
    assert sink_of("System.Diagnostics.Process.Start") == Sink("Process", "Start")
    assert sink_of("java.io.ObjectInputStream.<init>") == Sink("ObjectInputStream", "")
    assert sink_of("System.Data.SqlClient.SqlCommand.<init>") == Sink("SqlCommand", "")
    assert sink_of("new org.yaml.snakeyaml.Yaml") == Sink("Yaml", "")
    assert sink_of("exec") is None
    assert sink_of("") is None


JAVA = """package app;
public class Api {
    public String ping(String host) throws Exception {
        log(host);
        Runtime.getRuntime().exec("ping -c 1 " + host);
        return "ok";
    }
}
"""


def test_java_hook_wraps_the_sink_call_on_the_line():
    h = hook_call_site(JAVA, "java", 5, sink_of("java.lang.Runtime.exec"))
    assert h.calls == 1 and h.on_line
    assert 'exec(frameproof.Spy.arg("ping -c 1 " + host))' in h.source
    assert "log(host);" in h.source                    # other calls untouched
    assert "getRuntime()" in h.source                  # no data argument, nothing wrapped


def test_a_moved_call_is_still_hooked():
    # a fixed copy where lines shifted: the call is found in the file, not lost
    h = hook_call_site(JAVA, "java", 2, sink_of("java.lang.Runtime.exec"))
    assert h.calls == 1 and not h.on_line
    assert "frameproof.Spy.arg(" in h.source


def test_a_file_without_the_call_has_no_hook():
    assert hook_call_site(JAVA, "java", 5, sink_of("java.lang.ProcessBuilder.start")) is None


def test_java_constructor_and_argument_kinds():
    src = ('class A { void m(String s) { new java.io.ObjectInputStream(f(s));'
           ' new Other(s); g(x -> x, null, 3, "lit", h(s)); } }')
    h = hook_call_site(src, "java", 1, sink_of("java.io.ObjectInputStream.<init>"))
    assert "new java.io.ObjectInputStream(frameproof.Spy.arg(f(s)))" in h.source
    assert "new Other(s)" in h.source
    h = hook_call_site(src, "java", 1, Sink("X", "g"))
    # lambdas and literals are left alone; data arguments are wrapped
    assert 'g(x -> x, null, 3, "lit", frameproof.Spy.arg(h(s)))' in h.source


def test_nested_sink_calls_are_wrapped_inside_out():
    h = hook_call_site("class A { void m(String s) { g(g(s)); } }", "java", 1, Sink("X", "g"))
    assert "g(frameproof.Spy.arg(g(frameproof.Spy.arg(s))))" in h.source


CSHARP = """using System.Diagnostics;
namespace app {
    public class Api {
        public void Ping(string host) {
            Process.Start("ping", "-c 1 " + host);
            Run(x => x, ref host, out var y, name: host);
        }
    }
}
"""


def test_csharp_hook_wraps_data_arguments_only():
    h = hook_call_site(CSHARP, "csharp", 5, sink_of("System.Diagnostics.Process.Start"))
    assert h.calls == 1 and h.on_line
    assert 'Process.Start("ping", global::FrameProof.Spy.Arg("-c 1 " + host));' in h.source
    h = hook_call_site(CSHARP, "csharp", 6, Sink("X", "Run"))
    # ref/out arguments and lambdas are untouched; a named argument's value is wrapped
    assert "Run(x => x, ref host, out var y, name: global::FrameProof.Spy.Arg(host));" in h.source


def test_generated_harnesses_name_the_call_site_class():
    main = java_hook_main("new app.Api().ping(MARKER);", "Api", "M_1")
    assert 'frameproof.Spy.CALLSITE = "Api";' in main
    assert "new app.Api().ping(MARKER);" in main
    assert "System.exit(frameproof.Spy.seen && frameproof.Spy.via ? 0 : NOT_REACHED);" in main
    test = csharp_hook_test("new app.Api().Ping(MARKER);", "Api", "M_1")
    assert 'global::FrameProof.Spy.CallSite = "Api";' in test
    assert "Assert.True(global::FrameProof.Spy.Seen && global::FrameProof.Spy.Via" in test


def test_a_driver_that_could_not_run_is_not_a_fix(monkeypatch):
    # Before: reproduced. After: the fixed code does not compile. That proves nothing.
    import frame.sil.proof_deps as pd
    runs = iter([DepsRun(True, "reached", ran=True),
                 DepsRun(False, "the project did not compile standalone")])
    monkeypatch.setattr(pd, "run_reproduction", lambda *a, **k: next(runs))
    spec = DepsReproSpec("", "", "", "java.lang.Runtime.exec", "", "app/Api.java:5", "host")
    proof = fix_proof("d", spec, "v", "f", language="java")
    assert not proof.proved and "could not run" in proof.detail
    runs = iter([DepsRun(True, "reached", ran=True),
                 DepsRun(False, "the marker did not reach the sink", ran=True)])
    assert fix_proof("d", spec, "v", "f", language="java").proved


def test_driver_errors_that_mean_the_code_was_not_reached():
    assert _driver_ran("")
    assert _driver_ran("driver error: ValueError: bad host")          # the fix rejected it
    assert not _driver_ran("driver error: ModuleNotFoundError: No module named 'views'")
    assert not _driver_ran("driver error: Error: Cannot find module './routes'")
    assert not _driver_ran("driver error: TypeError: handler is not a function")
    assert not _driver_ran("patch failed: AttributeError: x")
