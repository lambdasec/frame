"""No JavaScript/TypeScript syntax silently loses data on its way to SIL (the JS counterpart of
tests/test_lowering_coverage.py).

The JS frontend lowers each expression node it knows; anything else falls back to a variable
named by the node's source text, so whatever data the node carried is lost without a trace (a
chained assignment, a sequence, a spread and `<T>x` were all lowered that way). A statement kind
it does not know is lowered child by child and recorded as `statement:<type>`. Both are recorded
in `Program.unlowered_syntax`; a syntax zoo of everyday forms must reach the fallback only with
node types that carry no data. A new construct, or a refactor that breaks one, fails here instead
of quietly costing findings.
"""

from frame.sil.frontends.javascript_frontend import JavaScriptFrontend, TypeScriptFrontend

# Node types that may reach the fallback: they carry no data a finding could depend on.
JS_ALLOWED = {
    "arrow_function", "function_expression", "function", "generator_function",   # function values
    "class",                        # a class value
    "meta_property",                # `new.target`, `import.meta`
    "private_property_identifier",  # the `#x` of `#x in obj`
}

JS_ZOO = r'''
const cp = require('child_process');
const { exec: run } = require('child_process');
async function* gen(q) { yield q; yield* q; }
async function f(q, ...args) {
  let a, b, c, d, e;
  a = b = q;
  ({ c } = q);
  [d, e] = [q, 1];
  const [g, { h }] = [q, { h: q }];
  const x1 = (0, q);
  const x2 = `ping ${q}`.trim() + ('p ' + q).trim() + ['p', q].join(' ');
  const x3 = q.split(',')[0].trim();
  const x4 = q ? q : 'x';
  const x5 = (q || 'x') + (q ?? 'x') + (!q && q);
  const x6 = typeof q + void 0 + -q + ~1;
  const x7 = { a: q, ...args, [q]: 1, m() { return q; } };
  const x8 = [...args, q];
  const x9 = new Date(q) + /x/g.test(q);
  const x10 = q?.a?.[0]?.();
  const x11 = (a += q);
  const x12 = q.map(s => s.trim()).filter(Boolean);
  const x13 = class {};
  const x14 = function () {};
  const x15 = this && this.x;
  const x16 = arguments[0] + new.target;
  const x17 = await q;
  const x18 = sql`SELECT ${q}`;
  let i = 0;
  const x19 = args[i++];
  cp.exec(...args);
  (0, cp.exec)(q);
  run(q);
  for (const [k, v] of Object.entries(q)) { cp.exec(v); }
  for (const { y } of q) { cp.exec(y); }
  for (let j = 0, n = 2; j < n; j++, n--) {}
  for (;;) { break; }
  do { cp.exec(q); } while (false);
  outer: for (const z of q) { continue outer; }
  { cp.exec(q); }
  switch (q) { case 'a': { cp.exec(q); break; } default: cp.exec(q); }
  try { cp.exec(q); } catch (err) { cp.exec(q); } finally { cp.exec(q); }
  try { cp.exec(q); } catch { cp.exec(q); }
  if (q) cp.exec(q); else cp.exec(q);
  while (q) { cp.exec(q); }
  q.a = q.b = q;
  q[0] = q;
  delete q.a;
  void cp.exec(q);
  debugger;
  return f(q), q;
}
class K { #x = 1; m() { return #x in this; } }
'''

TS_ZOO = r'''
import { exec } from 'child_process';
class A {
  private db = 1;
  constructor(private readonly x: string) {}
  m<T>(q: string, t: T): string {
    const a = <string>q;
    const b = q as string;
    const c = q!;
    const d = q satisfies string;
    const e = (q as any).trim();
    const g = (<string>q).trim();
    exec(a + b + c + d + e + g);
    return q;
  }
}
'''


def _unexpected(program):
    return {k: n for k, n in (program.unlowered_syntax or {}).items() if k not in JS_ALLOWED}


def test_js_zoo_lowers_every_data_carrying_node():
    program = JavaScriptFrontend().translate(JS_ZOO, "zoo.js")
    assert program.syntax_error_line is None
    assert not _unexpected(program), f"node types lowered as their source text: {_unexpected(program)}"


def test_ts_zoo_lowers_every_data_carrying_node():
    program = TypeScriptFrontend().translate(TS_ZOO, "zoo.ts")
    assert program.syntax_error_line is None
    assert not _unexpected(program), f"node types lowered as their source text: {_unexpected(program)}"


def test_the_fallback_is_recorded():
    # The tripwire itself: a construct the frontend does not lower must show up.
    program = JavaScriptFrontend().translate("function f(q) { const t = new.target; return t; }", "t.js")
    assert "meta_property" in (program.unlowered_syntax or {})


def test_statements_are_never_dropped():
    # every statement kind of the zoo is lowered by name: none goes through the generic path
    for frontend, code, name in ((JavaScriptFrontend(), JS_ZOO, "zoo.js"), (TypeScriptFrontend(), TS_ZOO, "zoo.ts")):
        program = frontend.translate(code, name)
        generic = [k for k in (program.unlowered_syntax or {}) if k.startswith("statement:")]
        assert not generic, generic
