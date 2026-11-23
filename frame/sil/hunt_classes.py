"""Flaw classes for the hunt: authorization, and the business-logic classes beside it.

The hunt's pipeline (scouts, units, one fresh agent per unit, a verdict on every member, a finding
only with an invariant and a concrete violating request) is the same for every class. What a class
brings is what differs:

  focus        what the agent hunts and which engine questions settle it
  mechanisms   what a finding of the class can be, with its finding type and CWE
  signals      how the engine's facts rank a unit for the class (never names): numbers the
               caller chooses, data written, a secret compared with a guess, siblings
  corroborate  the engine answer that makes a finding of the class the `llm_verified` tier: a
               `check` the engine decided in the agent's run, never the model's say-so

`authz` is the authorization hunt as it was (its prompt and ranking are unchanged, so its
benchmark numbers are). The others: `limits` (a client number reaching stored state without its
bound, decided by Z3 through `check(kind=lower_bound|upper_bound)`), `race` (read, decide, write
without a lock), `workflow` (a required state or one-time token skipped), `replay` (a state change
accepted twice), `bruteforce` (a guessable secret checked without an attempt limit).
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any, Dict, FrozenSet, List, Optional, Tuple

try:                                        # Python 3.11+
    import tomllib
except ModuleNotFoundError:                 # pragma: no cover - 3.10
    import tomli as tomllib                 # type: ignore[no-redef]

CREDENTIAL_CHECKS = Path(__file__).parent / "specs" / "data" / "credential-checks.toml"


@dataclass(frozen=True)
class FlawClass:
    name: str
    title: str
    focus: str
    mechanisms: Dict[str, Tuple[str, str]]       # mechanism -> (finding type, CWE)
    unit_kinds: FrozenSet[str]                    # unit kinds the class audits
    corroborating: FrozenSet[str]                 # `check` kinds whose refutation backs a finding
    cwes: FrozenSet[str]                          # the class's CWE family


_ALL_KINDS = frozenset({"handlers", "service", "scouted", "coverage"})

AUTHZ = FlawClass(
    name="authz", title="authorization", focus="",
    mechanisms={"missing_authorization": ("missing_authorization", "CWE-862"),
                "idor": ("idor", "CWE-639"),
                "privilege_escalation": ("privilege_escalation", "CWE-269"),
                "mass_assignment": ("mass_assignment", "CWE-915"),
                "business_logic": ("business_logic_flaw", "CWE-840")},
    unit_kinds=_ALL_KINDS, corroborating=frozenset({"guarded_by", "scoped_by_identity"}),
    cwes=frozenset({"CWE-639", "CWE-862", "CWE-863", "CWE-285", "CWE-284", "CWE-269", "CWE-915",
                    "CWE-840", "CWE-566", "CWE-732"}))

LIMITS = FlawClass(
    name="limits", title="missing limits",
    focus=(
        "MISSING LIMITS: a number the caller chooses reaches stored state or money without the "
        "bound the business needs -- a negative or zero quantity, amount, price or points value, a "
        "discount over 100%, a refund above what was paid, more items than are in stock, a date "
        "outside its range, NaN or Infinity past a guard (NaN fails every ordered comparison, so "
        "`if (amount < 0) reject` lets it through).\n"
        "For each member:\n"
        "  1. Find the values the caller chooses (body, query and path fields) that are stored, "
        "charged, credited, transferred or compared with a balance or a stock count.\n"
        "  2. State the bound the business needs (quantity >= 1, 0 <= discount <= 100, refund <= "
        "amount paid).\n"
        "  3. Ask the engine at the line that stores or uses the value: check(name, line, "
        "kind='lower_bound' or 'upper_bound', var=<the value as the code names it>, bound=<n>). "
        "`refuted` comes with the value that gets through on a feasible path; `proved` means every "
        "path enforces it; `unknown` means the engine cannot follow the value (it is computed or "
        "read from storage): read the code.\n"
        "  4. A bound enforced elsewhere counts: a request schema or validator (pydantic "
        "Field(gt=0), conint, Joi/zod/yup .min(), class-validator @Min, Bean Validation @Min / "
        "@Positive, [Range]), a model or database constraint (PositiveIntegerField, a CHECK), or the "
        "service layer the handler calls. Look for it before reporting.\n"
        "  5. A value the server should take from its own records is a flaw of its own "
        "(mechanism client_trusted_value): a price, total or currency the request sends instead of "
        "the server reading it from the product, plan or order, or a plan / product / price id "
        "accepted without checking it belongs to the thing being bought. The violating request "
        "sends a cheaper price, or another item's plan id.\n"
        "  6. A limit the server sets FOR the caller is a bound too (mechanism missing_limit): a "
        "rate limit, quota, usage cap, seat count, plan tier, credit, or a flag that selects a "
        "larger allowance. When the caller's own create or update writes it (a serializer, form "
        "or schema that leaves it writable, a body spread onto the model), the caller raises "
        "their own allowance: that is a gain, not self-harm, even on the caller's own record. "
        "The violating request writes the higher value. This is about a stored allowance FIELD "
        "the caller can write; an endpoint that simply has no rate limit, throttle or captcha is "
        "not this class.\n"
        "Not this class (mark_safe for it, naming why; other classes cover them): a missing "
        "authentication or authorization check, a missing rate limit / throttle / captcha / "
        "anti-abuse check on an endpoint, who may send mail or trigger a job, a number with no "
        "business meaning (page size, sort order, a display setting, a timeout) unless it changes "
        "money, stock or what is stored. The violating request names the field and the value "
        "that gets through."),
    mechanisms={"missing_limit": ("business_logic_flaw", "CWE-1284"),
                "client_trusted_value": ("business_logic_flaw", "CWE-472")},
    unit_kinds=_ALL_KINDS, corroborating=frozenset({"lower_bound", "upper_bound"}),
    cwes=frozenset({"CWE-1284", "CWE-20", "CWE-682", "CWE-840", "CWE-839", "CWE-472", "CWE-602"}))

RACE = FlawClass(
    name="race", title="race conditions",
    focus=(
        "RACE CONDITIONS: a handler reads stored state, decides on it and writes it back without "
        "a lock or an atomic statement, so two concurrent requests both pass the check -- a "
        "balance spent twice, a coupon, gift card or invite redeemed twice, a vote or a like "
        "counted twice, a limit or the stock exceeded.\n"
        "For each member:\n"
        "  1. Find the read (a balance, a usage count, a status), the decision on it and the write "
        "that depends on it (callees(name) follows them into the service layer).\n"
        "  2. Find what makes them atomic: a row lock on the read (SELECT ... FOR UPDATE, "
        "select_for_update(), with_for_update(), a pessimistic lock mode), ONE conditional "
        "statement (UPDATE ... SET n = n - 1 WHERE n > 0, F() expressions, $inc with the "
        "condition in its filter, an atomic increment), a unique constraint that makes the second "
        "write fail, optimistic versioning (@Version, a version column in the WHERE), or a lock "
        "held around the code. A transaction alone, at the default isolation level, does not stop "
        "the second request from reading the old value.\n"
        "  3. Ask the engine: check(name, line, kind='atomic_write') at the write. `proved` names "
        "the lock or atomic write; `refuted` means it saw the read before the write and no lock, "
        "version or atomic write in the function or its callers; `unknown` means it cannot tell "
        "(read the code).\n"
        "The violating request is N identical requests sent at the same moment: say what each "
        "reads and why all of them succeed."),
    mechanisms={"race_condition": ("race_condition", "CWE-362")},
    unit_kinds=_ALL_KINDS, corroborating=frozenset({"atomic_write"}),
    cwes=frozenset({"CWE-362", "CWE-367", "CWE-366", "CWE-820", "CWE-821"}))

WORKFLOW = FlawClass(
    name="workflow", title="workflow bypass",
    focus=(
        "WORKFLOW BYPASS: a step or state the business requires that a caller can skip, repeat or "
        "reverse -- an order shipped, refunded or reviewed in the wrong state, a payment marked "
        "paid without being paid, an approval skipped by calling the next step directly, a "
        "one-time token (password reset, email verification, invite, magic link, coupon) accepted "
        "again or after it expires, a state one handler checks and a sibling step does not.\n"
        "For each member:\n"
        "  1. Name the state the operation requires (status == 'paid', token unused and not "
        "expired) and where it is stored.\n"
        "  2. Ask the engine whether every path checks it: check(name, line, kind='guarded_by', "
        "pattern=<the state field or the token check>) at the line that changes state; `refuted` "
        "comes with a path that skips it. siblings(name) shows which neighbouring steps check it.\n"
        "  3. For a one-time token, find where it is consumed (deleted, marked used, expired) and "
        "whether that happens on every path that accepts it.\n"
        "The violating request is the call that skips or repeats the step, with the state the "
        "object is in when it is sent."),
    mechanisms={"workflow_bypass": ("business_logic_flaw", "CWE-841"),
                "token_reuse": ("business_logic_flaw", "CWE-640")},
    unit_kinds=_ALL_KINDS, corroborating=frozenset({"guarded_by"}),
    cwes=frozenset({"CWE-841", "CWE-840", "CWE-640", "CWE-613", "CWE-672"}))

REPLAY = FlawClass(
    name="replay", title="replay",
    focus=(
        "REPLAY: a state-changing request the server accepts twice when it should act once -- a "
        "payment, transfer or webhook processed twice, a signed request or token with no nonce or "
        "expiry, an idempotency key that is not checked, a one-time code accepted again.\n"
        "For each member: what makes a second identical request harmless -- a nonce or "
        "idempotency key stored and checked, a uniqueness constraint, a status check that the "
        "first request changed, a signature over a timestamp that is checked? Ask the engine: "
        "check(name, line, kind='guarded_by', pattern=<that check>) at the line that changes "
        "state.\n"
        "The violating request is the same request sent a second time (say what it repeats and "
        "what the second one changes)."),
    mechanisms={"replay": ("business_logic_flaw", "CWE-837")},
    unit_kinds=_ALL_KINDS, corroborating=frozenset({"guarded_by"}),
    cwes=frozenset({"CWE-837", "CWE-294", "CWE-799", "CWE-841"}))

BRUTEFORCE = FlawClass(
    name="bruteforce", title="brute force",
    focus=(
        "BRUTE FORCE: a check of a secret the caller can guess -- a password, a one-time code, a "
        "2FA / TOTP code, a PIN, a reset code, an invite or API key -- with no limit on attempts: "
        "no rate limit, no lockout, no growing delay, no CAPTCHA.\n"
        "For each member:\n"
        "  1. Find the comparison of the guess with the secret.\n"
        "  2. Find the limit: a rate-limit decorator, guard or middleware on this route or the "
        "whole application (read where the app registers its middleware and its settings), an "
        "attempt counter with a lockout, a throttle in the framework's configuration. Ask the "
        "engine: check(name, line, kind='attempt_limit') at the function that compares the guess; "
        "`proved` names the limiter, `refuted` means nothing in the code limits attempts, `unknown` "
        "says what to read (an application-wide limiter, an attempt counter it may keep).\n"
        "  3. Size the attack: how many guesses the secret space needs (a 6-digit code is 10^6) "
        "and whether the secret expires first.\n"
        "The violating request is the guess, repeated: say how many and how fast."),
    mechanisms={"brute_force": ("credential_stuffing", "CWE-307")},
    unit_kinds=frozenset({"handlers", "scouted", "service"}), corroborating=frozenset({"attempt_limit"}),
    cwes=frozenset({"CWE-307", "CWE-799", "CWE-1216"}))

CLASSES: Dict[str, FlawClass] = {c.name: c for c in (AUTHZ, LIMITS, RACE, WORKFLOW, REPLAY, BRUTEFORCE)}
LOGIC = ("limits", "race", "workflow", "replay", "bruteforce")


def parse(value: Any) -> List[str]:
    """`authz`, `limits,race`, `all`, `logic` (every business-logic class) or a list of them, in
    the registry's order. An unknown name is an error naming the choices."""
    if value is None or value == "" or value == []:
        return ["authz"]
    items = value if isinstance(value, (list, tuple)) else str(value).split(",")
    out: List[str] = []
    for raw in items:
        n = str(raw).strip().lower()
        if not n:
            continue
        names = list(CLASSES) if n == "all" else list(LOGIC) if n == "logic" else [n]
        for x in names:
            if x not in CLASSES:
                raise ValueError(f"unknown hunt class {raw!r}; choose from "
                                 f"{', '.join(CLASSES)}, logic or all")
            if x not in out:
                out.append(x)
    return [c for c in CLASSES if c in out] or ["authz"]


# ---- the agent's instructions --------------------------------------------------------------

_COMMON = (
    "You are auditing ONE unit of an application -- a few related handlers, or the service "
    "functions they delegate to -- for ONE class of BUSINESS-LOGIC flaw, described below. The "
    "unit's members are listed in the first message, with their source. You must leave a verdict "
    "on EVERY member.\n\n"
    "{focus}\n\n"
    "Ask the engine instead of guessing: check(...) proves or refutes a claim at a line, "
    "guards(name, line) lists the conditions that hold on EVERY feasible path to a line, "
    "callees(name) follows a handler into its service layer, siblings(name) shows what the "
    "neighbouring handlers do, trace(name) shows which request values reach which data access. "
    "Read code with read_file and line ranges; grep with a path to stay focused.\n\n"
    "Only server code enforces a business rule: a page, component, hook or client store runs "
    "in the caller's own browser, so a check missing there is not a flaw (mark_safe: browser "
    "code); audit the endpoint it calls instead. A flaw needs a caller who GAINS: money, stock, "
    "access or an effect on someone else. A value only an administrator, or the owner of the "
    "record, can set, and that harms nobody but themselves, is not a flaw unless a "
    "lower-privileged caller can send it too.\n\n"
    "Verdicts: report_finding when you can state the invariant the code should guarantee and a "
    "concrete violating request (who sends what, to which endpoint, with which values, and what "
    "they gain); "
    "mark_safe naming what enforces the invariant (or why the member has nothing to do with this "
    "class); mark_unresolved when, after looking, the answer depends on something the repository "
    "does not hold (a configuration value, a deployment's settings, a library's behaviour) -- "
    "say what you suspect, where you looked and the fact that would decide it. Report only this "
    "class of flaw; a wrong finding is worse than none. When every member has a verdict, reply "
    "with a one-line summary and no tool call."
)


def system_prompt(cls: FlawClass, authz_prompt: str) -> str:
    """The unit agent's system prompt: the authorization hunt's own for `authz`, else the shared
    protocol with the class's focus."""
    return authz_prompt if cls.name == "authz" else _COMMON.format(focus=cls.focus)


def report_tool(cls: FlawClass, base: Dict[str, Any]) -> Dict[str, Any]:
    """report_finding with the class's mechanisms (the authorization hunt keeps its own)."""
    if cls.name == "authz":
        return base
    import copy
    tool = copy.deepcopy(base)
    fn = tool["function"]
    fn["description"] = (f"Record ONE confirmed {cls.title} flaw. Required: the invariant the code "
                         "should guarantee and a concrete violating request grounded in the code "
                         "you read. A claim you cannot turn into such a request is not a finding.")
    props = fn["parameters"]["properties"]
    props["mechanism"] = {"type": "string", "enum": list(cls.mechanisms)}
    props["engine_backed"] = {"type": "boolean",
                              "description": "true when an engine check(...) you ran supports it"}
    return tool


# ---- ranking: engine facts per member --------------------------------------------------------

@lru_cache(maxsize=None)
def credential_checks(path: Path = CREDENTIAL_CHECKS) -> Dict[str, Tuple[str, ...]]:
    data = tomllib.loads(Path(path).read_text(encoding="utf-8"))
    data.pop("bases", None)
    return _id_lists(data, path, "call ids")


@lru_cache(maxsize=None)
def credential_bases(path: Path = CREDENTIAL_CHECKS) -> Dict[str, Tuple[str, ...]]:
    """Library classes whose own methods compare a guess with a stored secret, per language."""
    data = tomllib.loads(Path(path).read_text(encoding="utf-8")).get("bases") or {}
    if not isinstance(data, dict):
        raise ValueError(f"{Path(path).name}: [bases] must be a table of class id lists")
    return _id_lists(data, path, "class ids")


def _id_lists(data: Dict[str, Any], path: Path, what: str) -> Dict[str, Tuple[str, ...]]:
    out: Dict[str, Tuple[str, ...]] = {}
    for lang, ids in data.items():
        if not isinstance(ids, list) or not all(isinstance(i, str) and i for i in ids):
            raise ValueError(f"{Path(path).name}: {lang} must be a list of {what}")
        out[lang] = tuple(ids)
    return out


def _inherits_credential_check(program, proc_name: str) -> bool:
    """Is `proc_name` a method of a class built on a library class that checks credentials in
    its own methods (`credential_bases`)? The class's resolved bases and the ones it inherits
    through the project's own classes are compared."""
    ids = credential_bases().get(_lang(program)) or ()
    if not ids or "." not in proc_name:
        return False
    cls = proc_name.split("#", 1)[0].rsplit(".", 1)[0]
    info = (getattr(program, "class_info", None) or {}).get(cls)
    if info is None:
        return False
    lineage = [str(b) for b in (list(getattr(info, "canonical_bases", None) or [])
                                + list(getattr(info, "project_bases", None) or []))]
    return any(b == i or b.endswith("." + i) for b in lineage for i in ids)


def _lang(program) -> str:
    lang = (getattr(program, "language", "") or "").lower()
    return "javascript" if lang in ("typescript", "javascript") else lang


def _calls_credential_check(program, proc) -> bool:
    ids = credential_checks().get(_lang(program)) or ()
    if not ids:
        return False
    from frame.sil.instructions import Call
    for node in (getattr(proc, "nodes", {}) or {}).values():
        for ins in getattr(node, "instrs", []) or []:
            if not isinstance(ins, Call):
                continue
            canon = str(getattr(ins, "canonical", "") or "")
            written = ins.get_full_name().strip('"') if hasattr(ins, "get_full_name") else ""
            for i in ids:
                if canon == i or canon.endswith("." + i) or written == i:
                    return True
    return False


def _numeric_inputs(program, proc_name: str) -> List[str]:
    """Client values the procedure converts to numbers (or, in JavaScript, compares with < or > as
    read)."""
    from frame.sil.logic_facts import conversion, declared
    vf = (getattr(program, "value_facts", None) or {}).get(proc_name) or {}
    lang = getattr(program, "language", "") or ""
    out: List[str] = [n for n in (vf.get("entry") or {})
                      if declared(lang, (vf.get("types") or {}).get(n, "")) is not None]
    from frame.sil.logic_facts import used_as_number
    clients = set().union(*[set(c) for c in (vf.get("client") or {}).values()]) if vf.get("client") else set()
    for name, ds in (vf.get("defs") or {}).items():
        for d in ds:
            if d[0] == "call" and conversion(lang, d[1]) is not None and name in clients:
                out.append(name)
            elif d[0] == "read" and _lang(program) == "javascript" and name in clients \
                    and used_as_number(vf, [name]):
                out.append(name)
    # name them as the code does: `qty = $qty_1` names the converted temporary `$qty_1`
    copies: Dict[str, List[str]] = {}
    for name, ds in (vf.get("defs") or {}).items():
        if len(ds) == 1 and ds[0][0] == "copy":
            copies.setdefault(ds[0][1], []).append(name)
    shown: set = set()
    for n in out:
        todo, named = [n], []
        while todo and len(named) < 8:
            cur = todo.pop()
            if not cur.startswith("$"):
                named.append(cur)
            todo.extend(copies.get(cur, []))
        shown.update(named or [n])
    return sorted(shown)


def _passes_client_data(proc, vf) -> bool:
    """Does the procedure hand client data to a call (an argument holding a value the request
    sent, at that line)? A handler that only reads its parameters to build a title passes none."""
    client = vf.get("client") or {}
    entry = set(vf.get("entry") or {})
    for node in (getattr(proc, "nodes", {}) or {}).values():
        for ins in getattr(node, "instrs", []) or []:
            if type(ins).__name__ != "Call":
                continue
            line = getattr(getattr(ins, "loc", None), "line", 0) or 0
            held = set(client.get(line) or {}) | entry
            if not held:
                continue
            for arg in getattr(ins, "args", None) or []:
                exp = arg[0] if isinstance(arg, tuple) else arg
                try:
                    names = {str(getattr(v, "name", v)) for v in exp.free_vars()}
                except Exception:
                    continue
                if any(n in held or n.split(".", 1)[0] in held for n in names):
                    return True
    return False


def _browser_program(program, proc=None) -> bool:
    """React's documented boundary: a module or function marked "use client" runs in the browser."""
    return "use client" in (list(getattr(program, "directives", None) or [])
                            + list(getattr(proc, "directives", None) or []))


def _reached_files(ctx) -> Optional[set]:
    """Files a request can reach: those holding an entry point (an engine handler, or a route the
    scouts recorded that is not browser code or a view that only renders), and, transitively,
    those defining a name a reached file calls (by the call graph's simple names; a name several
    files define counts only for the file the caller imports it from). A file outside this set is
    a standalone script (a migration, a seed, a CLI) or browser code (a store or hook only
    components call): no caller's data reaches it on the server. None when the context cannot say
    (no entry point at all, or a failure: nothing is excluded). Cached on the context."""
    scouted = list(getattr(ctx, "scouted_routes", None) or [])
    key = (id(getattr(ctx, "index", None)), len(getattr(ctx, "programs", None) or []), len(scouted))
    cached = getattr(ctx, "_reached_files_cache", None)
    if cached is not None and cached[0] == key:
        return cached[1]
    out: set = set()
    try:
        from frame.sil.hunt_units import simple_name
        from frame.sil.hunt_tools import _program_file
        root = getattr(ctx, "repo_root", None)
        by_file: Dict[str, Any] = {}
        for prog in getattr(ctx, "programs", None) or []:
            pf = _program_file(prog, root)
            by_file[pf] = prog
            if any(getattr(p, "entry_kinds", None) for p in (getattr(prog, "procedures", {}) or {}).values()):
                out.add(pf)
        for h in (getattr(getattr(ctx, "index", None), "handlers", None) or []):
            f = getattr(h, "file", None) or (h.get("file") if isinstance(h, dict) else None)
            if f:
                out.add(f)
        for file, name in scouted:
            prog = by_file.get(file)
            loc = ctx.locate(name, file) if prog is not None else None
            proc = ((getattr(prog, "procedures", {}) or {}).get(loc["proc"])
                    if loc is not None and loc.get("file") == file else None)
            if prog is not None and (_browser_program(prog, proc) or getattr(proc, "renders", False)):
                continue
            out.add(file)
        if not out:
            return None
        imports: Dict[str, Dict[str, str]] = {}
        for prog in getattr(ctx, "programs", None) or []:
            table = getattr(prog, "imports", None)
            table = table if isinstance(table, dict) else getattr(table, "names", None)
            if isinstance(table, dict):
                imports[_program_file(prog, root)] = table
        defs, calls = ctx.graph()
        by_caller: Dict[str, List[str]] = {}
        for (pf, _pname), cs in calls.items():
            by_caller.setdefault(pf, []).extend(c for c, _line in cs)

        def callees(pf: str, callee: str) -> List[str]:
            every = defs.get(simple_name(callee)) or []
            if "." not in callee and any(d["file"] == pf for d in every):
                return []                   # a plain call of a function the caller's file defines
            ds = [d for d in every if d["file"] != pf]
            if len(ds) == 1:
                return [ds[0]["file"]]
            # a name several files define counts only for the file the caller imports it from
            # (the JS frontend already names a call through a module after it: ./lib/ids.newId)
            head = callee.split(".")[0]
            table = imports.get(pf) or {}
            origins = [o for o in (table.get(head), table.get(callee)) if isinstance(o, str)]
            if "/" in callee or "\\" in callee:
                origins.append(callee.rsplit(".", 1)[0])
            if not origins:
                return []
            parts = {x for o in origins for x in re.split(r"[./\\]+", o) if x}
            return [d["file"] for d in ds
                    if os.path.splitext(os.path.basename(d["file"]))[0] in parts
                    or (os.path.splitext(os.path.basename(d["file"]))[0] == "index"
                        and os.path.basename(os.path.dirname(d["file"])) in parts)]

        work = list(out)
        while work:
            pf = work.pop()
            for callee in by_caller.get(pf) or []:
                for f in callees(pf, callee):
                    if f not in out:
                        out.add(f)
                        work.append(f)
    except Exception:
        return None
    try:
        ctx._reached_files_cache = (key, out)
    except Exception:
        pass
    return out


def _resolve(ctx, defs, file: str, proc_name: str, callee: str) -> Optional[Dict[str, Any]]:
    """The project function a call names (`HuntContext.resolve_call`), else the one definition
    of its name."""
    if hasattr(ctx, "resolve_call"):
        return ctx.resolve_call(file, proc_name, callee)
    from frame.sil.hunt_units import simple_name
    ds = defs.get(simple_name(callee)) or []
    return ds[0] if len(ds) == 1 else None


def _callee_data(ctx, file: str, proc_name: str) -> Tuple[bool, bool, bool]:
    """Does a function this one calls (one hop, resolved to one project function) read,
    write, or run a query that may write stored data? A route that stores through a helper in
    another file is server code."""
    reads = writes = may_write = False
    try:
        defs, calls = ctx.graph()
        for callee, _line in (calls.get((file, proc_name)) or [])[:40]:
            d = _resolve(ctx, defs, file, proc_name, callee)
            if d is None:
                continue
            loc = ctx.locate(d["name"], d["file"] or None)
            if loc is None or loc.get("program") is None:
                continue
            vf = (getattr(loc["program"], "value_facts", None) or {}).get(loc["proc"]) or {}
            reads = reads or bool(vf.get("data"))
            writes = writes or bool(vf.get("writes"))
            may_write = may_write or bool(vf.get("may_write", vf.get("writes")))
            if reads and writes:
                break
    except Exception:
        pass
    return reads, writes, may_write or writes


# How many project calls deep a credential check is looked for: an endpoint verifies a password
# through the application's own helpers (duplicati: `VerifyWebserverPassword` ->
# `PbkdfConfig.VerifyPassword` -> `CryptographicOperations.FixedTimeEquals`).
CREDENTIAL_DEPTH = 3


def _callee_credential(ctx, file: str, proc_name: str) -> bool:
    """Does a function this one calls, through at most CREDENTIAL_DEPTH project calls each to a
    name with one definition in the project, compare a guess with a stored secret?"""
    try:
        defs, calls = ctx.graph()
        seen = {(file, proc_name)}
        frontier = [(file, proc_name)]
        for _ in range(CREDENTIAL_DEPTH):
            nxt = []
            for key in frontier:
                for callee, _line in (calls.get(key) or [])[:40]:
                    d = _resolve(ctx, defs, key[0], key[1], callee)
                    if d is None:
                        continue
                    ckey = (d["file"], d["name"])
                    if ckey in seen:
                        continue
                    seen.add(ckey)
                    if _checks_credential_itself(ctx, ckey):
                        return True
                    nxt.append(ckey)
            frontier = nxt
    except Exception:
        pass
    return False


def _checks_credential_itself(ctx, key: Tuple[str, str]) -> bool:
    """Does the project function (file, name) itself call a credential check? Memoised."""
    memo = ctx.__dict__.setdefault("_credential_memo", {})
    if key not in memo:
        loc = ctx.locate(key[1], key[0] or None)
        proc = None
        if loc is not None and loc.get("program") is not None:
            proc = (getattr(loc["program"], "procedures", {}) or {}).get(loc["proc"])
        memo[key] = bool(proc is not None and _calls_credential_check(loc["program"], proc))
    return memo[key]


def _credential_callers(ctx, file: str, proc_name: str) -> int:
    """How many functions calling this one compare a guess with a stored secret themselves or
    through their own callees. A write such a function makes is the attempt bookkeeping a
    lockout depends on (Sync-in's `updateAccesses`, called by `logUser` after `bcrypt.compare`)."""
    if not hasattr(ctx, "callers_of"):
        return 0
    n = 0
    try:
        for key in ctx.callers_of(file, proc_name)[:40]:
            if _checks_credential_itself(ctx, key) or _callee_credential(ctx, key[0], key[1]):
                n += 1
    except Exception:
        pass
    return n


def _file_facts(ctx, file: str, out: Dict[str, Any]) -> None:
    """For a member the engine parsed the file of but has no procedure for by that name (a
    method written as a wrapped class field, `getRole = computedFn(() => ...)`): what the file
    says. `parsed`, browser code (a "use client" module), and whether a request reaches it."""
    if not file:
        return
    try:
        from frame.sil.hunt_tools import _program_file
        root = getattr(ctx, "repo_root", None)
        prog = next((p for p in getattr(ctx, "programs", None) or [] if _program_file(p, root) == file), None)
        if prog is None:
            return
        out["parsed"] = True
        out["browser"] = _browser_program(prog)
        reached = _reached_files(ctx)
        out["reached"] = reached is None or file in reached
    except Exception:
        pass


def member_facts(ctx, member) -> Dict[str, Any]:
    """What the engine knows about one unit member, for ranking: client numbers, data reads and
    writes, a credential check, whether it is an entry point and whether its file is test code.
    `known` is False when the engine has no program for it."""
    out = {"numeric": [], "reads": False, "writes": False, "may_write": False, "credential": False,
           "credential_callers": 0,
           "known": False, "parsed": False,
           "entry": False, "test": False, "client": False, "browser": False, "view": False,
           "reached": True, "passes": False, "read_writes": [], "decided": []}
    try:
        if hasattr(member, "program"):
            program, proc_name, file = member.program, member.name, getattr(member, "file", "")
            kinds = {str(s.get("kind")) for s in (member.sinks or [])}
            out["reads"] = bool(member.reaches_resource) or bool(kinds & {"resource_select", "sql", "nosql", "orm"})
            out["writes"] = "resource_modify" in kinds
            out["may_write"] = bool(kinds & {"resource_modify", "sql", "nosql", "orm"})
            out["entry"] = True                       # an engine handler is an entry point
        else:
            loc = ctx.locate(str(member.get("name", "")), member.get("file") or None)
            if loc is None or loc.get("program") is None or (
                    member.get("file") and loc.get("file") != member.get("file")):
                _file_facts(ctx, str(member.get("file") or ""), out)
                return out
            program, proc_name, file = loc["program"], loc["proc"], loc.get("file") or ""
        if program is None:
            return out
        proc = (getattr(program, "procedures", {}) or {}).get(proc_name)
        if proc is None:
            _file_facts(ctx, file, out)
            return out
        out["known"] = True
        vf = (getattr(program, "value_facts", None) or {}).get(proc_name) or {}
        out["reads"] = out["reads"] or bool(vf.get("data"))
        out["writes"] = out["writes"] or bool(vf.get("writes"))
        out["may_write"] = out["may_write"] or out["writes"] or bool(vf.get("may_write"))
        out["test"] = bool(vf.get("test"))
        out["entry"] = out["entry"] or bool(getattr(proc, "entry_kinds", None))
        if not (out["reads"] or out["writes"]) and hasattr(ctx, "graph"):
            out["reads"], out["writes"], out["may_write"] = _callee_data(ctx, file, proc_name)
        out["numeric"] = _numeric_inputs(program, proc_name)
        out["client"] = bool(vf.get("entry")) or any(bool(v) for v in (vf.get("client") or {}).values())
        out["credential"] = _calls_credential_check(program, proc) or \
            _inherits_credential_check(program, proc_name) or (
            hasattr(ctx, "graph") and _callee_credential(ctx, file, proc_name))
        if out["may_write"] and not out["credential"]:
            out["credential_callers"] = _credential_callers(ctx, file, proc_name)
        out["browser"] = _browser_program(program, proc)
        out["view"] = bool(getattr(proc, "renders", False))
        out["passes"] = _passes_client_data(proc, vf)
        from frame.sil.concurrency import decided_read_writes, unprotected_read_writes
        out["read_writes"] = unprotected_read_writes(program, proc_name)
        out["decided"] = decided_read_writes(program, proc_name) if out["read_writes"] else []
        if not out["entry"]:
            reached = _reached_files(ctx)
            out["reached"] = reached is None or file in reached
    except Exception:
        pass
    return out


def score(cls: FlawClass, unit, ctx) -> Tuple[float, List[str]]:
    """How much the engine's facts say this unit matters for `cls` (0: not audited for it).
    Never by names. Every kind of unit is scored by its members' facts; only a unit the engine
    has no program for at all (found by a scout in code it does not parse) gets a base score, so
    an app the engine cannot see is still audited.

    A business-logic rule is enforced where the server acts: a member counts when it is an entry
    point or touches stored data. Browser code (a page, a hook, a client store) reads values the
    user's own browser chooses and stores nothing, so it scores 0, and so does test code."""
    if unit.kind not in cls.unit_kinds:
        return 0.0, []
    facts = [member_facts(ctx, m) for m in unit.members]
    known = [f for f in facts if f["known"]]
    if not known:
        if unit.kind not in ("scouted", "coverage"):
            return 0.0, []
        # a file the engine parsed says where it runs even when a member's name does not resolve
        if facts and all(f["parsed"] and (f["browser"] or not f["reached"]) for f in facts):
            return 0.0, ["browser code or code no request reaches"]
        return 1.0, ["found by the scouts or relied on by other units; the engine has no program for it"]
    live = [f for f in known if not f["test"]]
    if not live:
        return 0.0, ["test code"]
    # where the server acts on the caller's data: not browser code, not a view that only
    # renders (unless it writes), not a script no request reaches
    server = [f for f in live if (f["entry"] or f["reads"] or f["writes"]) and not f["browser"]
              and (f["writes"] or not f["view"]) and f["reached"]]
    s, why = 0.0, []
    numeric = sorted({n for f in server for n in f["numeric"]})
    reads = sum(1 for f in server if f["reads"])
    writes = sum(1 for f in server if f["writes"])
    may_write = sum(1 for f in server if f["may_write"])
    if cls.name == "limits":
        if numeric:
            s += 3 + min(len(numeric), 3)
            why.append("client numbers: " + ", ".join(numeric[:6]))
        # A limit is lost where the caller's value is stored or acted on: a number the caller
        # chooses, or a write (an update can set an allowance field), or a query that may write
        # (SQL, NoSQL, ORM calls: the engine cannot tell their reads from their writes). An
        # endpoint the engine knows only selects records is not audited for it.
        if writes:
            s += 1
            why.append("writes stored data")
        elif may_write:
            s += 1
            why.append("runs a query that may write stored data")
        # a value the server should take from its own records (a price, a plan id) is often
        # text, and the store it is checked against may be one the engine does not model: only
        # when the engine knows of no data access at all
        if not s and not reads and any(f["entry"] and f["client"] and f["passes"] for f in server):
            s += 1
            why.append("an entry point takes client data")
    elif cls.name == "race":
        decided = [f["decided"][0] for f in server if f.get("decided")]
        rmw = [f["read_writes"][0] for f in server if f.get("read_writes")]
        if decided:
            # check-then-act: what two concurrent requests both pass
            s += 5
            r, d, w = decided[0]
            why.append(f"reads stored data at line {r}, branches on it at line {d} and writes at "
                       f"line {w} with no lock, version or atomic write (engine)")
        elif rmw:
            s += 1
            why.append(f"reads stored data at line {rmw[0][0]} and writes at line {rmw[0][1]} "
                       "with no lock, version or atomic write (engine)")
        if writes:
            s += 3
            why.append("writes stored data")
        if reads:
            s += 2
            why.append("reads stored data")
        if numeric:
            s += 1
            why.append("client numbers: " + ", ".join(numeric[:4]))
    elif cls.name in ("workflow", "replay"):
        if writes:
            s += 3
            why.append("writes stored data")
        if reads:
            s += 1
            why.append("reads stored data")
        if cls.name == "workflow" and unit.kind == "handlers" and reads >= 2:
            s += 2
            why.append(f"{reads} sibling handlers reach the same data")
    elif cls.name == "bruteforce":
        cred = sum(1 for f in live if f["credential"])
        if cred:
            s += 5
            why.append(f"{cred} member(s) compare a guess with a stored secret")
        books = [f["credential_callers"] for f in live if f.get("credential_callers")]
        if books:
            s += 3
            why.append(f"writes stored data for {max(books)} caller(s) that compare a guess with a "
                       "stored secret (attempt counting)")
    return s, why


# ---- corroboration -------------------------------------------------------------------------

def corroboration(cls: FlawClass, finding: Dict[str, Any], checks: List[Dict[str, Any]]
                  ) -> Optional[Dict[str, Any]]:
    """The engine answer that backs a finding of `cls`: a `check` of one of the class's kinds,
    run in the agent's own session, that the engine REFUTED in the function the finding names
    (a feasible path without the guard, or a value outside the bound). None when there is none."""
    if not cls.corroborating:
        return None
    from frame.sil.hunt_units import simple_name
    want = simple_name(str(finding.get("handler") or ""))
    for c in checks or []:
        if c.get("kind") in cls.corroborating and c.get("verdict") == "refuted" \
                and want and simple_name(str(c.get("name") or "")) == want:
            return c
    return None


__all__ = ["AUTHZ", "CLASSES", "FlawClass", "LOGIC", "corroboration", "credential_bases", "credential_checks",
           "member_facts", "parse", "report_tool", "score", "system_prompt"]
