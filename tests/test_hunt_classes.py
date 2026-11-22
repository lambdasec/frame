"""The business-logic hunt: flaw classes (frame/sil/hunt_classes.py) and the engine's bound check
(frame/sil/logic_facts.py).

What it must guarantee: a bound is `proved` only when every feasible path entails it, `refuted`
only for a value the caller chooses (a request read, copied or converted) with the value that gets
through (NaN past a guard written as `if (v < lo) reject`), and `unknown` for anything computed or
not numeric; a plain scan records none of it; each class audits the units its engine facts select,
with its own instructions and mechanisms; a business-logic finding is `llm_verified` only when an
engine check the agent ran refuted the bound or guard in that function; the authorization hunt is
unchanged when it is the only class."""

import json

import pytest

from frame import config as frame_config
from frame.cli import main
from frame.sil.hunt_classes import CLASSES, corroboration, parse, score
from frame.sil.llm_client import LLMClient, LLMConfig
from frame.sil.llm_hunt import UNIT_SYSTEM, hunt_authz
from frame.sil.logic_facts import check_bound, conversion, numbers
from frame.sil.scanner import FrameScanner

FLASK = '''\
from flask import Flask, request, abort
from models import Order, db

app = Flask(__name__)


@app.route("/cart/add", methods=["POST"])
def add_item():
    qty = int(request.form["qty"])
    order = Order.query.get(request.form["order"])
    order.quantity = qty
    db.session.commit()
    return "ok"


@app.route("/cart/set", methods=["POST"])
def set_item():
    qty = int(request.form["qty"])
    if qty < 1 or qty > 100:
        abort(400)
    order = Order.query.get(request.form["order"])
    order.quantity = qty
    db.session.commit()
    return "ok"


@app.route("/pay", methods=["POST"])
def pay():
    amount = float(request.form["amount"])
    if amount <= 0:
        abort(400)
    charge(amount)
    return "ok"


@app.route("/label", methods=["POST"])
def label():
    size = request.form["size"]
    total = int(request.form["a"]) * 2
    save(size, total)
    return "ok"
'''

EXPRESS = '''\
const express = require("express");
const db = require("./db");
const app = express();

app.post("/refund", async (req, res) => {
  const amount = Number(req.body.amount);
  if (amount < 0 || amount > 500) {
    return res.status(400).send("bad");
  }
  await db.refund(req.body.order, amount);
  res.send("ok");
});

app.post("/tip", async (req, res) => {
  const tip = req.body.tip;
  if (!(tip >= 0)) {
    return res.status(400).send("bad");
  }
  await db.tip(req.body.order, tip);
  res.send("ok");
});

app.post("/give", async (req, res) => {
  const pts = req.body.points;
  if (pts > 1000) {
    return res.status(400).send("too many");
  }
  await db.give(req.body.user, pts);
  res.send("ok");
});
'''


def _programs(tmp_path, name, text, collect=True):
    (tmp_path / name).write_text(text)
    sc = FrameScanner()
    sc.collect_programs = collect
    results = sc.scan_directory(str(tmp_path), None, project_root=str(tmp_path))
    return sc, [v for r in results for v in r.vulnerabilities]


def _program_with(sc, proc):
    return next(p for p in sc._hunt_programs if proc in (p.value_facts or {}) or
                any(n.startswith(proc) for n in (p.value_facts or {})))


def _js_proc(program, line):
    return next(n for n, r in program.value_facts.items() if line in r["pc"] and n != "<module>")


@pytest.fixture
def flask_app(tmp_path):
    sc, findings = _programs(tmp_path, "app.py", FLASK)
    return tmp_path, sc, findings


def test_a_bound_is_refuted_with_the_value_that_gets_through(flask_app):
    _, sc, _ = flask_app
    p = _program_with(sc, "add_item")
    r = check_bound(p, "add_item", 11, "order.quantity", "lower_bound", 1)
    assert r["verdict"] == "refuted"
    assert r["witness"][0]["equals"] < 1 and r["witness"][0]["from"].startswith("request.form")
    assert "int(request.form" in r["origin"]


def test_a_bound_every_path_enforces_is_proved(flask_app):
    _, sc, _ = flask_app
    p = _program_with(sc, "set_item")
    assert check_bound(p, "set_item", 22, "qty", "lower_bound", 1)["verdict"] == "proved"
    assert check_bound(p, "set_item", 22, "order.quantity", "upper_bound", 100)["verdict"] == "proved"
    r = check_bound(p, "set_item", 22, "qty", "upper_bound", 50)
    assert r["verdict"] == "refuted" and 50 < r["witness"][0]["equals"] <= 100


def test_nan_gets_past_a_guard_written_as_a_rejection(flask_app):
    _, sc, _ = flask_app
    p = _program_with(sc, "pay")
    r = check_bound(p, "pay", 32, "amount", "lower_bound", 1)
    assert r["verdict"] == "refuted" and r["witness"][0]["equals"] == "NaN"


def test_raw_text_and_computed_values_are_unknown(flask_app):
    _, sc, _ = flask_app
    p = _program_with(sc, "label")
    assert check_bound(p, "label", 41, "size", "lower_bound", 0)["verdict"] == "unknown"   # text
    assert check_bound(p, "label", 41, "total", "lower_bound", 0)["verdict"] == "unknown"  # computed
    assert check_bound(p, "label", 41, "nope", "lower_bound", 0)["verdict"] == "unknown"
    assert check_bound(p, "label", 41, "size", "lower_bound", "x")["verdict"] == "unknown"


def test_javascript_numbers_json_fields_and_nan(tmp_path):
    sc, _ = _programs(tmp_path, "app.js", EXPRESS)
    p = next(p for p in sc._hunt_programs if p.value_facts and len(p.value_facts) > 1)
    refund = check_bound(p, _js_proc(p, 10), 10, "amount", "lower_bound", 0)
    assert refund["verdict"] == "refuted" and refund["witness"][0]["equals"] == "NaN"
    assert check_bound(p, _js_proc(p, 19), 19, "tip", "lower_bound", 0)["verdict"] == "proved"
    give = check_bound(p, _js_proc(p, 28), 28, "pts", "lower_bound", 0)
    assert give["verdict"] == "refuted" and give["witness"][0]["from"] == "req.body.points"


def test_a_plain_scan_records_no_value_facts(tmp_path):
    (tmp_path / "app.py").write_text(FLASK)
    sc = FrameScanner()
    sc.collect_programs = True
    sc.scan_directory(str(tmp_path), None, project_root=str(tmp_path))
    assert any(p.value_facts for p in sc._hunt_programs)
    from frame.sil.frontends.python_frontend import PythonFrontend
    from frame.sil.translator import SILTranslator
    prog = PythonFrontend().translate(FLASK, str(tmp_path / "app.py"))
    SILTranslator(prog).translate_program()
    assert not prog.value_facts


def test_the_conversion_table_is_strict(tmp_path):
    assert conversion("python", "int").integer and not conversion("python", "int").nan
    assert conversion("typescript", "parseInt").nan
    assert conversion("java", "java.lang.Integer.parseInt").integer
    assert conversion("python", "self.int") is None
    assert numbers().raw["javascript"].nan
    bad = tmp_path / "n.toml"
    bad.write_text('[[conversion]]\nlanguage = "python"\ncalls = ["int"]\nintger = true\n')
    with pytest.raises(ValueError):
        numbers.__wrapped__(bad)


def test_class_names_parse_in_order_and_unknown_ones_fail():
    assert parse(None) == ["authz"]
    assert parse("race,limits") == ["limits", "race"]
    assert parse("logic") == ["limits", "race", "workflow", "replay", "bruteforce"]
    assert parse(["all"])[0] == "authz" and len(parse("all")) == 6
    with pytest.raises(ValueError):
        parse("limts")


def test_the_config_takes_a_list_of_classes(tmp_path):
    s = frame_config.parse_tables({"hunt": {"classes": ["limits", "race"]}}, "x.toml")
    assert s.values["hunt"]["classes"] == ["limits", "race"]
    with pytest.raises(frame_config.SettingsError):
        frame_config.parse_tables({"hunt": {"classes": "limits"}}, "x.toml")


def test_cli_rejects_an_unknown_class(tmp_path, capsys):
    (tmp_path / "a.py").write_text("x = 1\n")
    assert main(["scan", str(tmp_path), "--hunt", "nope"]) == 2
    assert "unknown hunt class" in capsys.readouterr().err


# -- the hunt end to end, with a scripted agent ------------------------------------------------

def _tc(tool, **args):
    return {"content": "", "tool_calls": [{"id": "1", "function": {
        "name": tool, "arguments": json.dumps(args)}}]}


def _client(fn):
    c = LLMClient(LLMConfig(base_url="x", model="m"))
    c.chat_raw = fn
    return c


def _unit_of(messages):
    c = messages[1]["content"]
    return "".join(b.get("text", "") for b in c) if isinstance(c, list) else c


def test_limits_units_are_ranked_by_client_numbers_and_backed_by_the_engine(flask_app):
    root, sc, findings = flask_app
    seen = []

    def chat(messages, tools=None):
        system, intro = messages[0]["content"], _unit_of(messages)
        if not seen or seen[-1][1] != intro:
            seen.append((system, intro, [t["function"]["name"] for t in tools or []],
                         next(t for t in tools if t["function"]["name"] == "report_finding")))
        turn = sum(1 for m in messages if m["role"] == "assistant")
        script = [
            _tc("check", name="add_item", line=11, kind="lower_bound", var="order.quantity", bound=1),
            _tc("report_finding", handler="add_item", file="app.py", line=11, mechanism="missing_limit",
                invariant="an order line holds at least one item",
                violating_request="POST /cart/add qty=-5 order=1 credits five items"),
            _tc("report_finding", handler="pay", file="app.py", line=32, mechanism="missing_limit",
                invariant="a payment is a positive amount",
                violating_request="POST /pay amount=nan charges NaN"),
            _tc("mark_safe", handler="set_item", reason="1 <= qty <= 100 is checked before it is stored"),
            _tc("mark_safe", handler="label", reason="nothing it stores is money or a quantity"),
            {"content": "done", "tool_calls": []}]
        return script[min(turn, len(script) - 1)]

    status = {}
    out = hunt_authz(sc._hunt_programs, findings, str(root), LLMConfig(), client=_client(chat),
                     max_steps=8, status=status, classes=["limits"], scout_steps=0)
    assert status["classes"] == ["limits"] and status["stop"] == "finished"
    system, intro, tools, report = seen[0]
    assert system != UNIT_SYSTEM and "MISSING LIMITS" in system
    assert report["function"]["parameters"]["properties"]["mechanism"]["enum"] == ["missing_limit", "client_trusted_value"]
    assert "client_numbers=[order.quantity, qty]" in intro and "Selected because: client numbers" in intro
    (unit,) = [u for u in status["units"] if u["stop"] != "deferred"]
    assert unit["class"] == "limits" and unit["id"].endswith("::limits")
    by_line = {v.line: v for v in out}
    backed, alone = by_line[11], by_line[32]
    assert backed.source_var == "llm_verified" and backed.cwe_id == "CWE-1284"
    assert "engine: order.quantity = 0 reaches line 11" in backed.description
    assert alone.source_var == "llm_detect"          # no engine check backed it
    assert backed.type.value == "business_logic_flaw"


def test_a_class_audits_only_units_its_facts_select_and_shares_the_budget(flask_app):
    root, sc, findings = flask_app
    from frame.sil.hunt_tools import HuntContext
    from frame.sil.hunt_units import plan_units
    from frame.sil.llm_hunt import _class_units, build_index
    index = build_index(sc._hunt_programs, findings, str(root))
    ctx = HuntContext(index, sc._hunt_programs, str(root), "python", findings)
    planned, _ = plan_units(index, "python")
    s, why = score(CLASSES["limits"], planned[0], ctx)
    assert s > 0 and any("qty" in w for w in why)
    assert score(CLASSES["bruteforce"], planned[0], ctx)[0] == 0      # no secret is compared
    both, rest = _class_units(ctx, planned, ["authz", "limits"], 1)
    assert [u.hunt_class for u in both] == ["authz"] and [u.hunt_class for u in rest] == ["limits"]


def test_corroboration_needs_a_refuted_check_of_the_class_in_that_function():
    lim = CLASSES["limits"]
    checks = [{"name": "add_item", "kind": "lower_bound", "verdict": "refuted", "line": 11},
              {"name": "other", "kind": "lower_bound", "verdict": "refuted", "line": 3},
              {"name": "set_item", "kind": "lower_bound", "verdict": "proved", "line": 22}]
    assert corroboration(lim, {"handler": "add_item"}, checks)["line"] == 11
    assert corroboration(lim, {"handler": "set_item"}, checks) is None
    assert corroboration(CLASSES["workflow"], {"handler": "add_item"}, checks) is None
    assert corroboration(CLASSES["race"], {"handler": "add_item"}, checks) is None


def test_authorization_alone_keeps_its_prompt_and_unit_ids(flask_app):
    root, sc, findings = flask_app
    systems = []

    def chat(messages, tools=None):
        systems.append(messages[0]["content"])
        return {"content": "done", "tool_calls": []}
    status = {}
    hunt_authz(sc._hunt_programs, findings, str(root), LLMConfig(), client=_client(chat),
               max_steps=2, status=status, scout_steps=0)
    assert status["classes"] == ["authz"] and set(systems) == {UNIT_SYSTEM}
    assert all("::" in u["id"] and not u["id"].endswith(("::limits", "::race")) for u in status["units"])


JAVA = '''\
package shop;

import org.springframework.web.bind.annotation.*;

@RestController
public class CartController {
    private final CartService carts;

    public CartController(CartService carts) { this.carts = carts; }

    @PostMapping("/cart/add")
    public String add(@RequestParam int qty, @RequestParam long item) {
        carts.add(item, qty);
        return "ok";
    }

    @PostMapping("/cart/set")
    public String set(@RequestParam String qty, @RequestParam long item) {
        int n = Integer.parseInt(qty);
        if (n < 1) {
            throw new IllegalArgumentException("qty");
        }
        carts.add(item, n);
        return "ok";
    }
}
'''

CSHARP = '''\
using Microsoft.AspNetCore.Mvc;

namespace Shop
{
    [ApiController]
    public class CartApi : ControllerBase
    {
        [HttpPost("/cart/add")]
        public IActionResult Add([FromForm] int qty, [FromForm] long item)
        {
            Carts.Add(item, qty);
            return Ok();
        }

        [HttpPost("/cart/set")]
        public IActionResult Set([FromForm] string qty)
        {
            var n = int.Parse(qty);
            if (n <= 0) return BadRequest();
            Carts.Add(1, n);
            return Ok();
        }
    }
}
'''


@pytest.mark.parametrize("name, text, add, add_line, sett, set_line", [
    ("CartController.java", JAVA, "CartController.add", 13, "CartController.set", 23),
    ("CartApi.cs", CSHARP, "Shop.CartApi.Add", 11, "Shop.CartApi.Set", 20),
])
def test_typed_parameters_and_parsed_numbers_in_java_and_csharp(tmp_path, name, text, add, add_line,
                                                                 sett, set_line):
    # A handler parameter of a number type is client-chosen (the analysis drops it as a taint
    # source: a number carries no injection); a parsed one follows its conversion.
    sc, _ = _programs(tmp_path, name, text)
    p = next(p for p in sc._hunt_programs if add in (p.value_facts or {}))
    r = check_bound(p, add, add_line, "qty", "lower_bound", 1)
    assert r["verdict"] == "refuted" and "declared int" in r["origin"]
    assert check_bound(p, sett, set_line, "n", "lower_bound", 1)["verdict"] == "proved"


def test_a_copy_of_a_reassigned_name_is_not_bounded_by_the_new_value(tmp_path):
    src = '''\
from flask import Flask, request, abort
app = Flask(__name__)


@app.route("/add", methods=["POST"])
def add():
    qty = int(request.form["qty"])
    order.quantity = qty
    qty = 5
    if qty < 1:
        abort(400)
    order.save()
    return "ok"
'''
    sc, _ = _programs(tmp_path, "app.py", src)
    p = _program_with(sc, "add")
    r = check_bound(p, "add", 12, "order.quantity", "lower_bound", 1)
    assert r["verdict"] != "proved" and "assigned more than once" in r["origin"]


# -- what a business-logic class audits: server code, never browser or test code ----------------

BROWSER = '''\
export function useQuantity() {
  const qty = parseInt(new URLSearchParams(location.search).get("qty"));
  if (qty < 1) {
    return 1;
  }
  return qty;
}
'''

SERVER_HELPER = '''\
const express = require("express");
const Order = require("./models/order");
const app = express();

function save(order, qty) {
  return Order.findByIdAndUpdate(order, { quantity: qty });
}

app.post("/cart", async (req, res) => {
  const plan = req.body.planId;
  if (!plan) {
    return res.status(400).send("plan");
  }
  const qty = req.body.qty;
  const total = qty * 3;
  await save(req.body.order, total);
  res.send(plan);
});
'''

MODEL = '''\
const mongoose = require("mongoose");
module.exports = mongoose.model("Order", new mongoose.Schema({ quantity: Number }));
'''

UNITTEST = '''\
import frappe
from app.helpers import BaseCase
from app.utils import slugify


class TestSlugs(BaseCase):
    def test_slug(self):
        qty = int(frappe.form_dict.get("qty"))
        frappe.db.set_value("Order", "o", "qty", qty)
        self.assertEqual(slugify("a b"), "a-b")
'''


def _ctx(tmp_path, files):
    for name, text in files.items():
        (tmp_path / name).parent.mkdir(parents=True, exist_ok=True)
        (tmp_path / name).write_text(text)
    sc = FrameScanner()
    sc.collect_programs = True
    results = sc.scan_directory(str(tmp_path), None, project_root=str(tmp_path))
    findings = [v for r in results for v in r.vulnerabilities]
    from frame.sil.hunt_tools import HuntContext
    from frame.sil.llm_hunt import build_index
    index = build_index(sc._hunt_programs, findings, str(tmp_path))
    return sc, HuntContext(index, sc._hunt_programs, str(tmp_path), "", findings)


def _scouted(*members):
    from frame.sil.hunt_units import Unit
    return Unit(id="u", kind="scouted", title="t", files=[members[0]["file"]], members=list(members))


def test_browser_code_and_test_code_are_not_audited_for_business_logic(tmp_path):
    _, ctx = _ctx(tmp_path, {"web/hooks.js": BROWSER, "app/test_slugs.py": UNITTEST})
    browser = _scouted({"name": "useQuantity", "file": "web/hooks.js", "role": "route"})
    tests = _scouted({"name": "test_slug", "file": "app/test_slugs.py", "role": "service"})
    assert score(CLASSES["limits"], browser, ctx)[0] == 0      # a number the user's own browser picks
    assert score(CLASSES["limits"], tests, ctx) == (0.0, ["test code"])
    assert score(CLASSES["race"], tests, ctx)[0] == 0


def test_a_scouted_route_storing_through_a_helper_is_server_code(tmp_path):
    _, ctx = _ctx(tmp_path, {"server.js": SERVER_HELPER, "models/order.js": MODEL})
    p = next(p for p in ctx.programs if any("save" == n for n in (p.value_facts or {})))
    assert p.value_facts["save"]["data"]                       # a mongoose update: stored data
    route = next(n for n, r in p.value_facts.items() if n not in ("save", "<module>") and 16 in r["pc"])
    s, why = score(CLASSES["limits"], _scouted({"name": route, "file": "server.js", "role": "route"}), ctx)
    assert s > 1 and "runs a query that may write stored data" in why and any("qty" in w for w in why)


DRF_PROJECT = {
    "app/__init__.py": "",
    "app/models.py": ("from django.db import models\n\n"
                      "class Token(models.Model):\n    label = models.CharField(max_length=10)\n"),
    "app/serializers/__init__.py": "from .base import BaseSerializer\nfrom .api import TokenSerializer\n",
    "app/serializers/base.py": ("from rest_framework import serializers\n\n"
                                "class BaseSerializer(serializers.ModelSerializer):\n    pass\n"),
    "app/serializers/api.py": ("from .base import BaseSerializer\nfrom app.models import Token\n\n"
                               "class TokenSerializer(BaseSerializer):\n    class Meta:\n"
                               "        model = Token\n        fields = '__all__'\n"),
    "app/views/base.py": ("from rest_framework.views import APIView\n\n"
                          "class BaseAPIView(APIView):\n    pass\n"),
    "app/views/api.py": ("from rest_framework.response import Response\nfrom .base import BaseAPIView\n"
                         "from app.models import Token\nfrom app.serializers import TokenSerializer\n\n"
                         "class TokenEndpoint(BaseAPIView):\n"
                         "    def patch(self, request, pk):\n"
                         "        s = TokenSerializer(Token.objects.get(pk=pk), data=request.data, partial=True)\n"
                         "        if s.is_valid():\n            s.save()\n"
                         "        return Response(s.data)\n\n"
                         "    def put(self, request, pk):\n"
                         "        t = Token.objects.get(pk=pk)\n        t.label = request.data['label']\n"
                         "        t.save()\n        return Response({})\n\n"
                         "    def get(self, request, pk):\n"
                         "        t = Token.objects.get(pk=pk)\n"
                         "        return Response(TokenSerializer(t).data)\n"),
}


def test_limits_audits_a_django_view_that_writes_not_one_that_only_selects(tmp_path):
    # The view extends a project base view in another file and writes through a project
    # serializer (a ModelSerializer two files away) or a model instance; the GET only selects.
    _, ctx = _ctx(tmp_path, DRF_PROJECT)
    def member(name):
        return _scouted({"name": f"TokenEndpoint.{name}", "file": "app/views/api.py", "role": "route"})
    for name in ("patch", "put"):
        s, why = score(CLASSES["limits"], member(name), ctx)
        assert s > 0 and "writes stored data" in why, name
    assert score(CLASSES["limits"], member("get"), ctx)[0] == 0


def test_a_scouted_member_the_engine_has_no_program_for_keeps_a_base_score(tmp_path):
    _, ctx = _ctx(tmp_path, {"server.js": SERVER_HELPER})
    unseen = _scouted({"name": "Charge", "file": "billing/charge.go", "role": "route"})
    assert score(CLASSES["limits"], unseen, ctx)[0] == 1.0


CLIENT_MODULE = '''\
"use client";
const Order = require("./models/order");

export function bump(order, qty) {
  return Order.findByIdAndUpdate(order, { quantity: qty * 2 });
}
'''

VIEWS = '''\
const Order = require("./models/order");

export function OrderPage({ id }) {
  const order = Order.findById(id);
  return (<div>{order.quantity}</div>);
}

export function loadOrder({ id }) {
  const order = Order.findById(id);
  return order.quantity;
}

export function Badge({ id }) {
  return id ? <p>{id}</p> : null;
}
'''

MIGRATION = '''\
const Order = require("../models/order");

function newId() {
  return Math.random().toString(36);
}

async function run(qty) {
  await Order.updateMany({}, { quantity: qty * 2 });
}

run(Number(process.argv[2]));
'''


def test_a_use_client_module_is_browser_code(tmp_path):
    _, ctx = _ctx(tmp_path, {"web/bump.js": CLIENT_MODULE, "web/models/order.js": MODEL})
    member = _scouted({"name": "bump", "file": "web/bump.js", "role": "service"})
    assert score(CLASSES["limits"], member, ctx)[0] == 0
    assert score(CLASSES["race"], member, ctx)[0] == 0


def test_a_view_that_only_renders_is_not_audited(tmp_path):
    _, ctx = _ctx(tmp_path, {"web/pages.js": VIEWS, "web/models/order.js": MODEL,
                             "web/server.js": 'const p = require("./pages");\n'
                                              'p.OrderPage({ id: 1 }); p.loadOrder({ id: 1 });\n'})
    procs = next(p for p in ctx.programs if "OrderPage" in (p.procedures or {})).procedures
    assert procs["OrderPage"].renders and procs["Badge"].renders and not procs["loadOrder"].renders
    view = _scouted({"name": "OrderPage", "file": "web/pages.js", "role": "route"})
    loader = _scouted({"name": "loadOrder", "file": "web/pages.js", "role": "service"})
    assert score(CLASSES["limits"], view, ctx)[0] == 0         # reads to render, writes nothing
    assert score(CLASSES["limits"], loader, ctx)[0] > 0


IDS = '''\
function newId() {
  return Date.now().toString(36);
}
module.exports = { newId };
'''


def test_a_script_no_request_reaches_is_not_audited(tmp_path):
    # the server calls a newId the script also defines, but imports it from lib/ids.js
    server = SERVER_HELPER.replace('const app = express();',
                                   'const { newId } = require("./lib/ids");\nconst app = express();\nnewId();')
    _, ctx = _ctx(tmp_path, {"migrations/001.js": MIGRATION, "models/order.js": MODEL,
                             "lib/ids.js": IDS, "server.js": server})
    from frame.sil.hunt_classes import _reached_files
    reached = _reached_files(ctx)
    assert "lib/ids.js" in reached and "migrations/001.js" not in reached
    script = _scouted({"name": "run", "file": "migrations/001.js", "role": "service"})
    assert score(CLASSES["limits"], script, ctx)[0] == 0
    assert score(CLASSES["race"], script, ctx)[0] == 0


STORE = '''\
const Order = require("../models/order");

export class OrderStore {
  getRole = computedFn((workspace, project) => {
    return this.roles[workspace][project];
  });

  save(order, qty) {
    return Order.findByIdAndUpdate(order, { quantity: qty * 2 });
  }
}
'''

PAGE = '''\
import { OrderStore } from "./store";

export function OrderPage({ id, qty }) {
  const store = new OrderStore();
  store.save(id, qty);
  return (<div>{store.getRole("w", id)}</div>);
}
'''

PRICE = '''\
const Order = require("../models/order");

function reprice(order, qty) {
  return Order.findByIdAndUpdate(order, { quantity: qty * 2 });
}
module.exports = { reprice };
'''

ROUTES = '''\
const { reprice } = require("../lib/price");

function charge(req) {
  return reprice(req.order, req.qty);
}
module.exports = { charge };
'''


def test_a_store_only_components_call_is_not_audited(tmp_path):
    # Plane's MobX stores: no "use client", called by components, never by a request; one method
    # is a wrapped class field the engine has no procedure for by name
    server = SERVER_HELPER.replace('const app = express();',
                                   'const { reprice } = require("./lib/price");\nconst app = express();')
    server = server.replace("await save(req.body.order, total);", "await reprice(req.body.order, total);")
    _, ctx = _ctx(tmp_path, {"server.js": server, "models/order.js": MODEL, "lib/price.js": PRICE,
                             "web/store.js": STORE, "web/page.js": PAGE})
    from frame.sil.hunt_classes import _reached_files
    reached = _reached_files(ctx)
    assert "lib/price.js" in reached and "web/store.js" not in reached and "web/page.js" not in reached
    assert ctx.locate("OrderStore.getRole", "web/store.js") is None
    wrapped = _scouted({"name": "OrderStore.getRole", "file": "web/store.js", "role": "scouted_helper"})
    assert score(CLASSES["limits"], wrapped, ctx) == (0.0, ["browser code or code no request reaches"])
    writes = _scouted({"name": "OrderStore.save", "file": "web/store.js", "role": "scouted_service"})
    assert score(CLASSES["limits"], writes, ctx)[0] == 0      # writes, but only the browser calls it
    helper = _scouted({"name": "reprice", "file": "lib/price.js", "role": "scouted_service"})
    assert score(CLASSES["limits"], helper, ctx)[0] > 0
    unseen = _scouted({"name": "Charge", "file": "billing/charge.go", "role": "scouted_route"})
    assert score(CLASSES["limits"], unseen, ctx)[0] == 1.0    # a file the engine does not parse


def test_a_route_the_scouts_found_makes_what_it_calls_reached(tmp_path):
    # the engine sees one server; the scouts found a route in a convention it does not know
    _, ctx = _ctx(tmp_path, {"server.js": SERVER_HELPER, "models/order.js": MODEL,
                             "lib/price.js": PRICE, "routes/api.js": ROUTES,
                             "web/store.js": STORE, "web/page.js": PAGE})
    from frame.sil.hunt_classes import _reached_files
    assert "lib/price.js" not in _reached_files(ctx)
    ctx.scouted_routes = [("routes/api.js", "charge"), ("web/page.js", "OrderPage")]
    reached = _reached_files(ctx)
    assert {"routes/api.js", "lib/price.js"} <= reached
    assert "web/store.js" not in reached                       # a page that renders is not a route
    helper = _scouted({"name": "reprice", "file": "lib/price.js", "role": "scouted_service"})
    assert score(CLASSES["limits"], helper, ctx)[0] > 0


FASTAPI = '''\
from fastapi import FastAPI
import billing

app = FastAPI()


@app.post("/pay")
def pay(amount: float, plan_id: str):
    return billing.charge(plan_id, amount)


@app.post("/subscribe")
def subscribe(plan_id: str):
    return billing.subscribe(plan_id)


@app.get("/meta")
def meta(slug: str):
    return {"title": f"Post {slug}"}
'''


def test_a_python_number_annotation_is_a_client_number(tmp_path):
    _, ctx = _ctx(tmp_path, {"api.py": FASTAPI})
    s, why = score(CLASSES["limits"], _scouted({"name": "pay", "file": "api.py", "role": "route"}), ctx)
    assert s > 1 and any("amount" in w for w in why)


def test_an_entry_point_taking_client_text_is_audited_for_trusted_values(tmp_path):
    # a plan id is text and the store it should be checked against is one the engine does not
    # model, yet the server should not take it on trust (CWE-472)
    _, ctx = _ctx(tmp_path, {"api.py": FASTAPI})
    s, why = score(CLASSES["limits"], _scouted({"name": "subscribe", "file": "api.py", "role": "route"}), ctx)
    assert s == 1 and why == ["an entry point takes client data"]
    # one that only formats what it was sent hands it to nothing
    assert score(CLASSES["limits"], _scouted({"name": "meta", "file": "api.py", "role": "route"}), ctx)[0] == 0


def test_a_raw_javascript_value_is_a_number_only_when_the_code_uses_it_as_one(tmp_path):
    _, ctx = _ctx(tmp_path, {"server.js": SERVER_HELPER, "models/order.js": MODEL})
    p = next(p for p in ctx.programs if "save" in (p.value_facts or {}))
    route = next(n for n, r in p.value_facts.items() if n not in ("save", "<module>") and 16 in r["pc"])
    plan = check_bound(p, route, 16, "plan", "lower_bound", 1)
    assert plan["verdict"] == "unknown" and "not used as a number" in plan["reason"]   # an id
    qty = check_bound(p, route, 16, "qty", "lower_bound", 1)
    assert qty["verdict"] == "refuted"                         # multiplied: a quantity, unbounded


def test_an_agent_reply_cut_off_at_the_output_limit_is_not_its_answer():
    from frame.sil.llm_agent import TRUNCATED_NUDGE, run_agent
    replies = [({"content": "", "tool_calls": []}, "length"),
               ({"content": "", "tool_calls": [{"id": "1", "function": {"name": "note", "arguments": "{}"}}]}, "tool_calls"),
               ({"content": "done", "tool_calls": []}, "stop")]

    class C:
        last_call: dict = {}

        def chat_raw(self, messages, tools=None):
            msg, finish = replies.pop(0)
            self.last_call = {"status": "ok", "finish_reason": finish}
            return msg

    ran = []
    r = run_agent([{"role": "system", "content": "s"}, {"role": "user", "content": "u"}], C(),
                  tools=[], exec_tool=lambda n, a: ran.append(n) or "ok", max_steps=6,
                  finalize=lambda c: c)
    assert r.stop == "finished" and r.result == "done" and ran == ["note"]
    assert any(m.get("content") == TRUNCATED_NUDGE for m in r.transcript)


def test_one_flaw_reported_at_the_handler_and_its_service_is_one_finding(tmp_path):
    from frame.sil.llm_hunt import _merge_layers
    _, ctx = _ctx(tmp_path, {"server.js": SERVER_HELPER, "models/order.js": MODEL})
    p = next(p for p in ctx.programs if "save" in (p.value_facts or {}))
    route = next(n for n, r in p.value_facts.items() if n not in ("save", "<module>") and 16 in r["pc"])
    handler = {"hunt_class": "limits", "mechanism": "missing_limit", "handler": route, "file": "server.js",
               "line": 16, "reasoning": "qty unbounded"}
    service = {"hunt_class": "limits", "mechanism": "missing_limit", "handler": "save", "file": "server.js",
               "line": 6, "reasoning": "stores qty"}
    other = {"hunt_class": "limits", "mechanism": "client_trusted_value", "handler": "save",
             "file": "server.js", "line": 6, "reasoning": "price"}
    authz = {"hunt_class": "authz", "mechanism": "idor", "handler": route, "file": "server.js", "line": 16}
    kept = _merge_layers([handler, service, other, authz], ctx)
    assert service in kept and handler not in kept and other in kept and authz in kept
    assert "also reported at server.js:16" in service["reasoning"]
    backed = dict(handler, engine_fact={"kind": "lower_bound"})
    assert _merge_layers([backed, dict(service)], ctx) == [backed]   # only the caller is engine-backed


def test_a_tsx_file_is_parsed_with_the_tsx_grammar(tmp_path):
    # the TypeScript grammar reads `(<div>...)` as a type assertion and an error
    page = ('export default function Page({ params }: { params: { id: string } }) {\n'
            '  const { id } = params;\n'
            '  return (\n    <main title={id}>\n      <p>{id}</p>\n    </main>\n  );\n}\n')
    _, ctx = _ctx(tmp_path, {"app/page.tsx": page})
    prog = next(p for p in ctx.programs if "Page" in p.procedures)
    assert prog.procedures["Page"].renders
    assert getattr(prog, "syntax_error_line", None) is None


PASSWORD_HELPERS = {
    "app/security.py": ("from werkzeug.security import check_password_hash\n\n"
                        "def _verify(stored, guess):\n    return check_password_hash(stored, guess)\n\n"
                        "def password_ok(user, guess):\n    return _verify(user.password_hash, guess)\n"),
    "app/views.py": ("from flask import Flask, request\nfrom app.security import password_ok\n"
                     "app = Flask(__name__)\n\n"
                     "@app.route('/login', methods=['POST'])\n"
                     "def login():\n"
                     "    user = find_user(request.form['name'])\n"
                     "    if password_ok(user, request.form['password']):\n        return 'ok'\n"
                     "    return 'no', 401\n\n"
                     "@app.route('/ping')\n"
                     "def ping():\n    return 'pong'\n"),
}


def test_bruteforce_follows_a_password_check_through_the_application_s_helpers(tmp_path):
    # The route verifies the guess through two project helpers before the library call
    # (duplicati: VerifyWebserverPassword -> PbkdfConfig.VerifyPassword -> FixedTimeEquals).
    _, ctx = _ctx(tmp_path, PASSWORD_HELPERS)
    login = _scouted({"name": "login", "file": "app/views.py", "role": "route"})
    ping = _scouted({"name": "ping", "file": "app/views.py", "role": "route"})
    s, why = score(CLASSES["bruteforce"], login, ctx)
    assert s > 0 and any("compare a guess with a stored secret" in w for w in why)
    assert score(CLASSES["bruteforce"], ping, ctx)[0] == 0


CSHARP_PASSWORD = {
    "Server/Settings.cs": ("using System;\nusing System.Security.Cryptography;\n\nnamespace App.Server\n{\n"
                           "    public class Settings\n    {\n        public string Hash;\n"
                           "        public bool VerifyPassword(string password)\n"
                           "            => CryptographicOperations.FixedTimeEquals(Convert.FromBase64String(Hash), "
                           "Convert.FromBase64String(password));\n    }\n}\n"),
    "Web/Auth.cs": ("using App.Server;\n\nnamespace App.Web\n{\n    public class Auth\n    {\n"
                    "        private Settings settings;\n"
                    "        public string Login(string password)\n        {\n"
                    "            if (!settings.VerifyPassword(password))\n"
                    "                throw new UnauthorizedAccessException(\"no\");\n"
                    "            return \"token\";\n        }\n    }\n}\n"),
}


def test_bruteforce_sees_a_password_check_written_inside_a_condition(tmp_path):
    # `if (!settings.VerifyPassword(p))` is an expression in the branch condition, not a Call, and
    # the helper's `CryptographicOperations.FixedTimeEquals` is resolved through its using.
    _, ctx = _ctx(tmp_path, CSHARP_PASSWORD)
    login = _scouted({"name": "App.Web.Auth.Login", "file": "Web/Auth.cs", "role": "route"})
    s, why = score(CLASSES["bruteforce"], login, ctx)
    assert s > 0 and any("compare a guess with a stored secret" in w for w in why), why


ATTEMPT_COUNTER = {
    "src/users-queries.service.ts": (
        "import { drizzle } from 'drizzle-orm/node-postgres';\n"
        "import { check } from './utils';\n"
        "const db = drizzle(process.env.DATABASE_URL);\n"
        "export class UsersQueries {\n"
        "  async updateAccesses(id: number, mode: string) {\n"
        "    check(await db.update(users).set({ attempts: mode }), 1)\n"
        "    return true\n  }\n"
        "  async rename(id: number, name: string) {\n"
        "    check(await db.update(users).set({ name }), 1)\n  }\n}\n"),
    "src/utils.ts": "export function check(r: any, n: number) { return r }\n",
    "src/users-manager.service.ts": (
        "import bcrypt from 'bcryptjs';\n"
        "import { UsersQueries } from './users-queries.service';\n"
        "export class UsersManager {\n"
        "  constructor(private readonly usersQueries: UsersQueries) {}\n"
        "  async logUser(user: any, password: string) {\n"
        "    const ok: boolean = await bcrypt.compare(password, user.password)\n"
        "    this.updateAccesses(user, ok).catch((e: Error) => console.log(e))\n"
        "    return ok\n  }\n"
        "  async updateAccesses(user: any, ok: boolean) {\n"
        "    if (!(await this.usersQueries.updateAccesses(user.id, ok ? 'reset' : 'increment'))) {\n"
        "      throw new Error('not updated')\n    }\n  }\n"
        "  async rename(user: any, name: string) {\n"
        "    await this.usersQueries.rename(user.id, name)\n  }\n}\n"),
}


def test_bruteforce_ranks_the_attempt_counter_a_password_check_writes(tmp_path):
    # Sync-in: the lockout flaw is in `UsersManager.updateAccesses`, which writes the failed-attempt
    # count for `logUser` after `bcrypt.compare`. The write is nested in another call's argument,
    # and `this.usersQueries.updateAccesses` shares its name with the caller (resolved by callee id).
    _, ctx = _ctx(tmp_path, ATTEMPT_COUNTER)
    counter = _scouted({"name": "UsersManager.updateAccesses", "file": "src/users-manager.service.ts",
                        "role": "service"})
    rename = _scouted({"name": "UsersManager.rename", "file": "src/users-manager.service.ts",
                       "role": "service"})
    s, why = score(CLASSES["bruteforce"], counter, ctx)
    assert s > 0 and any("attempt counting" in w for w in why), why
    assert score(CLASSES["bruteforce"], rename, ctx)[0] == 0


WEBAUTHN_VIEW = {
    "accounts/views.py": (
        "from django.views.generic import View\n"
        "from django_otp_webauthn.views import CompleteCredentialAuthenticationView\n\n"
        "class SecondFactorMixin(View):\n"
        "    def second_factor_completed(self, device):\n        return device\n\n"
        "class CompleteView(SecondFactorMixin, CompleteCredentialAuthenticationView):\n"
        "    def complete_auth(self, device):\n        return self.second_factor_completed(device)\n\n"
        "class ProfileView(SecondFactorMixin):\n"
        "    def get(self, request):\n        return request.user\n"),
    "accounts/urls.py": ("from django.urls import path\nfrom accounts.views import CompleteView, ProfileView\n"
                         "urlpatterns = [path('webauthn/', CompleteView.as_view()),\n"
                         "               path('profile/', ProfileView.as_view())]\n"),
}


def test_bruteforce_sees_a_check_the_view_inherits_from_its_library_base(tmp_path):
    # Weblate: the WebAuthn view verifies the assertion in django-otp-webauthn's own methods;
    # nothing the application writes calls a check.
    _, ctx = _ctx(tmp_path, WEBAUTHN_VIEW)
    view = _scouted({"name": "CompleteView.complete_auth", "file": "accounts/views.py", "role": "route"})
    other = _scouted({"name": "ProfileView.get", "file": "accounts/views.py", "role": "route"})
    s, why = score(CLASSES["bruteforce"], view, ctx)
    assert s > 0 and any("compare a guess with a stored secret" in w for w in why), why
    assert score(CLASSES["bruteforce"], other, ctx)[0] == 0
