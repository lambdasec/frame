"""`check(kind="atomic_write")`: a read-then-write two concurrent requests can both pass, decided
from the packs' `[[concurrency]]` facts (frame/sil/concurrency.py). Proved when the write is
atomic or a lock comes first, refuted when the function reads first and nothing protects it,
unknown otherwise (never refuted when a caller of the same name locks)."""

import json
import textwrap

import pytest

from frame.sil.engine_query import QueryIndex
from frame.sil.packs.loader import tomllib
from frame.sil.packs.schema import PackError, parse_pack


def _check(tmp_path, files, name, line):
    for rel, text in files.items():
        p = tmp_path / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(textwrap.dedent(text).lstrip("\n"))
    q = QueryIndex(str(tmp_path))
    q.build()
    return json.loads(q.ctx.check(name, line, "atomic_write"))


MODELS = {"shop/models.py": """
    from django.db import models

    class Coupon(models.Model):
        uses = models.IntegerField()
        limit = models.IntegerField()
"""}


def test_read_then_write_with_no_protection_is_refuted(tmp_path):
    r = _check(tmp_path, {**MODELS, "shop/views.py": """
        from shop.models import Coupon

        def redeem(code):
            c = Coupon.objects.get(code=code)
            if c.uses < c.limit:
                c.uses = c.uses + 1
                c.save()
    """}, "redeem", 7)
    assert r["verdict"] == "refuted", r
    assert [w["line"] for w in r["witness"]] == [4, 7]


def test_select_for_update_first_is_proved(tmp_path):
    r = _check(tmp_path, {**MODELS, "shop/views.py": """
        from shop.models import Coupon

        def redeem(code):
            c = Coupon.objects.select_for_update().get(code=code)
            if c.uses < c.limit:
                c.uses = c.uses + 1
                c.save()
    """}, "redeem", 7)
    assert r["verdict"] == "proved", r


def test_f_expression_write_is_proved(tmp_path):
    r = _check(tmp_path, {**MODELS, "shop/views.py": """
        from django.db.models import F
        from shop.models import Coupon

        def redeem(code):
            c = Coupon.objects.get(code=code)
            c.uses = F("uses") + 1
            c.save()
    """}, "redeem", 7)
    assert r["verdict"] != "refuted", r        # F() assigned before the save: never a refutation


def test_no_read_before_the_write_is_unknown(tmp_path):
    r = _check(tmp_path, {**MODELS, "shop/views.py": """
        from shop.models import Coupon

        def reset(c):
            c.uses = 0
            c.save()
    """}, "reset", 5)
    assert r["verdict"] == "unknown", r


def test_a_line_without_a_write_is_unknown(tmp_path):
    r = _check(tmp_path, {**MODELS, "shop/views.py": """
        from shop.models import Coupon

        def look(code):
            c = Coupon.objects.get(code=code)
            return c.uses
    """}, "look", 5)
    assert r["verdict"] == "unknown", r


def test_typeorm_increment_is_proved_and_save_is_refuted(tmp_path):
    files = {"stock.service.ts": """
        import { Repository } from 'typeorm';
        export class StockService {
            constructor(private repo: Repository<Level>) {}
            async bump(id: number) {
                const level = await this.repo.findOne({ where: { id } });
                await this.repo.increment({ id }, 'onHand', 1);
            }
            async adjust(id: number, change: number) {
                const level = await this.repo.findOne({ where: { id } });
                await this.repo.update(level.id, { onHand: level.onHand + change });
            }
        }
    """}
    assert _check(tmp_path, files, "StockService.bump", 6)["verdict"] == "proved"
    r = _check(tmp_path, files, "StockService.adjust", 10)
    assert r["verdict"] == "refuted", r


def test_a_caller_that_locks_makes_it_unknown(tmp_path):
    r = _check(tmp_path, {**MODELS, "shop/views.py": """
        from shop.models import Coupon

        def bump(c):
            fresh = Coupon.objects.get(id=c.id)
            fresh.uses = fresh.uses + 1
            fresh.save()

        def redeem(code):
            c = Coupon.objects.select_for_update().get(code=code)
            bump(c)
    """}, "bump", 6)
    assert r["verdict"] == "unknown", r


def test_concurrency_entries_are_validated():
    with pytest.raises(PackError):
        parse_pack(tomllib.loads('[pack]\nname = "x"\nlanguage = "python"\n\n[[concurrency]]\ncall = ["a.b"]\nkind = "mutex"\n'))
    pack = parse_pack(tomllib.loads('[pack]\nname = "x"\nlanguage = "python"\n\n[[concurrency]]\ncall = ["a.b"]\nkind = "lock"\n'))
    assert pack.concurrency == [{"call": ["a.b"], "kind": "lock"}]


def test_a_refuted_atomic_write_corroborates_a_race_finding():
    from frame.sil.hunt_classes import CLASSES, corroboration
    checks = [{"kind": "atomic_write", "name": "redeem", "line": 7, "verdict": "refuted"},
              {"kind": "atomic_write", "name": "reset", "line": 5, "verdict": "unknown"}]
    assert corroboration(CLASSES["race"], {"handler": "redeem"}, checks)["line"] == 7
    assert corroboration(CLASSES["race"], {"handler": "reset"}, checks) is None
    assert corroboration(CLASSES["limits"], {"handler": "redeem"}, checks) is None


def test_unprotected_read_writes_rank_race_units(tmp_path):
    """The `race` class ranks a unit by the read-then-write pairs the check would refute: plane's
    sign-up view scored like hundreds of handlers that merely touch data and sorted 613th."""
    from frame.sil.concurrency import unprotected_read_writes
    files = {**MODELS, "shop/views.py": """
        from shop.models import Coupon

        def redeem(code):
            c = Coupon.objects.get(code=code)
            if c.uses < c.limit:
                c.uses = c.uses + 1
                c.save()

        def redeem_locked(code):
            c = Coupon.objects.select_for_update().get(code=code)
            c.uses = c.uses + 1
            c.save()
    """}
    for rel, text in files.items():
        p = tmp_path / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(textwrap.dedent(text).lstrip("\n"))
    q = QueryIndex(str(tmp_path))
    q.build()
    prog = next(p for p in q.ctx.programs if "redeem" in p.procedures)
    assert unprotected_read_writes(prog, "redeem") == [(4, 7)]
    assert unprotected_read_writes(prog, "redeem_locked") == []


def test_check_then_act_is_told_apart_from_a_plain_read_then_write(tmp_path):
    """Get-then-save is everywhere in a Django app (plane: ~500 handlers); what a race needs is a
    decision on the value read before the write."""
    from frame.sil.concurrency import decided_read_writes
    files = {**MODELS, "shop/views.py": """
        from shop.models import Coupon

        def redeem(code):
            c = Coupon.objects.get(code=code)
            left = c.limit - c.uses
            if left > 0:
                c.uses = c.uses + 1
                c.save()

        def rename(code, name):
            c = Coupon.objects.get(code=code)
            c.name = name
            c.save()
    """}
    for rel, text in files.items():
        p = tmp_path / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(textwrap.dedent(text).lstrip("\n"))
    q = QueryIndex(str(tmp_path))
    q.build()
    prog = next(p for p in q.ctx.programs if "redeem" in p.procedures)
    assert decided_read_writes(prog, "redeem") == [(4, 6, 8)]
    assert decided_read_writes(prog, "rename") == []


# -- protections written as data or SQL text -------------------------------------------------

def test_a_prisma_atomic_number_operation_is_proved_and_a_computed_value_refuted(tmp_path):
    files = {"stock.ts": """
        import { PrismaClient } from '@prisma/client';
        const prisma = new PrismaClient();
        export async function take(id: number) {
            const item = await prisma.item.findUnique({ where: { id } });
            await prisma.item.update({ where: { id }, data: { stock: { decrement: 1 } } });
        }
        export async function takeComputed(id: number) {
            const item = await prisma.item.findUnique({ where: { id } });
            await prisma.item.update({ where: { id }, data: { stock: item.stock - 1 } });
        }
    """}
    assert _check(tmp_path, files, "take", 5)["verdict"] == "proved"
    r = _check(tmp_path, files, "takeComputed", 9)
    assert r["verdict"] == "refuted", r


def test_a_mongo_update_operator_is_proved_and_a_set_of_a_read_value_refuted(tmp_path):
    files = {"shop/stock.py": """
        from pymongo import MongoClient

        client = MongoClient()
        items = client.shop.items


        def take(item_id):
            doc = items.find_one({"_id": item_id})
            items.update_one({"_id": item_id}, {"$inc": {"stock": -1}})


        def take_set(item_id):
            doc = items.find_one({"_id": item_id})
            items.update_one({"_id": item_id}, {"$set": {"stock": doc["stock"] - 1}})
    """}
    assert _check(tmp_path, files, "take", 9)["verdict"] == "proved"
    r = _check(tmp_path, files, "take_set", 14)
    assert r["verdict"] == "refuted", r


SQL_STOCK = {"shop/stock.py": """
    import sqlite3

    conn = sqlite3.connect("shop.db")


    def take(item_id):
        cur = conn.cursor()
        cur.execute("SELECT stock FROM items WHERE id = ?", (item_id,))
        cur.execute("UPDATE items SET stock = stock - 1 WHERE id = ?", (item_id,))


    def take_value(item_id):
        cur = conn.cursor()
        row = cur.execute("SELECT stock FROM items WHERE id = ?", (item_id,)).fetchone()
        cur.execute("UPDATE items SET stock = ? WHERE id = ?", (row[0] - 1, item_id))


    def take_locked(item_id):
        cur = conn.cursor()
        row = cur.execute("SELECT stock FROM items WHERE id = ? FOR UPDATE", (item_id,)).fetchone()
        cur.execute("UPDATE items SET stock = ? WHERE id = ?", (row[0] - 1, item_id))


    def redeem(code):
        cur = conn.cursor()
        cur.execute("SELECT used FROM coupons WHERE code = ?", (code,))
        sql = "UPDATE coupons SET used = 1 WHERE code = ? AND used = 0"
        cur.execute(sql, (code,))
"""}


def test_sql_that_computes_from_the_column_or_locks_first_is_proved(tmp_path):
    assert _check(tmp_path, SQL_STOCK, "take", 9)["verdict"] == "proved"
    r = _check(tmp_path, SQL_STOCK, "take_value", 15)
    assert r["verdict"] == "refuted", r
    assert _check(tmp_path, SQL_STOCK, "take_locked", 21)["verdict"] == "proved"
    # a compare-and-set held in a local: the WHERE re-checks the column the statement sets
    assert _check(tmp_path, SQL_STOCK, "redeem", 28)["verdict"] == "proved"


def test_sequelize_models_increment_and_lock(tmp_path):
    files = {"wallet.js": """
        const { Sequelize, Model, DataTypes } = require('sequelize');
        const sequelize = new Sequelize('sqlite::memory:');
        class Wallet extends Model {}
        Wallet.init({ balance: DataTypes.INTEGER }, { sequelize });
        async function spend(id, amt) {
          const w = await Wallet.findOne({ where: { id } });
          await Wallet.increment('balance', { by: -amt, where: { id } });
        }
        async function spendComputed(id, amt) {
          const w = await Wallet.findOne({ where: { id } });
          await Wallet.update({ balance: w.balance - amt }, { where: { id } });
        }
        async function spendLocked(id, amt, t) {
          const w = await Wallet.findOne({ where: { id }, lock: true, transaction: t });
          await Wallet.update({ balance: w.balance - amt }, { where: { id }, transaction: t });
        }
        module.exports = { spend, spendComputed, spendLocked };
    """}
    assert _check(tmp_path, files, "spend", 7)["verdict"] == "proved"
    r = _check(tmp_path, files, "spendComputed", 11)
    assert r["verdict"] == "refuted", r
    assert _check(tmp_path, files, "spendLocked", 15)["verdict"] == "proved"


def test_sqlalchemy_with_for_update_and_column_expressions(tmp_path):
    files = {"bank/service.py": """
        from sqlalchemy import update
        from sqlalchemy.orm import Session
        from bank.models import Wallet


        def spend(session: Session, wid, amt):
            w = session.query(Wallet).filter_by(id=wid).one()
            w.balance = w.balance - amt
            session.commit()


        def spend_locked(session: Session, wid, amt):
            w = session.query(Wallet).filter_by(id=wid).with_for_update().one()
            w.balance = w.balance - amt
            session.commit()


        def spend_in_sql(session: Session, wid, amt):
            w = session.query(Wallet).filter_by(id=wid).one()
            session.execute(update(Wallet).where(Wallet.id == wid).values(balance=Wallet.balance - amt))
            session.commit()


        def spend_value(session: Session, wid, amt):
            w = session.query(Wallet).filter_by(id=wid).one()
            session.execute(update(Wallet).where(Wallet.id == wid).values(balance=w.balance - amt))
    """}
    r = _check(tmp_path, files, "spend", 9)
    assert r["verdict"] == "refuted", r
    assert _check(tmp_path, files, "spend_locked", 15)["verdict"] == "proved"
    assert _check(tmp_path, files, "spend_in_sql", 20)["verdict"] == "proved"
    r = _check(tmp_path, files, "spend_value", 26)
    assert r["verdict"] != "proved", r


def test_concurrency_keys_and_write_entries_are_validated():
    head = {"pack": {"name": "x", "language": "python"}}
    pack = parse_pack({**head, "concurrency": [{"call": ["a.update"], "kind": "atomic", "keys": ["$inc"]},
                                              {"call": ["a.commit"], "kind": "write"},
                                              {"call": ["a.values"], "kind": "atomic", "self_reference": True}]})
    assert [e["kind"] for e in pack.concurrency] == ["atomic", "write", "atomic"]
    with pytest.raises(PackError):
        parse_pack({**head, "concurrency": [{"call": ["a.b"], "kind": "atomic", "self_reference": "yes"}]})


def test_a_line_picks_the_method_among_same_named_ones(tmp_path):
    files = {**MODELS, "shop/views.py": """
        from shop.models import Coupon


        class First:
            def post(self, request, cid):
                c = Coupon.objects.get(id=cid)
                return c


        class Second:
            def post(self, request, cid):
                c = Coupon.objects.get(id=cid)
                c.uses = c.uses + 1
                c.save()
    """}
    r = _check(tmp_path, files, "post", 14)
    assert r["verdict"] == "refuted", r
