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
    assert [w["line"] for w in r["witness"]] == [4, 5, 7]     # read, decision, write


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
    # the attribute assigned on the loaded object is the write the commit makes
    r = _check(tmp_path, files, "spend", 8)
    assert r["verdict"] == "refuted" and [w["line"] for w in r["witness"]] == [7, 8], r
    assert _check(tmp_path, files, "spend_locked", 14)["verdict"] == "proved"
    assert _check(tmp_path, files, "spend_locked", 15)["verdict"] == "proved"
    assert _check(tmp_path, files, "spend_in_sql", 20)["verdict"] == "proved"
    r = _check(tmp_path, files, "spend_value", 26)
    assert r["verdict"] != "proved", r


def test_tracked_saves_are_validated():
    head = {"pack": {"name": "x", "language": "csharp"}}
    pack = parse_pack({**head, "concurrency": [{"call": ["a.SaveChanges"], "kind": "write", "tracked": True}]})
    assert pack.concurrency == [{"call": ["a.SaveChanges"], "kind": "write", "tracked": True}]
    for bad in ({"call": ["a.Find"], "kind": "read", "tracked": True},
                {"call": ["a.SaveChanges"], "kind": "write", "tracked": "yes"}):
        with pytest.raises(PackError):
            parse_pack({**head, "concurrency": [bad]})


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


# -- check-then-act, compare-and-set, and the project's own functions ---------------------------

def test_an_atomic_increment_after_a_decision_on_the_same_field_is_refuted(tmp_path):
    """sync-in's link limit: the increment is computed by the database, but the limit was checked
    on the value read before it, so two requests both pass the check."""
    files = {**MODELS, "shop/views.py": """
        from django.db.models import F
        from shop.models import Coupon


        def redeem(cid):
            c = Coupon.objects.get(id=cid)
            if c.uses < c.limit:
                Coupon.objects.filter(id=cid).update(uses=F("uses") + 1)


        def redeem_guarded(cid):
            c = Coupon.objects.get(id=cid)
            if c.uses < c.limit:
                Coupon.objects.filter(id=cid, uses__lt=F("limit")).update(uses=F("uses") + 1)


        def touch(cid):
            c = Coupon.objects.get(id=cid)
            if c is not None:
                Coupon.objects.filter(id=cid).update(uses=F("uses") + 1)
    """}
    r = _check(tmp_path, files, "redeem", 8)
    assert r["verdict"] == "refuted", r
    assert [w["line"] for w in r["witness"]] == [6, 7, 8]
    assert "check-then-act" in r["reason"]
    assert _check(tmp_path, files, "redeem_guarded", 14)["verdict"] == "proved"
    assert _check(tmp_path, files, "touch", 20)["verdict"] == "proved"     # a null check decides nothing


PRISMA_INVITE = {"invite.ts": """
    import { PrismaClient } from '@prisma/client';
    const prisma = new PrismaClient();
    export async function useInvite(code: string) {
        const invite = await prisma.invite.findFirst({ where: { code } });
        if (invite.uses >= invite.maxUses) throw new Error('used up');
        await prisma.invite.update({ where: { id: invite.id }, data: { uses: { increment: 1 } } });
    }
    export async function useInviteGuarded(code: string, max: number) {
        const invite = await prisma.invite.findFirst({ where: { code } });
        if (invite.uses >= invite.maxUses) throw new Error('used up');
        await prisma.invite.updateMany({ where: { id: invite.id, uses: { lt: max } }, data: { uses: { increment: 1 } } });
    }
    export async function useInviteLocked(code: string) {
        return prisma.$transaction(async (tx) => {
            await tx.$queryRaw`SELECT id FROM "Invite" WHERE code = ${code} FOR UPDATE`;
            const invite = await tx.invite.findFirst({ where: { code } });
            if (invite.uses >= invite.maxUses) throw new Error('used up');
            await tx.invite.update({ where: { id: invite.id }, data: { uses: invite.uses + 1 } });
        });
    }
"""}


def test_prisma_check_then_increment_compare_and_set_and_a_raw_lock(tmp_path):
    r = _check(tmp_path, PRISMA_INVITE, "useInvite", 6)
    assert r["verdict"] == "refuted", r
    assert _check(tmp_path, PRISMA_INVITE, "useInviteGuarded", 11)["verdict"] == "proved"
    r = _check(tmp_path, PRISMA_INVITE, "anonymous", 18)
    assert r["verdict"] == "proved", r


DRIZZLE_LINKS = {"links.ts": """
    import { drizzle } from 'drizzle-orm/node-postgres';
    import { and, eq, lt, sql } from 'drizzle-orm';
    import { links } from './schema';
    const db = drizzle(process.env.DB);
    export async function access(uuid: string) {
        const [link] = await db.select().from(links).where(eq(links.uuid, uuid));
        if (link.nbAccess >= link.limitAccess) throw new Error('exceeded');
        await db.update(links).set({ nbAccess: sql`${links.nbAccess} + 1` }).where(eq(links.uuid, uuid));
    }
    export async function accessGuarded(uuid: string) {
        const [link] = await db.select().from(links).where(eq(links.uuid, uuid));
        if (link.nbAccess >= link.limitAccess) throw new Error('exceeded');
        await db.update(links).set({ nbAccess: sql`${links.nbAccess} + 1` })
            .where(and(eq(links.uuid, uuid), lt(links.nbAccess, links.limitAccess)));
    }
    export async function count(uuid: string) {
        const [link] = await db.select().from(links).where(eq(links.uuid, uuid));
        await db.update(links).set({ nbAccess: sql`${links.nbAccess} + 1` }).where(eq(links.uuid, uuid));
    }
    export async function countStale(uuid: string) {
        const [link] = await db.select().from(links).where(eq(links.uuid, uuid));
        await db.update(links).set({ nbAccess: link.nbAccess + 1 }).where(eq(links.uuid, uuid));
    }
"""}


def test_drizzle_atomic_set_compare_and_set_and_a_stale_value(tmp_path):
    r = _check(tmp_path, DRIZZLE_LINKS, "access", 8)
    assert r["verdict"] == "refuted", r
    assert _check(tmp_path, DRIZZLE_LINKS, "accessGuarded", 13)["verdict"] == "proved"
    assert _check(tmp_path, DRIZZLE_LINKS, "count", 18)["verdict"] == "proved"
    r = _check(tmp_path, DRIZZLE_LINKS, "countStale", 22)
    assert r["verdict"] == "refuted", r


def test_mongo_and_sqlalchemy_compare_and_set(tmp_path):
    files = {"shop/stock.py": """
        from pymongo import MongoClient
        from sqlalchemy import update
        from sqlalchemy.orm import Session
        from shop.models import Wallet

        items = MongoClient().shop.items


        def take(item_id):
            doc = items.find_one({"_id": item_id})
            if doc["stock"] > 0:
                items.update_one({"_id": item_id, "stock": {"$gt": 0}}, {"$inc": {"stock": -1}})


        def spend(session: Session, wid, amt):
            w = session.query(Wallet).filter_by(id=wid).one()
            if w.balance >= amt:
                session.execute(update(Wallet).where(Wallet.id == wid, Wallet.balance >= amt)
                                .values(balance=Wallet.balance - amt))
    """}
    assert _check(tmp_path, files, "take", 12)["verdict"] == "proved"
    assert _check(tmp_path, files, "spend", 18)["verdict"] == "proved"


def test_reads_writes_and_locks_through_the_project_s_functions(tmp_path):
    files = {**MODELS, "shop/repo.py": """
        from shop.models import Coupon


        def load(cid):
            return Coupon.objects.get(id=cid)


        def load_locked(cid):
            return Coupon.objects.select_for_update().get(id=cid)


        def store(c: Coupon):
            c.save()
    """, "shop/views.py": """
        from shop.repo import load, load_locked, store


        def redeem(cid):
            c = load(cid)
            if c.uses < c.limit:
                c.uses = c.uses + 1
                store(c)


        def redeem_locked(cid):
            c = load_locked(cid)
            if c.uses < c.limit:
                c.uses = c.uses + 1
                store(c)
    """}
    r = _check(tmp_path, files, "redeem", 8)
    assert r["verdict"] == "refuted", r
    assert [w["line"] for w in r["witness"]] == [5, 6, 8]
    r = _check(tmp_path, files, "redeem_locked", 15)
    assert r["verdict"] == "proved", r


def test_a_lock_after_the_read_is_not_a_protection(tmp_path):
    r = _check(tmp_path, {**MODELS, "shop/views.py": """
        from shop.models import Coupon

        def redeem(cid):
            c = Coupon.objects.get(id=cid)
            Coupon.objects.select_for_update().get(id=cid)
            c.uses = c.uses + 1
            c.save()
    """}, "redeem", 7)
    assert r["verdict"] == "unknown", r
    assert "after the read" in r["reason"]


def test_sql_claims_and_selects(tmp_path):
    from frame.sil.concurrency import sql_effect
    assert sql_effect("INSERT INTO claims (k) VALUES (?) ON CONFLICT (k) DO NOTHING")["guarantee"] == "conditional"
    assert sql_effect("INSERT IGNORE INTO claims (k) VALUES (?)")["guarantee"] == "conditional"
    assert sql_effect("UPDATE c SET used = 1 WHERE id = ? AND used = 0")["guarantee"] == "conditional"
    assert sql_effect("UPDATE c SET n = n + 1 WHERE id = ?")["guarantee"] == "atomic"
    assert sql_effect("SELECT n FROM c WHERE id = ?") == {"write": False, "read": True, "guarantee": None,
                                                          "columns": set()}
    r = _check(tmp_path, SQL_STOCK, "take", 8)              # the SELECT line is not a write
    assert "no write" in r["reason"], r


def test_sql_session_settings_and_explicit_locks():
    from frame.sil.concurrency import sql_effect
    for setting in ("SET LOCAL lock_timeout = '3s'", "BEGIN", "COMMIT", "SAVEPOINT a"):
        assert sql_effect(setting)["read"] is False and sql_effect(setting)["write"] is False, setting
    assert sql_effect("LOCK TABLE coupons IN EXCLUSIVE MODE")["guarantee"] == "lock"
    assert sql_effect("SELECT pg_advisory_xact_lock(hashtext(?))")["guarantee"] == "lock"
    assert sql_effect("SELECT GET_LOCK('signup', 10)")["guarantee"] == "lock"
    # a try-lock that may fail decides nothing by itself
    assert sql_effect("SELECT pg_try_advisory_lock(42)")["guarantee"] is None


def _check_lang(tmp_path, files, language, name, line):
    for rel, text in files.items():
        p = tmp_path / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(textwrap.dedent(text).lstrip("\n"))
    q = QueryIndex(str(tmp_path), language=language)
    q.build()
    return json.loads(q.ctx.check(name, line, "atomic_write"))


JPA = {"shop/CouponRepository.java": """
    package shop;
    import org.springframework.data.jpa.repository.JpaRepository;
    public interface CouponRepository extends JpaRepository<Coupon, Long> {}
""", "shop/CouponService.java": """
    package shop;
    import org.springframework.stereotype.Service;
    @Service
    public class CouponService {
      private final CouponRepository repo;
      public CouponService(CouponRepository repo) { this.repo = repo; }
      public void redeem(Long id) {
        Coupon c = repo.findById(id).orElseThrow();
        if (c.getUses() < 10) {
          c.setUses(c.getUses() + 1);
          repo.save(c);
        }
      }
    }
"""}

COUPON = """
    package shop;
    import jakarta.persistence.Entity;
    import jakarta.persistence.Id;
    import jakarta.persistence.Version;
    @Entity
    public class Coupon {
      @Id private Long id;
      private int uses;
      {version}
      public int getUses() { return uses; }
      public void setUses(int u) { uses = u; }
    }
"""


@pytest.mark.parametrize("version, verdict", [("@Version private Long version;", "proved"),
                                              ("private Long version;", "refuted")])
def test_a_jpa_version_field_is_an_optimistic_lock(tmp_path, version, verdict):
    files = {**JPA, "shop/Coupon.java": COUPON.replace("{version}", version)}
    r = _check_lang(tmp_path, files, "java", "CouponService.redeem", 11)
    assert r["verdict"] == verdict, r


EF = """
    using System.ComponentModel.DataAnnotations;
    using Microsoft.EntityFrameworkCore;
    public class Product {
      public int Id { get; set; }
      public int Stock { get; set; }
      {token}public int Version { get; set; }
    }
    public class ShopContext : DbContext {
      public DbSet<Product> Products { get; set; }
    }
    public class OrderService {
      private readonly ShopContext _db;
      public OrderService(ShopContext db) { _db = db; }
      public void Buy(int id) {
        var p = _db.Products.Find(id);
        if (p.Stock > 0) {
          p.Stock = p.Stock - 1;
          _db.SaveChanges();
        }
      }
    }
"""


@pytest.mark.parametrize("token, verdict", [("[ConcurrencyCheck] ", "proved"), ("", "refuted")])
def test_an_ef_concurrency_token_is_an_optimistic_lock(tmp_path, token, verdict):
    r = _check_lang(tmp_path, {"Shop.cs": EF.replace("{token}", token)}, "csharp", "OrderService.Buy", 18)
    assert r["verdict"] == verdict, r


EF_EXECUTE = """
    using System.Linq;
    using Microsoft.EntityFrameworkCore;
    public class Product { public int Id { get; set; } public int Stock { get; set; } }
    public class ShopContext : DbContext { public DbSet<Product> Products { get; set; } }
    public class OrderService {
      private readonly ShopContext _db;
      public OrderService(ShopContext db) { _db = db; }
      public void Buy(int id) {
        var p = _db.Products.Find(id);
        if (p.Stock > 0) {
          _db.Products.Where(x => x.Id == id{guard}).ExecuteUpdate(s => s.SetProperty(x => x.Stock, {value}));
        }
      }
    }
"""


@pytest.mark.parametrize("guard, value, verdict", [
    (" && x.Stock > 0", "x => x.Stock - 1", "proved"),      # compare-and-set
    ("", "x => x.Stock - 1", "refuted"),                    # atomic, but decided on the stale read
    ("", "p.Stock - 1", "refuted")])                        # the value read before
def test_ef_execute_update(tmp_path, guard, value, verdict):
    text = EF_EXECUTE.replace("{guard}", guard).replace("{value}", value)
    r = _check_lang(tmp_path, {"Shop.cs": text}, "csharp", "OrderService.Buy", 11)
    assert r["verdict"] == verdict, r
