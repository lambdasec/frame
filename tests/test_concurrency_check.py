"""`check(kind="atomic_write")`: a read-then-write two concurrent requests can both pass, decided
from the packs' `[[concurrency]]` facts (frame/sil/concurrency.py). Proved when the write is
atomic or a lock comes first, refuted when the function reads first and nothing protects it,
unknown otherwise (never refuted when a caller of the same name locks)."""

import json
import textwrap

import pytest

from frame.sil.engine_query import QueryIndex
import tomllib

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
