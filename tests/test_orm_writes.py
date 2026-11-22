"""ORM writes in JavaScript/TypeScript as data facts: a procedure that writes stored data through
TypeORM, Prisma or Drizzle is a service-layer function with `writes`, which the business-logic
hunt plans units from. The values are typed the way an application declares them: an injected
`Repository<E>`, `new PrismaClient()`, a driver's `drizzle(...)`, a TypeScript alias of a library
type (`type DB = MySql2Database<S> & {...}`, in another file too), or a project method declared
to return a library type (Vendure's `TransactionalConnection.getRepository(): Repository<E>`)."""

import textwrap

from frame.sil.scanner import FrameScanner, language_extensions


def _facts(root):
    sc = FrameScanner()
    sc.collect_programs = True
    sc.scan_directory(str(root), None, extensions=language_extensions(None), project_root=str(root))
    services, writes = set(), set()
    for program in sc._hunt_programs:
        services |= set(getattr(program, "service_functions", None) or {})
        for name, facts in (getattr(program, "value_facts", None) or {}).items():
            if isinstance(facts, dict) and facts.get("writes"):
                writes.add(name)
    return services, writes


def _write(root, files):
    for rel, text in files.items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(textwrap.dedent(text))


def test_typeorm_injected_repository_write(tmp_path):
    _write(tmp_path, {"stock.service.ts": """
        import { InjectRepository } from '@nestjs/typeorm';
        import { Repository } from 'typeorm';
        export class StockService {
            constructor(@InjectRepository(Level) private repo: Repository<Level>) {}
            async adjust(id: number, change: number) {
                const level = await this.repo.findOne({ where: { id } });
                await this.repo.update(level.id, { onHand: level.onHand + change });
            }
            async read(id: number) {
                return this.repo.findOne({ where: { id } });
            }
        }
    """})
    services, writes = _facts(tmp_path)
    assert "StockService.adjust" in services and "StockService.adjust" in writes
    assert "StockService.read" not in writes          # a find is not a write


def test_prisma_model_write(tmp_path):
    _write(tmp_path, {"coupons.ts": """
        import { PrismaClient } from '@prisma/client';
        const prisma = new PrismaClient();
        export async function redeem(code: string) {
            const c = await prisma.coupon.findUnique({ where: { code } });
            await prisma.coupon.update({ where: { code }, data: { uses: c.uses + 1 } });
        }
        export async function look(code: string) {
            return prisma.coupon.findUnique({ where: { code } });
        }
    """})
    services, writes = _facts(tmp_path)
    assert "redeem" in writes and "redeem" in services
    assert "look" not in writes


def test_drizzle_factory_and_transaction(tmp_path):
    _write(tmp_path, {"db.ts": """
        import { drizzle } from 'drizzle-orm/node-postgres';
        const db = drizzle(process.env.DATABASE_URL);
        export async function close(id: number) {
            await db.transaction(async (tx) => {
                await tx.update(orders).set({ open: false });
            });
        }
        export async function drop() {
            await db.delete(orders);
        }
    """})
    _, writes = _facts(tmp_path)
    assert "drop" in writes
    assert any(name not in ("drop", "<module>", "close") for name in writes)   # the tx callback


def test_typescript_alias_of_a_library_type_across_files(tmp_path):
    _write(tmp_path, {
        "db/database.interface.ts": """
            import type { MySql2Database } from 'drizzle-orm/mysql2';
            import type { Pool } from 'mysql2';
            export type DBSchema = MySql2Database<typeof schema> & { $client: Pool };
            export type Either = MySql2Database<typeof schema> | Pool;
        """,
        "links/links-queries.service.ts": """
            import { eq, sql } from 'drizzle-orm';
            import type { DBSchema, Either } from '../db/database.interface';
            export class LinksQueries {
                constructor(private readonly db: DBSchema, private readonly other: Either) {}
                async increment(uuid: string) {
                    await this.db.update(links).set({ n: sql`${links.n} + 1` }).where(eq(links.uuid, uuid));
                }
                async maybe(uuid: string) {
                    await this.other.update(links).set({ n: 1 });
                }
            }
        """})
    services, writes = _facts(tmp_path)
    assert "LinksQueries.increment" in writes and "LinksQueries.increment" in services
    assert "LinksQueries.maybe" not in writes        # a union could be either: it names no type


def test_project_method_declared_to_return_a_library_type(tmp_path):
    _write(tmp_path, {
        "connection/transactional-connection.ts": """
            import { DataSource, ObjectLiteral, ObjectType, Repository } from 'typeorm';
            import { Local } from './local';
            export class TransactionalConnection {
                constructor(private readonly dataSource: DataSource) {}
                getRepository<E extends ObjectLiteral>(ctx: unknown, target: ObjectType<E>): Repository<E> {
                    return this.dataSource.getRepository(target);
                }
                getLocal(): Local {
                    return new Local();
                }
            }
        """,
        "service/stock-level.service.ts": """
            import { TransactionalConnection } from '../connection/transactional-connection';
            export class StockLevelService {
                constructor(private connection: TransactionalConnection) {}
                async updateStock(ctx: unknown, id: number, change: number) {
                    const s = await this.connection.getRepository(ctx, StockLevel).findOne({ where: { id } });
                    await this.connection.getRepository(ctx, StockLevel).update(s.id, { onHand: s.onHand + change });
                }
                async local() {
                    await this.connection.getLocal().update(1);
                }
            }
        """})
    services, writes = _facts(tmp_path)
    assert "StockLevelService.updateStock" in writes and "StockLevelService.updateStock" in services
    assert "StockLevelService.local" not in writes   # a project type names no library write


def test_spring_data_repository_and_jpa_writes(tmp_path):
    _write(tmp_path, {
        "com/shop/CouponRepository.java": """
            package com.shop;
            import org.springframework.data.jpa.repository.JpaRepository;
            public interface CouponRepository extends JpaRepository<Coupon, Long> {}
        """,
        "com/shop/CouponService.java": """
            package com.shop;
            import jakarta.persistence.EntityManager;
            public class CouponService {
                private final CouponRepository repo;
                private final EntityManager em;
                public CouponService(CouponRepository repo, EntityManager em) { this.repo = repo; this.em = em; }
                public void redeem(Long id) {
                    Coupon c = repo.findById(id).orElseThrow();
                    c.setUses(c.getUses() + 1);
                    repo.save(c);
                }
                public void merge(Coupon c) { em.merge(c); }
                public Coupon look(Long id) { return repo.findById(id).orElseThrow(); }
            }
        """})
    services, writes = _facts(tmp_path)
    assert {"CouponService.redeem", "CouponService.merge"} <= writes
    assert "CouponService.redeem" in services
    assert "CouponService.look" not in writes


def test_ef_core_context_write(tmp_path):
    _write(tmp_path, {"Shop.cs": """
        using Microsoft.EntityFrameworkCore;
        public class ShopContext : DbContext { public DbSet<Coupon> Coupons { get; set; } }
        public class CouponService {
            private readonly ShopContext _db;
            public CouponService(ShopContext db) { _db = db; }
            public void Redeem(int id) {
                var c = _db.Coupons.Find(id);
                c.Uses += 1;
                _db.SaveChanges();
            }
            public Coupon Look(int id) { return _db.Coupons.Find(id); }
        }
    """})
    services, writes = _facts(tmp_path)
    assert "CouponService.Redeem" in writes and "CouponService.Redeem" in services
    assert "CouponService.Look" not in writes


def test_a_write_inside_another_call_s_argument_is_a_write(tmp_path):
    # Sync-in: `dbCheckAffectedRows(await this.db.update(users).set(set)..., 1)`; the write is an
    # expression in the argument, and the method chained on its result has no name of its own.
    _write(tmp_path, {"q.ts": """
        import { drizzle } from 'drizzle-orm/node-postgres';
        import { check } from './u';
        const db = drizzle(process.env.DATABASE_URL);
        export class Q {
            async nested(id: number) { check(await db.update(users).set({ a: 1 }), 1); }
            async reads(id: number) { return check(1, 1); }
        }
    """, "u.ts": "export function check(r: any, n: number) { return r }\n"})
    _, writes = _facts(tmp_path)
    assert "Q.nested" in writes and "Q.reads" not in writes
