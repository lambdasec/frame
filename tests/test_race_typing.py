"""Typing the database handles real applications write through, so the race check sees their
writes (each shape is one of logicbench's race cases): a generated Prisma client imported through
a tsconfig alias (zipline), a Drizzle handle typed by a type alias declared in another file
(sync-in), a repository an overloaded project method returns (vendure), a Django model parameter
typed by its annotation, and the line of each link of a multi-line chain."""

import json
import textwrap

from frame.sil.engine_query import QueryIndex


def _index(tmp_path, files, language=None):
    for rel, text in files.items():
        p = tmp_path / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(textwrap.dedent(text).lstrip("\n"))
    q = QueryIndex(str(tmp_path), language=language) if language else QueryIndex(str(tmp_path))
    q.build()
    return q.ctx


def _calls(ctx, proc_name):
    out = []
    for p in ctx.programs:
        proc = p.procedures.get(proc_name)
        if proc is None:
            continue
        for n in proc.nodes.values():
            for i in n.instrs:
                if type(i).__name__ == "Call":
                    out.append((i.loc.line, str(getattr(i.func, "value", i.func)).strip('"'), i.canonical))
    return sorted(out)


ZIPLINE = {
    "tsconfig.json": '{ "compilerOptions": { "baseUrl": ".", "paths": { "@/*": ["src/*"] } } }\n',
    "prisma/schema.prisma": """
        generator client {
          provider = "prisma-client"
          output   = "../src/prisma"
        }
        model Invite {
          id   String @id
          uses Int
        }
    """,
    "src/lib/db/index.ts": """
        import { PrismaClient } from '@/prisma/client';

        let prisma: ExtendedPrismaClient;

        if (!global.__db__) {
          global.__db__ = getClient();
        }

        prisma = global.__db__;

        type ExtendedPrismaClient = ReturnType<typeof getClient>;

        function getClient() {
          const client = new PrismaClient({ log: undefined }).$extends({ result: {} });
          return client;
        }

        export { prisma };
    """,
    "src/routes/register.ts": """
        import { prisma } from '@/lib/db';

        export async function register(code: string) {
          const invite = await prisma.invite.findFirst({ where: { code } });
          if (invite.uses >= invite.maxUses) throw new Error('used');
          await prisma.invite.update({ where: { id: invite.id }, data: { uses: invite.uses + 1 } });
        }
    """,
}


def test_a_generated_prisma_client_imported_through_an_alias_is_prisma(tmp_path):
    ctx = _index(tmp_path, ZIPLINE)
    ids = {name: cid for _, name, cid in _calls(ctx, "register")}
    assert ids["prisma.invite.update"].startswith("@prisma/client.PrismaClient.")
    r = json.loads(ctx.check("register", 6, "atomic_write"))
    assert r["verdict"] == "refuted", r


def test_a_generated_directory_the_schema_does_not_name_is_not_prisma(tmp_path):
    files = dict(ZIPLINE)
    files["prisma/schema.prisma"] = "model Invite {\n  id String @id\n}\n"     # no generator output
    ctx = _index(tmp_path, files)
    ids = {name: cid for _, name, cid in _calls(ctx, "register")}
    assert not str(ids["prisma.invite.update"]).startswith("@prisma/client")


SYNC_IN = {
    "src/db/interfaces.ts": """
        import { MySql2Database } from 'drizzle-orm/mysql2';
        export type DBSchema = MySql2Database<any>;
    """,
    "src/links/links.queries.ts": """
        import { eq, sql } from 'drizzle-orm';
        import { DBSchema } from '../db/interfaces';
        import { links } from './schema';

        export class LinksQueries {
          constructor(private readonly db: DBSchema) {}

          async bump(uuid: string) {
            const [link] = await this.db.select().from(links).where(eq(links.uuid, uuid));
            await this.db.update(links).set({ nbAccess: link.nbAccess + 1 }).where(eq(links.uuid, uuid));
          }
        }
    """,
}


def test_a_handle_typed_by_an_alias_in_another_file_gets_the_library_s_ids(tmp_path):
    ctx = _index(tmp_path, SYNC_IN)
    ids = {name: cid for _, name, cid in _calls(ctx, "LinksQueries.bump")}
    assert ids["this.db.update"] == "drizzle-orm/mysql2.MySql2Database.update"
    r = json.loads(ctx.check("LinksQueries.bump", 10, "atomic_write"))
    assert r["verdict"] == "refuted", r


VENDURE = {
    "conn/connection.ts": """
        import { Injectable } from '@nestjs/common';
        import { DataSource, ObjectLiteral, ObjectType, Repository } from 'typeorm';
        @Injectable()
        export class TransactionalConnection {
            constructor(private dataSource: DataSource) {}
            getRepository<E extends ObjectLiteral>(target: ObjectType<E>): Repository<E>;
            getRepository<E extends ObjectLiteral>(ctx: any, target: ObjectType<E>): Repository<E>;
            getRepository<E extends ObjectLiteral>(ctxOrTarget: any, maybeTarget?: ObjectType<E>): Repository<E> {
                return this.dataSource.getRepository(maybeTarget ?? ctxOrTarget);
            }
        }
    """,
    "svc/stock.service.ts": """
        import { Injectable } from '@nestjs/common';
        import { TransactionalConnection } from '../conn/connection';
        import { StockLevel } from './stock-level.entity';
        @Injectable()
        export class StockLevelService {
            constructor(private connection: TransactionalConnection) {}
            async updateStockOnHand(ctx: any, id: number, change: number) {
                const stockLevel = await this.connection.getRepository(ctx, StockLevel).findOne({ where: { id } });
                if (stockLevel) {
                    await this.connection
                        .getRepository(ctx, StockLevel)
                        .update(stockLevel.id, { stockOnHand: stockLevel.stockOnHand + change });
                }
            }
        }
    """,
}


def test_a_repository_an_overloaded_project_method_returns_is_typed(tmp_path):
    ctx = _index(tmp_path, VENDURE)
    calls = _calls(ctx, "StockLevelService.updateStockOnHand")
    assert (12, "$chain3.update", "typeorm.Repository.update") in calls, calls
    r = json.loads(ctx.check("StockLevelService.updateStockOnHand", 12, "atomic_write"))
    assert r["verdict"] == "refuted", r
    assert r["witness"][0]["event"] == "reads stored data (typeorm.Repository.findOne)"


def test_each_link_of_a_multi_line_chain_keeps_its_own_line(tmp_path):
    ctx = _index(tmp_path, {"q.ts": """
        import { drizzle } from 'drizzle-orm/node-postgres';
        import { eq } from 'drizzle-orm';
        import { links } from './schema';
        const db = drizzle(process.env.DB);
        export async function touch(uuid: string) {
            await db.update(links).set({ n: 1 })
                .where(eq(links.uuid, uuid));
        }
    """})
    lines = {name.rsplit(".", 1)[-1]: line for line, name, _ in _calls(ctx, "touch")}
    assert lines["update"] == 6 and lines["set"] == 6 and lines["where"] == 7, lines


def test_an_annotated_model_parameter_is_an_instance_of_the_model_s_base(tmp_path):
    ctx = _index(tmp_path, {"shop/models.py": """
        from django.db import models

        class Coupon(models.Model):
            uses = models.IntegerField()
    """, "shop/repo.py": """
        from shop.models import Coupon


        def store(c: Coupon):
            c.save()
    """})
    ids = {name: cid for _, name, cid in _calls(ctx, "store")}
    assert ids["c.save"] == "django.db.models.Model.save"


LINKS_MANAGER = """
    import { Injectable } from '@nestjs/common';
    import { LinksQueries } from './links.queries';
    @Injectable()
    export class LinksManager {
      constructor(private readonly linksQueries: LinksQueries) {}
      async linkAccess(uuid: string) {
        const [link, check, ok] = await this.linkEnv(uuid);
        if (!ok) {
          throw new Error(check);
        }
        await this.linksQueries.incrementLinkNbAccess(link.uuid);
      }
      private async linkEnv(uuid: string): Promise<[any, string | true, boolean]> {
        const link = await this.linksQueries.linkFromUUID(uuid);
        const check = this.checkLink(link);
        const ok = check === true;
        return [link, check, ok];
      }
      private checkLink(link: any): string | true {
        if (!link) return 'not found';
        if (link.limitAccess !== 0 && link.nbAccess >= link.limitAccess) return 'exceeded';
        return true;
      }
    }
"""

LINKS_QUERIES = """
    import { drizzle } from 'drizzle-orm/node-postgres';
    import { and, eq, lt, sql } from 'drizzle-orm';
    import { links } from './schema';
    const db = drizzle(process.env.DB);
    export class LinksQueries {
      async linkFromUUID(uuid: string) {
        const [link] = await db.select().from(links).where(eq(links.uuid, uuid));
        return link;
      }
      async incrementLinkNbAccess(uuid: string) {
        await db.update(links).set({ nbAccess: sql`${links.nbAccess} + 1` }).where({where});
      }
    }
"""


def test_a_limit_checked_two_calls_down_before_an_atomic_increment_is_check_then_act(tmp_path):
    """sync-in GHSA-phhw: `linkEnv` reads the link and `checkLink` compares nbAccess with the
    limit; `linkAccess` only tests the returned `ok` before incrementing."""
    files = {"links.manager.ts": LINKS_MANAGER,
             "links.queries.ts": LINKS_QUERIES.replace("{where}", "eq(links.uuid, uuid)")}
    r = json.loads(_index(tmp_path, files).check("LinksManager.linkAccess", 11, "atomic_write"))
    assert r["verdict"] == "refuted", r
    assert r["witness"][1]["event"] == "decides on nbAccess"


def test_the_increment_re_checking_the_limit_itself_is_proved(tmp_path):
    files = {"links.manager.ts": LINKS_MANAGER, "links.queries.ts": LINKS_QUERIES.replace(
        "{where}", "and(eq(links.uuid, uuid), lt(links.nbAccess, links.limitAccess))")}
    r = json.loads(_index(tmp_path, files).check("LinksManager.linkAccess", 11, "atomic_write"))
    assert r["verdict"] == "proved", r


def test_a_conditional_update_written_inside_another_call_s_argument(tmp_path):
    """sync-in's fix: `return dbCheckAffectedRows(await this.db.update(links).set(...).where(...))`."""
    ctx = _index(tmp_path, {**SYNC_IN, "src/links/links.queries.ts": """
        import { and, eq, lt, sql } from 'drizzle-orm';
        import { DBSchema } from '../db/interfaces';
        import { links } from './schema';
        import { affected } from './utils';

        export class LinksQueries {
          constructor(private readonly db: DBSchema) {}

          async consume(uuid: string) {
            const [link] = await this.db.select().from(links).where(eq(links.uuid, uuid));
            if (link.nbAccess >= link.limitAccess) throw new Error('exceeded');
            return affected(await this.db.update(links).set({ nbAccess: sql`${links.nbAccess} + 1` })
              .where(and(eq(links.uuid, uuid), lt(links.nbAccess, links.limitAccess))));
          }
        }
    """})
    r = json.loads(ctx.check("LinksQueries.consume", 12, "atomic_write"))
    assert r["verdict"] == "proved", r
