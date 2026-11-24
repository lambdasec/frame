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


def _line_of(tmp_path, rel, needle):
    return next(i + 1 for i, text in enumerate((tmp_path / rel).read_text().splitlines()) if needle in text)


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


# -- C# repositories over EF Core (simplcommerce GHSA-jphx) ------------------------------------

SIMPL = {
    "Infra/IRepository.cs": """
        using System.Linq;
        namespace Shop.Infrastructure.Data
        {
            public interface IRepository<T>
            {
                IQueryable<T> Query();
                void Add(T entity);
                void SaveChanges();
            }
        }
    """,
    "Core/Repository.cs": """
        using System.Linq;
        using Microsoft.EntityFrameworkCore;
        using Shop.Infrastructure.Data;
        namespace Shop.Core.Data
        {
            public class RepositoryWithTypedId<T, TId> where T : class
            {
                public RepositoryWithTypedId(ShopDbContext context)
                {
                    Context = context;
                    DbSet = Context.Set<T>();
                }
                protected DbContext Context { get; }
                protected DbSet<T> DbSet { get; }
                public void Add(T entity)
                {
                    DbSet.Add(entity);
                }
                public void SaveChanges()
                {
                    Context.SaveChanges();
                }
                public IQueryable<T> Query()
                {
                    return DbSet;
                }
            }
            public class Repository<T> : RepositoryWithTypedId<T, long>, IRepository<T> where T : class
            {
                public Repository(ShopDbContext context) : base(context)
                {
                }
            }
            public class AuditLog
            {
                public void SaveChanges()
                {
                }
            }
            public class ShopDbContext : DbContext
            {
            }
        }
    """,
    "Orders/OrderService.cs": """
        using System;
        using System.Linq;
        using System.Threading.Tasks;
        using Microsoft.EntityFrameworkCore;
        using Shop.Infrastructure.Data;
        namespace Shop.Orders
        {
            public class Product { public int StockQuantity { get; set; } }
            public class CheckoutItem { public Product Product { get; set; } public int Quantity { get; set; } }
            public class Checkout { public Guid Id { get; set; } public System.Collections.Generic.List<CheckoutItem> CheckoutItems { get; set; } }
            public class Order { public string Note { get; set; } }
            public class OrderService
            {
                private readonly IRepository<Order> _orderRepository;
                private readonly IRepository<Checkout> _checkoutRepository;
                public OrderService(IRepository<Order> orderRepository, IRepository<Checkout> checkoutRepository)
                {
                    _orderRepository = orderRepository;
                    _checkoutRepository = checkoutRepository;
                }
                public async Task<bool> CreateOrder(Guid checkoutId)
                {
                    var checkout = await _checkoutRepository
                       .Query()
                       .Where(x => x.Id == checkoutId).FirstOrDefaultAsync();
                    var order = new Order();
                    foreach (var checkoutItem in checkout.CheckoutItems)
                    {
                        if (checkoutItem.Product.StockQuantity < checkoutItem.Quantity)
                        {
                            return false;
                        }
                        checkoutItem.Product.StockQuantity = checkoutItem.Product.StockQuantity - checkoutItem.Quantity;
                    }
                    order.Note = "new";
                    _orderRepository.Add(order);
                    _orderRepository.SaveChanges();
                    return true;
                }
            }
        }
    """,
}


def test_a_change_to_an_entity_read_through_a_project_repository_is_a_write_its_save_makes(tmp_path):
    """The read is `_repo.Query()` (a project method returning its `DbSet<T>`) chained with LINQ
    over lines; `SaveChanges` is the inherited base's (two classes define one), reached through
    the field's interface type; the write is the assignment to the tracked entity."""
    ctx = _index(tmp_path, SIMPL, language="csharp")
    rel = "Orders/OrderService.cs"
    write = _line_of(tmp_path, rel, "StockQuantity = checkoutItem")
    r = json.loads(ctx.check("Shop.Orders.OrderService.CreateOrder", write, "atomic_write"))
    assert r["verdict"] == "refuted", r
    assert r["witness"][0] == {"line": _line_of(tmp_path, rel, "var checkout"), "event":
                               "reads stored data (Microsoft.EntityFrameworkCore.DbSet.Where.FirstOrDefaultAsync)"}
    assert r["witness"][1] == {"line": _line_of(tmp_path, rel, "if (checkoutItem"), "event": "decides on StockQuantity"}
    # a property of an entity the function created is no write of what it read
    r = json.loads(ctx.check("Shop.Orders.OrderService.CreateOrder", _line_of(tmp_path, rel, "order.Note"),
                             "atomic_write"))
    assert "no write of stored data" in r["reason"], r


EF_FLUENT = {
    "Db.cs": """
        using Microsoft.EntityFrameworkCore;
        using Microsoft.EntityFrameworkCore.Metadata.Builders;
        namespace Shop
        {
            public class Product { public int Id { get; set; } public int Stock { get; set; } public byte[] Version { get; set; } }
            public class Coupon { public int Id { get; set; } public int Uses { get; set; } public int Rev { get; set; } }
            public class Order { public int Id { get; set; } public int Total { get; set; } }
            public class Gift { public int Id { get; set; } public int Left { get; set; } public byte[] Stamp { get; set; } }
            public class ShopContext : DbContext
            {
                public DbSet<Product> Products { get; set; }
                public DbSet<Coupon> Coupons { get; set; }
                public DbSet<Order> Orders { get; set; }
                public DbSet<Gift> Gifts { get; set; }
                protected override void OnModelCreating(ModelBuilder modelBuilder)
                {
                    modelBuilder.Entity<Product>().Property(p => p.Version).IsRowVersion();
                    modelBuilder.Entity<Gift>(b =>
                    {
                        b.HasKey(g => g.Id);
                        b.Property(g => g.Stamp).IsRowVersion();
                    });
                }
            }
            public class CouponConfiguration : IEntityTypeConfiguration<Coupon>
            {
                public void Configure(EntityTypeBuilder<Coupon> builder)
                {
                    builder.Property(c => c.Rev).IsConcurrencyToken();
                }
            }
        }
    """,
    "Svc.cs": """
        using System.Threading.Tasks;
        using Microsoft.EntityFrameworkCore;
        namespace Shop
        {
            public class StockService
            {
                private readonly ShopContext _db;
                public StockService(ShopContext db)
                {
                    _db = db;
                }
                public async Task Take(int id, int n)
                {
                    var p = await _db.Products.FindAsync(id);
                    p.Stock = p.Stock - n;
                    await _db.SaveChangesAsync();
                }
                public async Task Use(int id)
                {
                    var c = await _db.Coupons.FindAsync(id);
                    c.Uses = c.Uses + 1;
                    await _db.SaveChangesAsync();
                }
                public async Task Bump(int id)
                {
                    var o = await _db.Orders.FindAsync(id);
                    o.Total = o.Total + 1;
                    await _db.SaveChangesAsync();
                }
                public async Task Give(int id)
                {
                    var g = await _db.Gifts.FindAsync(id);
                    g.Left = g.Left - 1;
                    await _db.SaveChangesAsync();
                }
            }
        }
    """,
}


def test_ef_core_concurrency_tokens_configured_with_the_fluent_api(tmp_path):
    ctx = _index(tmp_path, EF_FLUENT, language="csharp")
    for name, needle in (("Take", "p.Stock = "), ("Use", "c.Uses = "), ("Give", "g.Left = ")):
        r = json.loads(ctx.check(f"Shop.StockService.{name}", _line_of(tmp_path, "Svc.cs", needle), "atomic_write"))
        assert r["verdict"] == "proved" and "optimistic lock" in r["reason"], (name, r)
    r = json.loads(ctx.check("Shop.StockService.Bump", _line_of(tmp_path, "Svc.cs", "o.Total = "),
                             "atomic_write"))     # no token on Order
    assert r["verdict"] == "refuted", r


def test_a_multi_line_csharp_receiver_keeps_its_declared_type(tmp_path):
    ctx = _index(tmp_path, SIMPL, language="csharp")
    calls = [i for p in ctx.programs for proc in p.procedures.values() if proc.name.endswith("CreateOrder")
             for n in proc.nodes.values() for i in n.instrs if type(i).__name__ == "Call"]
    first = min(calls, key=lambda c: c.loc.line)
    assert first.get_func_name() == "_checkoutRepository.Query" and first.callee_class == "IRepository"


# -- Medusa: services injected into typed fields; a lock taken after the read, then re-read ----

MEDUSA = """
    import { ModulesSdkTypes, Context } from "@medusajs/framework/types"
    import { SqlEntityManager } from "@medusajs/framework/mikro-orm/postgresql"

    type InjectedDependencies = { promotionService: any }

    export default class PromotionModuleService {
      protected promotionService_: ModulesSdkTypes.IMedusaInternalService<any>

      constructor({ promotionService }: InjectedDependencies) {
        this.promotionService_ = promotionService
      }

      protected async listActive_(filters: any, sharedContext?: Context) {
        return await this.promotionService_.list(filters, {}, sharedContext)
      }

      async registerUsage(codes: string[], sharedContext: Context = {}) {
        const usage = new Map<string, any>()
        {reads}
        for (const promotion of existing) {
          const used = (promotion.used ?? 0) + 1
          if (used > promotion.limit) {
            throw new Error("Promotion usage exceeds the limit.")
          }
          usage.set(promotion.id, { id: promotion.id, used })
        }
        await this.promotionService_.update(Array.from(usage.values()), sharedContext)
      }
    }
"""

LOCKED = """let existing = await this.listActive_({ code: codes }, sharedContext)
        const ids = existing.map((p) => p.id)
        const manager = sharedContext.transactionManager as SqlEntityManager
        const knex = manager?.getTransactionContext()
        await knex("promotion")
          .whereIn("id", ids)
          .forUpdate()
          .select("id")
        {again}"""


def _medusa(tmp_path, reads):
    ctx = _index(tmp_path, {"promotion-module.ts": MEDUSA.replace("{reads}", reads)})
    line = next(i + 1 for i, text in enumerate((tmp_path / "promotion-module.ts").read_text().splitlines())
                if "promotionService_.update" in text)
    return json.loads(ctx.check("PromotionModuleService.registerUsage", line, "atomic_write"))


def test_a_service_held_in_a_field_declared_with_a_library_type(tmp_path):
    """medusa GHSA-6r9h: the container's destructured argument names no type; the field's
    declaration does."""
    r = _medusa(tmp_path, "const existing = await this.listActive_({ code: codes }, sharedContext)")
    assert r["verdict"] == "refuted", r
    assert r["witness"][0]["event"] == "reads stored data (PromotionModuleService.listActive_)"


def test_rows_locked_after_a_read_that_only_picks_them_then_read_again(tmp_path):
    """medusa's fix: read the promotions, lock their rows with knex's forUpdate through the
    MikroORM transaction, read them again, write."""
    r = _medusa(tmp_path, LOCKED.replace(
        "{again}", "existing = await this.listActive_({ code: codes }, sharedContext)"))
    assert r["verdict"] == "proved" and "reads again under the lock" in r["reason"], r


def test_a_lock_after_the_read_whose_values_are_still_used_is_not_proof(tmp_path):
    r = _medusa(tmp_path, LOCKED.replace("{again}", "const fresh = await this.listActive_({ code: codes }, sharedContext)"))
    assert r["verdict"] == "unknown" and "comes after the read" in r["reason"], r


# -- Mongoose: optimisticConcurrency on the model's schema ------------------------------------

def _mongoose(tmp_path, option):
    return _index(tmp_path, {
        "models/coupon.js": f"""
            const mongoose = require('mongoose');
            const couponSchema = new mongoose.Schema({{ code: String, uses: Number, maxUses: Number }}{option});
            module.exports = mongoose.model('Coupon', couponSchema);
        """,
        "redeem.js": """
            const Coupon = require('./models/coupon');
            async function redeem(code) {
              const coupon = await Coupon.findOne({ code });
              if (coupon.uses >= coupon.maxUses) throw new Error('used up');
              coupon.uses = coupon.uses + 1;
              await coupon.save();
            }
            module.exports = { redeem };
        """})


def test_a_document_of_a_model_whose_schema_checks_versions_is_saved_conditionally(tmp_path):
    ctx = _mongoose(tmp_path, ", { optimisticConcurrency: true }")
    r = json.loads(ctx.check("redeem", _line_of(tmp_path, "redeem.js", "coupon.save"), "atomic_write"))
    assert r["verdict"] == "proved" and "optimisticConcurrency" in r["reason"], r


def test_without_the_option_or_with_it_off_a_document_save_is_a_plain_write(tmp_path):
    for option in ("", ", { optimisticConcurrency: false }"):
        ctx = _mongoose(tmp_path, option)
        r = json.loads(ctx.check("redeem", _line_of(tmp_path, "redeem.js", "coupon.save"), "atomic_write"))
        assert r["verdict"] == "refuted", (option, r)


# -- Spring WebFlux: the decision and the write inside a lambda (appsmith GHSA-9wcp) ----------

APPSMITH = {
    "src/com/acme/UserRepository.java": """
        package com.acme;
        import org.springframework.data.mongodb.repository.ReactiveMongoRepository;
        import reactor.core.publisher.Mono;
        public interface UserRepository extends ReactiveMongoRepository<User, String> {
            Mono<Long> countByIsSystemGenerated(boolean generated);
        }
    """,
    "src/com/acme/User.java": """
        package com.acme;
        public class User {
            private String email;
            public void setEmail(String e) { email = e; }
        }
    """,
    "src/com/acme/UserService.java": """
        package com.acme;
        import reactor.core.publisher.Mono;
        public class UserService {
            private final UserRepository repository;
            public UserService(UserRepository repository) {
                this.repository = repository;
            }
            public Mono<Boolean> isUsersEmpty() {
                return repository.countByIsSystemGenerated(false).map(count -> count == 0);
            }
            public Mono<User> create(User user) {
                return repository.save(user);
            }
        }
    """,
    "src/com/acme/Signup.java": """
        package com.acme;
        import reactor.core.publisher.Mono;
        public class Signup {
            private final UserService userService;
            public Signup(UserService userService) {
                this.userService = userService;
            }
            public Mono<User> signupSuper(String email) {
                return userService
                        .isUsersEmpty()
                        .flatMap(isEmpty -> {
                            if (!Boolean.TRUE.equals(isEmpty)) {
                                return Mono.error(new IllegalStateException("exists"));
                            }
                            final User user = new User();
                            user.setEmail(email);
                            return userService.create(user);
                        });
            }
        }
    """,
}


def test_a_check_and_a_write_inside_a_reactive_lambda_follow_the_read_they_chain_on(tmp_path):
    ctx = _index(tmp_path, APPSMITH, language="java")
    rel = "src/com/acme/Signup.java"
    r = json.loads(ctx.check("Signup.signupSuper", _line_of(tmp_path, rel, "userService.create"), "atomic_write"))
    assert r["verdict"] == "refuted", r
    assert [w["line"] for w in r["witness"]] == [
        _line_of(tmp_path, rel, "return userService"), _line_of(tmp_path, rel, "if (!Boolean"),
        _line_of(tmp_path, rel, "userService.create")]


# -- Fastify: plugins handed to fastify-plugin through a project wrapper (zipline) ------------

def test_a_plugin_registered_through_a_project_wrapper_gets_the_fastify_instance(tmp_path):
    ctx = _index(tmp_path, {
        "tsconfig.json": '{ "compilerOptions": { "baseUrl": ".", "paths": { "@/*": ["src/*"] } } }\n',
        "src/server/typedPlugin.ts": """
            import fastifyPlugin from 'fastify-plugin';
            export default function typedPlugin(plugin: any, opts?: any) {
              return fastifyPlugin(plugin as any, opts);
            }
        """,
        "src/server/routes/register.ts": """
            import typedPlugin from '@/server/typedPlugin';
            export const PATH = '/api/auth/register';
            export default typedPlugin(
              async (server) => {
                server.post(PATH, { schema: {} }, async (req, res) => {
                  return res.send({ ok: true });
                });
              },
              { name: PATH },
            );
        """})
    handlers = [h for h in ctx.index.handlers if h.file == "src/server/routes/register.ts"]
    assert len(handlers) == 1 and handlers[0].line == 5, [(h.name, h.line) for h in ctx.index.handlers]


def test_a_typescript_local_declared_or_cast_with_a_library_type(tmp_path):
    ctx = _index(tmp_path, {"q.ts": """
        import { SqlEntityManager } from '@mikro-orm/postgresql';
        import { EntityManager } from '@mikro-orm/core';
        export async function run(ctx: any) {
          const manager = ctx.transactionManager as SqlEntityManager;
          const em: EntityManager = ctx.em;
          manager?.getKnex();
          em.flush();
        }
    """})
    ids = {name: cid for _, name, cid in _calls(ctx, "run")}
    assert ids["manager?.getKnex"] == "@mikro-orm/postgresql.SqlEntityManager.getKnex"
    assert ids["em.flush"] == "@mikro-orm/core.EntityManager.flush"


CLAIM_REPOSITORY = """
    package com.acme;
    import org.bson.Document;
    import org.springframework.data.mongodb.core.FindAndModifyOptions;
    import org.springframework.data.mongodb.core.ReactiveMongoOperations;
    import org.springframework.data.mongodb.core.query.Criteria;
    import org.springframework.data.mongodb.core.query.Query;
    import org.springframework.data.mongodb.core.query.Update;
    import reactor.core.publisher.Mono;
    public class ClaimRepository {
        private final ReactiveMongoOperations ops;
        public ClaimRepository(ReactiveMongoOperations ops) {
            this.ops = ops;
        }
        public Mono<Boolean> claimSlot() {
            Query query = new Query(Criteria.where("_id").is("super-user-setup"));
            Update update = new Update().setOnInsert("_id", "super-user-setup").setOnInsert("status", "CLAIMED");
            FindAndModifyOptions options = FindAndModifyOptions.options().upsert(true).returnNew(false);
            return ops.findAndModify(query, update, options, Document.class, "superUserSetupLock")
                    .hasElement()
                    .map(existed -> !existed);
        }
    }
"""

SIGNUP_CLAIMED = """
    package com.acme;
    import reactor.core.publisher.Mono;
    public class SignupFixed {
        private final UserService userService;
        private final ClaimRepository claims;
        public SignupFixed(UserService userService, ClaimRepository claims) {
            this.userService = userService;
            this.claims = claims;
        }
        public Mono<User> signupSuper(String email) {
            return claims.claimSlot().flatMap(claimed -> {
                {check}
                return createSuper(email);
            });
        }
        private Mono<User> createSuper(String email) {
            return userService
                    .isUsersEmpty()
                    .flatMap(isEmpty -> {
                        if (!Boolean.TRUE.equals(isEmpty)) {
                            return Mono.error(new IllegalStateException("exists"));
                        }
                        final User user = new User();
                        user.setEmail(email);
                        return userService.create(user);
                    });
        }
    }
"""


def _claimed(tmp_path, check):
    files = {**APPSMITH, "src/com/acme/ClaimRepository.java": CLAIM_REPOSITORY,
             "src/com/acme/SignupFixed.java": SIGNUP_CLAIMED.replace("{check}", check)}
    ctx = _index(tmp_path, files, language="java")
    rel = "src/com/acme/SignupFixed.java"
    outer = json.loads(ctx.check("SignupFixed.signupSuper", _line_of(tmp_path, rel, "return createSuper"),
                                 "atomic_write"))
    inner = json.loads(ctx.check("SignupFixed.createSuper", _line_of(tmp_path, rel, "userService.create"),
                                 "atomic_write"))
    return outer, inner


def test_a_claim_the_code_goes_on_from_only_when_it_won_serializes_what_follows(tmp_path):
    """appsmith's fix: `findAndModify` upserting a fixed `_id` with `setOnInsert` (one request
    inserts it), then the signup only when the claim did."""
    outer, inner = _claimed(tmp_path, 'if (!Boolean.TRUE.equals(claimed)) { return Mono.error(new IllegalStateException("taken")); }')
    assert outer["verdict"] == "proved" and "claims what it changes" in outer["reason"], outer
    assert inner["verdict"] == "unknown" and "claims first" in inner["reason"], inner


def test_a_claim_whose_result_is_not_checked_protects_nothing(tmp_path):
    outer, inner = _claimed(tmp_path, "")
    assert outer["verdict"] != "proved", outer
    assert inner["verdict"] == "refuted", inner


def test_a_sql_claim_checked_before_the_read_serializes_what_follows(tmp_path):
    ctx = _index(tmp_path, {"svc.js": """
        const { Pool } = require('pg');
        const pool = new Pool();
        async function redeem(code, user) {
          const claim = await pool.query('INSERT INTO claims (code, user_id) VALUES ($1, $2) ON CONFLICT DO NOTHING', [code, user]);
          if (claim.rowCount === 0) throw new Error('taken');
          const { rows } = await pool.query('SELECT uses, max_uses FROM coupons WHERE code = $1', [code]);
          if (rows[0].uses >= rows[0].max_uses) throw new Error('used up');
          await pool.query('UPDATE coupons SET uses = $1 WHERE code = $2', [rows[0].uses + 1, code]);
        }
        async function redeemLate(code, user) {
          const { rows } = await pool.query('SELECT uses, max_uses FROM coupons WHERE code = $1', [code]);
          const claim = await pool.query('INSERT INTO claims (code, user_id) VALUES ($1, $2) ON CONFLICT DO NOTHING', [code, user]);
          if (claim.rowCount === 0) throw new Error('taken');
          await pool.query('UPDATE coupons SET uses = $1 WHERE code = $2', [rows[0].uses + 1, code]);
        }
        module.exports = { redeem, redeemLate };
    """})
    lines = [i + 1 for i, t in enumerate((tmp_path / "svc.js").read_text().splitlines()) if "UPDATE coupons" in t]
    r = json.loads(ctx.check("redeem", lines[0], "atomic_write"))
    assert r["verdict"] == "proved" and "claims what it changes" in r["reason"], r
    r = json.loads(ctx.check("redeemLate", lines[1], "atomic_write"))       # the read came first
    assert r["verdict"] == "refuted", r


def test_a_field_an_ancestor_declares_with_a_type_parameter_has_the_type_the_subclass_binds(tmp_path):
    """appsmith: `protected final R repository` in `BaseService<R, T, ID>`, `UserServiceImpl extends
    BaseService<UserRepository, User, String>`, and `isUsersEmpty` implemented by the fragment
    `CustomUserRepositoryImpl` of the Spring Data repository `UserRepository`."""
    ctx = _index(tmp_path, {
        "src/BaseService.java": """
            public abstract class BaseService<R extends BaseRepository, T, ID> {
                protected final R repository;
                public BaseService(R repository) { this.repository = repository; }
            }
        """,
        "src/BaseRepository.java": "public interface BaseRepository {}\n",
        "src/CustomUserRepository.java": "public interface CustomUserRepository { boolean isUsersEmpty(); }\n",
        "src/UserRepository.java": "public interface UserRepository extends BaseRepository, CustomUserRepository {}\n",
        "src/CustomUserRepositoryImpl.java": """
            public class CustomUserRepositoryImpl implements CustomUserRepository {
                public boolean isUsersEmpty() { return true; }
            }
        """,
        "src/OtherImpl.java": "public class OtherImpl { public boolean isUsersEmpty() { return false; } }\n",
        "src/UserServiceImpl.java": """
            public class UserServiceImpl extends BaseService<UserRepository, User, String> {
                public UserServiceImpl(UserRepository r) { super(r); }
                public boolean isUsersEmpty() { return repository.isUsersEmpty(); }
            }
        """}, language="java")
    d = ctx.resolve_call("src/UserServiceImpl.java", "UserServiceImpl.isUsersEmpty", "repository.isUsersEmpty")
    assert d is not None and d["name"] == "CustomUserRepositoryImpl.isUsersEmpty", d


# -- a project's own fluent query builder (appsmith's QueryAllParams) --------------------------

FLUENT = {
    "src/com/acme/params/QueryAllParams.java": """
        package com.acme.params;
        import com.acme.repo.BaseRepositoryImpl;
        import org.springframework.data.mongodb.core.query.Criteria;
        import reactor.core.publisher.Flux;
        import reactor.core.publisher.Mono;
        public class QueryAllParams<T> {
            private final BaseRepositoryImpl<T> repo;
            private int limit;
            public QueryAllParams(BaseRepositoryImpl<T> repo) { this.repo = repo; }
            public QueryAllParams<T> criteria(Criteria c) {
                if (c == null) {
                    return this;
                }
                return this;
            }
            public QueryAllParams<T> limit(int n) { this.limit = n; return this; }
            public Flux<T> all() { return repo.queryAllExecute(this); }
            public <P> Flux<P> all(Class<P> projection) { return repo.queryAllExecute(this, projection); }
            public Mono<Long> count() { return repo.countExecute(this); }
            public Mono<Integer> touch() { return repo.touchExecute(this); }
        }
    """,
    "src/com/acme/repo/BaseRepositoryImpl.java": """
        package com.acme.repo;
        import com.acme.params.QueryAllParams;
        import org.springframework.data.mongodb.core.ReactiveMongoOperations;
        import org.springframework.data.mongodb.core.query.Query;
        import reactor.core.publisher.Flux;
        import reactor.core.publisher.Mono;
        public class BaseRepositoryImpl<T> {
            protected ReactiveMongoOperations mongoOperations;
            protected Class<T> genericDomain;
            public QueryAllParams<T> queryBuilder() { return new QueryAllParams<>(this); }
            public Flux<T> queryAllExecute(QueryAllParams<T> params) {
                return mongoOperations.find(new Query(), genericDomain);
            }
            public <P> Flux<P> queryAllExecute(QueryAllParams<T> params, Class<P> projection) {
                return mongoOperations.find(new Query(), projection);
            }
            public Mono<Long> countExecute(QueryAllParams<T> params) {
                return mongoOperations.count(new Query(), genericDomain);
            }
            public Mono<Integer> touchExecute(QueryAllParams<T> params) { return Mono.just(1); }
        }
    """,
    "src/com/acme/repo/UserRepositoryImpl.java": """
        package com.acme.repo;
        import org.springframework.data.mongodb.core.query.Criteria;
        import reactor.core.publisher.Mono;
        public class UserRepositoryImpl extends BaseRepositoryImpl<User> {
            public Mono<Boolean> isUsersEmpty() {
                return queryBuilder()
                        .criteria(Criteria.where("isSystemGenerated").is(false))
                        .limit(1)
                        .all(IdOnly.class)
                        .count()
                        .map(count -> count == 0);
            }
            public Mono<Integer> touchAll() {
                return queryBuilder().limit(1).all().then(queryBuilder().touch());
            }
        }
    """,
    "src/com/acme/Signup.java": """
        package com.acme;
        import com.acme.repo.UserRepositoryImpl;
        import org.springframework.data.mongodb.core.ReactiveMongoOperations;
        import reactor.core.publisher.Mono;
        public class Signup {
            private final UserRepositoryImpl repository;
            private final ReactiveMongoOperations mongoOperations;
            public Signup(UserRepositoryImpl repository, ReactiveMongoOperations mongoOperations) {
                this.repository = repository;
                this.mongoOperations = mongoOperations;
            }
            public Mono<User> signupSuper(String email) {
                return repository
                        .isUsersEmpty()
                        .flatMap(isEmpty -> {
                            if (!Boolean.TRUE.equals(isEmpty)) {
                                return Mono.error(new IllegalStateException("exists"));
                            }
                            final User user = new User();
                            return mongoOperations.save(user);
                        });
            }
        }
    """,
}


def test_a_read_made_through_the_project_s_own_fluent_query_builder(tmp_path):
    """appsmith: `queryBuilder().criteria(..).limit(1).all(IdOnly.class).count()`, each link a
    method of the project class `QueryAllParams` that `queryBuilder` is declared to return; `all`
    reads through the repository's two-argument `queryAllExecute` (an overload named by its callee
    id is chosen by arity). The `count()` called on the Flux `all` returns is the library's, not
    the builder's own `count`."""
    from frame.sil.concurrency import events, _fluent_links
    ctx = _index(tmp_path, FLUENT, language="java")
    rel = "src/com/acme/repo/UserRepositoryImpl.java"
    prog = next(p for p in ctx.programs if "UserRepositoryImpl.isUsersEmpty" in p.procedures)
    proc = prog.procedures["UserRepositoryImpl.isUsersEmpty"]
    linked = [(c.get_func_name().rsplit(".", 1)[-1], d["name"]) for c, d in _fluent_links(ctx, rel, proc)]
    assert linked == [("criteria", "QueryAllParams.criteria"), ("limit", "QueryAllParams.limit"),
                      ("all", "QueryAllParams.all#2")], linked
    ev, _ = events(prog, proc, ctx=ctx, file=rel)
    assert set(ev.reads.values()) == {"QueryAllParams.all#2"}, ev.reads


def test_a_check_on_a_read_made_through_the_builder_then_a_write_is_refuted(tmp_path):
    ctx = _index(tmp_path, FLUENT, language="java")
    rel = "src/com/acme/Signup.java"
    r = json.loads(ctx.check("Signup.signupSuper", _line_of(tmp_path, rel, "mongoOperations.save"), "atomic_write"))
    assert r["verdict"] == "refuted", r
    assert [w["line"] for w in r["witness"]][:2] == [
        _line_of(tmp_path, rel, "return repository"), _line_of(tmp_path, rel, "if (!Boolean")], r


def test_a_repository_field_declared_with_a_type_parameter_of_a_base_service(tmp_path):
    """appsmith: `protected final R repository` in `BaseService<R, T, ID>`, `UserServiceCEImpl
    extends BaseService<UserRepository, User, String>`, `UserRepository` a Spring Data
    repository: `repository.findFirstBy..()` and `repository.save(u)` inside a lambda are the
    repository's read and write, so a check between them is check-then-act."""
    ctx = _index(tmp_path, {
        "src/com/acme/svc/BaseService.java": """
            package com.acme.svc;
            import com.acme.repo.BaseRepository;
            public abstract class BaseService<R extends BaseRepository<T, ID>, T, ID> {
                protected final R repository;
                public BaseService(R repository) { this.repository = repository; }
            }
        """,
        "src/com/acme/repo/BaseRepository.java": """
            package com.acme.repo;
            import org.springframework.data.mongodb.repository.ReactiveMongoRepository;
            public interface BaseRepository<T, ID> extends ReactiveMongoRepository<T, ID> {}
        """,
        "src/com/acme/repo/UserRepository.java": """
            package com.acme.repo;
            import com.acme.User;
            import reactor.core.publisher.Mono;
            public interface UserRepository extends BaseRepository<User, String> {
                Mono<User> findFirstByEmail(String email);
            }
        """,
        "src/com/acme/svc/UserService.java": """
            package com.acme.svc;
            import com.acme.User;
            import com.acme.repo.UserRepository;
            import reactor.core.publisher.Mono;
            public class UserService extends BaseService<UserRepository, User, String> {
                public UserService(UserRepository r) { super(r); }
                public Mono<User> enable(String email) {
                    return repository.findFirstByEmail(email).flatMap(saved -> {
                        if (saved.isEnabled()) {
                            return Mono.error(new IllegalStateException("exists"));
                        }
                        saved.setEnabled(true);
                        return repository.save(saved);
                    });
                }
            }
        """}, language="java")
    rel = "src/com/acme/svc/UserService.java"
    r = json.loads(ctx.check("UserService.enable", _line_of(tmp_path, rel, "repository.save"), "atomic_write"))
    assert r["verdict"] == "refuted", r
    assert r["witness"][0]["line"] == _line_of(tmp_path, rel, "repository.findFirstByEmail"), r
