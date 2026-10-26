package com.example.api;

import io.vertx.core.AbstractVerticle;
import io.vertx.core.Promise;
import io.vertx.ext.web.Router;
import io.vertx.ext.web.handler.BodyHandler;
import io.vertx.pgclient.PgConnectOptions;
import io.vertx.pgclient.PgPool;
import io.vertx.sqlclient.PoolOptions;

public class MainVerticle extends AbstractVerticle {

    @Override
    public void start(Promise<Void> startPromise) {
        PgPool pool = PgPool.pool(vertx, new PgConnectOptions().setHost("db").setDatabase("api"), new PoolOptions());
        UserRepository users = new UserRepository(pool);
        UserHandler handler = new UserHandler(users);

        Router router = Router.router(vertx);
        router.route().handler(BodyHandler.create());

        router.get("/users/search").handler(handler::search);
        router.get("/users/:id").handler(handler::show);
        router.post("/users").handler(handler::create);

        router.get("/hello").handler(ctx -> {
            String name = ctx.request().getParam("name");
            ctx.response().putHeader("Content-Type", "text/html").end("<h1>Hello " + name + "</h1>");   // frame-expect: CWE-79
        });

        router.get("/go").handler(ctx -> {
            String next = ctx.queryParam("next").get(0);
            ctx.redirect(next);   // frame-expect: CWE-601
        });

        router.get("/files/:name").handler(ctx -> {
            ctx.response().sendFile("/srv/public/" + ctx.pathParam("name"));   // frame-expect: CWE-22
        });

        vertx.createHttpServer().requestHandler(router).listen(8080)
                .onSuccess(s -> startPromise.complete())
                .onFailure(startPromise::fail);
    }
}
