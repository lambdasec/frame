package com.example.api;

import io.vertx.core.json.JsonObject;
import io.vertx.ext.web.RoutingContext;

public class UserHandler {

    private final UserRepository users;

    public UserHandler(UserRepository users) {
        this.users = users;
    }

    public void search(RoutingContext ctx) {
        String term = ctx.request().getParam("q");
        users.search(term, rows -> ctx.json(rows));
    }

    public void show(RoutingContext ctx) {
        String id = ctx.pathParam("id");
        users.byId(id, row -> ctx.json(row));
    }

    public void create(RoutingContext ctx) {
        JsonObject body = ctx.getBodyAsJson();
        users.insert(body.getString("name"), body.getString("email"));
        ctx.response().setStatusCode(201).end();
    }
}
