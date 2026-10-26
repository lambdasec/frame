package com.example.board;

import io.javalin.http.Context;

public class PostHandlers {

    private final PostDao dao;

    public PostHandlers(PostDao dao) {
        this.dao = dao;
    }

    public void search(Context ctx) {
        ctx.json(dao.search(ctx.queryParam("q")));
    }

    public void show(Context ctx) {
        ctx.json(dao.byId(ctx.pathParam("id")));
    }
}
