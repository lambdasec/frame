package com.example.board;

import io.javalin.Javalin;

public class App {

    public static void main(String[] args) {
        PostDao dao = new PostDao();
        PostHandlers handlers = new PostHandlers(dao);

        Javalin app = Javalin.create().start(7070);

        app.get("/posts", handlers::search);
        app.get("/posts/{id}", handlers::show);
        app.post("/posts", ctx -> dao.insert(ctx.formParam("author"), ctx.body()));

        app.get("/greet", ctx -> {
            String who = ctx.queryParam("who");
            ctx.html("<h1>Hi " + who + "</h1>");   // frame-expect: CWE-79
        });

        app.get("/out", ctx -> ctx.redirect(ctx.queryParam("to")));   // frame-expect: CWE-601

        app.get("/download", ctx -> {
            String name = ctx.queryParam("file");
            ctx.header("Content-Disposition", "attachment; filename=" + name);   // frame-expect: CWE-113
            ctx.result(new java.io.FileInputStream("/srv/exports/" + name));   // frame-expect: CWE-22
        });
    }
}
