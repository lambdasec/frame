package com.example.board;

import io.javalin.Javalin;
import org.owasp.encoder.Encode;

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
            ctx.html("<h1>Hi " + Encode.forHtml(who) + "</h1>");
        });

        app.get("/out", ctx -> ctx.redirect("/posts"));

        app.get("/download", ctx -> {
            String name = new java.io.File(ctx.queryParam("file")).getName();
            ctx.header("Content-Disposition", "attachment; filename=export.dat");
            ctx.result(new java.io.FileInputStream(new java.io.File("/srv/exports", name)));
        });
    }
}
