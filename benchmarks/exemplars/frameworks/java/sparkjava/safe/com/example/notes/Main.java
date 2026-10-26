package com.example.notes;

import static spark.Spark.get;
import static spark.Spark.port;
import static spark.Spark.post;

import org.owasp.encoder.Encode;

public class Main {

    public static void main(String[] args) {
        port(4567);
        NoteService service = new NoteService(new NoteRepository());

        get("/notes", (req, res) -> service.search(req.queryParams("q")));

        get("/notes/:id", (req, res) -> {
            String id = req.params(":id");
            res.type("application/json");
            return service.find(id);
        });

        post("/notes", (req, res) -> {
            service.create(req.queryParams("title"), req.body());
            res.status(201);
            return "created";
        });

        get("/hello", (req, res) -> "<h1>Hello " + Encode.forHtml(req.queryParams("name")) + "</h1>");

        get("/leave", (req, res) -> {
            res.redirect("/notes");
            return null;
        });

        get("/export", (req, res) -> {
            String format = "csv".equals(req.headers("X-Format")) ? "csv" : "txt";
            res.header("Content-Disposition", "attachment; filename=notes." + format);
            return service.exportAll();
        });
    }
}
