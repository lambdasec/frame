package com.example.notes;

import static spark.Spark.get;
import static spark.Spark.port;
import static spark.Spark.post;

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

        get("/hello", (req, res) -> "<h1>Hello " + req.queryParams("name") + "</h1>");   // frame-expect: CWE-79

        get("/leave", (req, res) -> {
            res.redirect(req.queryParams("to"));   // frame-expect: CWE-601
            return null;
        });

        get("/export", (req, res) -> {
            String format = req.headers("X-Format");
            res.header("Content-Disposition", "attachment; filename=notes." + format);   // frame-expect: CWE-113
            return service.exportAll();
        });
    }
}
