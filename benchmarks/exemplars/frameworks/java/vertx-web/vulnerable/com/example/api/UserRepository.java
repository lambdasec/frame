package com.example.api;

import io.vertx.core.json.JsonArray;
import io.vertx.core.json.JsonObject;
import io.vertx.sqlclient.Pool;
import io.vertx.sqlclient.Row;
import java.util.function.Consumer;

public class UserRepository {

    private final Pool pool;

    public UserRepository(Pool pool) {
        this.pool = pool;
    }

    public void search(String term, Consumer<JsonArray> done) {
        pool.query("SELECT id, name FROM users WHERE name LIKE '%" + term + "%'").execute(ar -> {   // frame-expect: CWE-89
            JsonArray out = new JsonArray();
            if (ar.succeeded()) {
                for (Row row : ar.result()) {
                    out.add(new JsonObject().put("id", row.getInteger("id")).put("name", row.getString("name")));
                }
            }
            done.accept(out);
        });
    }

    public void byId(String id, Consumer<JsonObject> done) {
        pool.query("SELECT id, name FROM users WHERE id = " + id).execute(ar -> done.accept(new JsonObject()));   // frame-expect: CWE-89
    }

    public void insert(String name, String email) {
        String sql = String.format("INSERT INTO users(name, email) VALUES ('%s', '%s')", name, email);
        pool.query(sql).execute(ar -> { });   // frame-expect: CWE-89
    }
}
