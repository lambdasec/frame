package com.example.api;

import io.vertx.core.json.JsonArray;
import io.vertx.core.json.JsonObject;
import io.vertx.sqlclient.Pool;
import io.vertx.sqlclient.Row;
import io.vertx.sqlclient.Tuple;
import java.util.function.Consumer;

public class UserRepository {

    private final Pool pool;

    public UserRepository(Pool pool) {
        this.pool = pool;
    }

    public void search(String term, Consumer<JsonArray> done) {
        pool.preparedQuery("SELECT id, name FROM users WHERE name LIKE $1").execute(Tuple.of("%" + term + "%"), ar -> {
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
        pool.preparedQuery("SELECT id, name FROM users WHERE id = $1").execute(Tuple.of(Integer.parseInt(id)), ar -> done.accept(new JsonObject()));
    }

    public void insert(String name, String email) {
        pool.preparedQuery("INSERT INTO users(name, email) VALUES ($1, $2)").execute(Tuple.of(name, email), ar -> { });
    }
}
