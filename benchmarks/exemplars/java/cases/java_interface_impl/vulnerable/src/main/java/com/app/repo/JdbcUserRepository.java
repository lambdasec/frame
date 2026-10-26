package com.app.repo;

import java.sql.Connection;
import java.sql.DriverManager;

public class JdbcUserRepository implements UserRepository {
    @Override
    public void delete(String id) throws Exception {
        Connection c = DriverManager.getConnection("jdbc:h2:mem:");
        c.createStatement().executeUpdate("DELETE FROM users WHERE id = " + id);
    }
}
