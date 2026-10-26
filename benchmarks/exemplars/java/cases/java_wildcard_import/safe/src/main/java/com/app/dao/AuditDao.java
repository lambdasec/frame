package com.app.dao;

import java.sql.Connection;
import java.sql.DriverManager;

public class AuditDao {
    public void log(String actor) throws Exception {
        Connection c = DriverManager.getConnection("jdbc:h2:mem:");
        c.createStatement().execute("INSERT INTO audit(actor) VALUES ('" + actor + "')");
    }
}
