package com.app.dao;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;

public abstract class BaseDao {
    protected ResultSet run(String sql) throws Exception {
        Connection c = DriverManager.getConnection("jdbc:h2:mem:");
        return c.createStatement().executeQuery(sql);
    }
}
