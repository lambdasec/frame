package com.app.dao;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.Statement;

public class UserDao {
    public ResultSet find(String name) throws Exception {
        Connection conn = DriverManager.getConnection("jdbc:h2:mem:");
        Statement st = conn.createStatement();
        return st.executeQuery("SELECT * FROM users WHERE name = '" + name + "'");
    }
}
