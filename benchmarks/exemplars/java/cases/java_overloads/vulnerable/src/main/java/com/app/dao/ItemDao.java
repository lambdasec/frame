package com.app.dao;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;

public class ItemDao {
    public ResultSet find(String code) throws Exception {
        Connection c = DriverManager.getConnection("jdbc:h2:mem:");
        return c.createStatement().executeQuery("SELECT * FROM items WHERE code = '" + code + "'");
    }

    public ResultSet find(int id) throws Exception {
        Connection c = DriverManager.getConnection("jdbc:h2:mem:");
        PreparedStatement ps = c.prepareStatement("SELECT * FROM items WHERE id = ?");
        ps.setInt(1, id);
        return ps.executeQuery();
    }
}
