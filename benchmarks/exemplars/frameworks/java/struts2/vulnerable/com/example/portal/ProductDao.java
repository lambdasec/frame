package com.example.portal;

import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.List;
import javax.sql.DataSource;

public class ProductDao {

    private DataSource dataSource;

    public List<Product> search(String query, String category) {
        List<Product> out = new ArrayList<>();
        String sql = "SELECT id, name FROM product WHERE name LIKE '%" + query + "%' AND category = '" + category + "'";
        try (Connection c = dataSource.getConnection(); Statement st = c.createStatement()) {
            ResultSet rs = st.executeQuery(sql);   // frame-expect: CWE-89
            while (rs.next()) {
                Product p = new Product();
                p.id = rs.getInt(1);
                p.name = rs.getString(2);
                out.add(p);
            }
        } catch (SQLException e) {
            throw new IllegalStateException(e);
        }
        return out;
    }

    public Product byId(String id) {
        try (Connection c = dataSource.getConnection(); Statement st = c.createStatement()) {
            ResultSet rs = st.executeQuery("SELECT id, name FROM product WHERE id = " + id);   // frame-expect: CWE-89
            return rs.next() ? new Product() : null;
        } catch (SQLException e) {
            throw new IllegalStateException(e);
        }
    }
}
