package com.example.portal;

import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.PreparedStatement;
import java.util.ArrayList;
import java.util.List;
import javax.sql.DataSource;

public class ProductDao {

    private DataSource dataSource;

    public List<Product> search(String query, String category) {
        List<Product> out = new ArrayList<>();
        String sql = "SELECT id, name FROM product WHERE name LIKE ? AND category = ?";
        try (Connection c = dataSource.getConnection(); PreparedStatement st = c.prepareStatement(sql)) {
            st.setString(1, "%" + query + "%");
            st.setString(2, category);
            ResultSet rs = st.executeQuery();
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
        try (Connection c = dataSource.getConnection();
             PreparedStatement st = c.prepareStatement("SELECT id, name FROM product WHERE id = ?")) {
            st.setInt(1, Integer.parseInt(id));
            ResultSet rs = st.executeQuery();
            return rs.next() ? new Product() : null;
        } catch (SQLException e) {
            throw new IllegalStateException(e);
        }
    }
}
