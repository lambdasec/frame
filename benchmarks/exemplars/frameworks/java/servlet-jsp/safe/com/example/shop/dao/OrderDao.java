package com.example.shop.dao;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.PreparedStatement;
import java.util.ArrayList;
import java.util.List;

public class OrderDao {

    private Connection connect() throws SQLException {
        return DriverManager.getConnection("jdbc:postgresql://db/shop", "shop", System.getenv("DB_PASSWORD"));
    }

    public List<String> findByCustomer(String customer) {
        List<String> rows = new ArrayList<>();
        try (Connection c = connect(); PreparedStatement st = c.prepareStatement("SELECT summary FROM orders WHERE customer = ?")) {
            st.setString(1, customer);
            ResultSet rs = st.executeQuery();
            while (rs.next()) {
                rows.add(rs.getString(1));
            }
        } catch (SQLException e) {
            throw new IllegalStateException(e);
        }
        return rows;
    }

    public void cancel(String id) {
        try (Connection c = connect(); PreparedStatement st = c.prepareStatement("UPDATE orders SET status = 'cancelled' WHERE id = ?")) {
            st.setLong(1, Long.parseLong(id));
            st.executeUpdate();
        } catch (SQLException e) {
            throw new IllegalStateException(e);
        }
    }
}
