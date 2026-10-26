package com.example.inventory;

import jakarta.inject.Inject;
import jakarta.inject.Singleton;
import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.PreparedStatement;
import java.util.ArrayList;
import java.util.List;
import javax.sql.DataSource;

@Singleton
public class StockRepository {

    @Inject
    DataSource dataSource;

    private static Item toItem(ResultSet rs) throws SQLException {
        Item item = new Item();
        item.sku = rs.getString("sku");
        item.name = rs.getString("name");
        return item;
    }

    public List<Item> search(String q, String warehouse) {
        List<Item> out = new ArrayList<>();
        try (Connection c = dataSource.getConnection(); PreparedStatement st = c.prepareStatement("SELECT * FROM item WHERE name LIKE ? AND warehouse = ?")) {
            st.setString(1, "%" + q + "%");
            st.setString(2, warehouse);
            ResultSet rs = st.executeQuery();
            while (rs.next()) {
                out.add(toItem(rs));
            }
        } catch (SQLException e) {
            throw new IllegalStateException(e);
        }
        return out;
    }

    public Item bySku(String sku) {
        try (Connection c = dataSource.getConnection(); PreparedStatement st = c.prepareStatement("SELECT * FROM item WHERE sku = ?")) {
            st.setString(1, sku);
            ResultSet rs = st.executeQuery();
            return rs.next() ? toItem(rs) : null;
        } catch (SQLException e) {
            throw new IllegalStateException(e);
        }
    }

    public List<Item> after(String sku) {
        List<Item> out = new ArrayList<>();
        try (Connection c = dataSource.getConnection(); PreparedStatement st = c.prepareStatement("SELECT * FROM item WHERE sku > ?")) {
            st.setString(1, sku);
            ResultSet rs = st.executeQuery();
            while (rs.next()) {
                out.add(toItem(rs));
            }
        } catch (SQLException e) {
            throw new IllegalStateException(e);
        }
        return out;
    }

    public List<Item> byCategory(String category) {
        List<Item> out = new ArrayList<>();
        try (Connection c = dataSource.getConnection();
             PreparedStatement st = c.prepareStatement("SELECT * FROM item WHERE category = ?")) {
            st.setString(1, category);
            ResultSet rs = st.executeQuery();
            while (rs.next()) {
                out.add(toItem(rs));
            }
        } catch (SQLException e) {
            throw new IllegalStateException(e);
        }
        return out;
    }

    public void log(String sku, String note, String operator) {
        try (Connection c = dataSource.getConnection(); PreparedStatement st = c.prepareStatement("INSERT INTO adjustment(sku, note, operator) VALUES (?, ?, ?)")) {
            st.setString(1, sku);
            st.setString(2, note);
            st.setString(3, operator);
            st.executeUpdate();
        } catch (SQLException e) {
            throw new IllegalStateException(e);
        }
    }
}
