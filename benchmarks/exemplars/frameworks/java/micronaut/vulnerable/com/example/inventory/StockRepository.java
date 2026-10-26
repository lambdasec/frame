package com.example.inventory;

import jakarta.inject.Inject;
import jakarta.inject.Singleton;
import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
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
        try (Connection c = dataSource.getConnection(); Statement st = c.createStatement()) {
            ResultSet rs = st.executeQuery("SELECT * FROM item WHERE name LIKE '%" + q + "%' AND warehouse = '" + warehouse + "'");   // frame-expect: CWE-89
            while (rs.next()) {
                out.add(toItem(rs));
            }
        } catch (SQLException e) {
            throw new IllegalStateException(e);
        }
        return out;
    }

    public Item bySku(String sku) {
        try (Connection c = dataSource.getConnection(); Statement st = c.createStatement()) {
            ResultSet rs = st.executeQuery("SELECT * FROM item WHERE sku = '" + sku + "'");   // frame-expect: CWE-89
            return rs.next() ? toItem(rs) : null;
        } catch (SQLException e) {
            throw new IllegalStateException(e);
        }
    }

    public List<Item> after(String sku) {
        List<Item> out = new ArrayList<>();
        try (Connection c = dataSource.getConnection(); Statement st = c.createStatement()) {
            ResultSet rs = st.executeQuery("SELECT * FROM item WHERE sku > '" + sku + "'");   // frame-expect: CWE-89
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
        String sql = String.format("SELECT * FROM item WHERE category = '%s'", category);
        try (Connection c = dataSource.getConnection(); Statement st = c.createStatement()) {
            ResultSet rs = st.executeQuery(sql);   // frame-expect: CWE-89
            while (rs.next()) {
                out.add(toItem(rs));
            }
        } catch (SQLException e) {
            throw new IllegalStateException(e);
        }
        return out;
    }

    public void log(String sku, String note, String operator) {
        try (Connection c = dataSource.getConnection(); Statement st = c.createStatement()) {
            st.executeUpdate("INSERT INTO adjustment(sku, note, operator) VALUES ('" + sku + "', '" + note + "', '" + operator + "')");   // frame-expect: CWE-89
        } catch (SQLException e) {
            throw new IllegalStateException(e);
        }
    }
}
