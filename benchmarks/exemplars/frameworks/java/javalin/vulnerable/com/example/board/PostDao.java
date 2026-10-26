package com.example.board;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.List;

public class PostDao {

    private Connection open() throws SQLException {
        return DriverManager.getConnection("jdbc:h2:mem:board");
    }

    public List<String> search(String q) {
        List<String> out = new ArrayList<>();
        try (Connection c = open(); Statement st = c.createStatement()) {
            ResultSet rs = st.executeQuery("SELECT title FROM post WHERE title LIKE '%" + q + "%'");   // frame-expect: CWE-89
            while (rs.next()) {
                out.add(rs.getString(1));
            }
        } catch (SQLException e) {
            throw new IllegalStateException(e);
        }
        return out;
    }

    public String byId(String id) {
        try (Connection c = open(); Statement st = c.createStatement()) {
            ResultSet rs = st.executeQuery("SELECT body FROM post WHERE id = " + id);   // frame-expect: CWE-89
            return rs.next() ? rs.getString(1) : "";
        } catch (SQLException e) {
            throw new IllegalStateException(e);
        }
    }

    public void insert(String author, String body) {
        try (Connection c = open(); Statement st = c.createStatement()) {
            st.executeUpdate("INSERT INTO post(author, body) VALUES ('" + author + "', '" + body + "')");   // frame-expect: CWE-89
        } catch (SQLException e) {
            throw new IllegalStateException(e);
        }
    }
}
