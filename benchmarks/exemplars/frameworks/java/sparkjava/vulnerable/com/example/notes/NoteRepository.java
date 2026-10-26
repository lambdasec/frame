package com.example.notes;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.List;

public class NoteRepository {

    private Connection open() throws SQLException {
        return DriverManager.getConnection("jdbc:sqlite:notes.db");
    }

    public List<String> titlesLike(String q) {
        List<String> out = new ArrayList<>();
        try (Connection c = open(); Statement st = c.createStatement()) {
            ResultSet rs = st.executeQuery("SELECT title FROM notes WHERE title LIKE '%" + q + "%'");   // frame-expect: CWE-89
            while (rs.next()) {
                out.add(rs.getString(1));
            }
        } catch (SQLException e) {
            throw new IllegalStateException(e);
        }
        return out;
    }

    public String body(String id) {
        try (Connection c = open(); Statement st = c.createStatement()) {
            ResultSet rs = st.executeQuery("SELECT body FROM notes WHERE id = " + id);   // frame-expect: CWE-89
            return rs.next() ? rs.getString(1) : "";
        } catch (SQLException e) {
            throw new IllegalStateException(e);
        }
    }

    public void insert(String title, String body) {
        try (Connection c = open(); Statement st = c.createStatement()) {
            st.executeUpdate("INSERT INTO notes(title, body) VALUES ('" + title + "', '" + body + "')");   // frame-expect: CWE-89
        } catch (SQLException e) {
            throw new IllegalStateException(e);
        }
    }
}
