package com.example.notes;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.PreparedStatement;
import java.util.ArrayList;
import java.util.List;

public class NoteRepository {

    private Connection open() throws SQLException {
        return DriverManager.getConnection("jdbc:sqlite:notes.db");
    }

    public List<String> titlesLike(String q) {
        List<String> out = new ArrayList<>();
        try (Connection c = open(); PreparedStatement st = c.prepareStatement("SELECT title FROM notes WHERE title LIKE ?")) {
            st.setString(1, "%" + q + "%");
            ResultSet rs = st.executeQuery();
            while (rs.next()) {
                out.add(rs.getString(1));
            }
        } catch (SQLException e) {
            throw new IllegalStateException(e);
        }
        return out;
    }

    public String body(String id) {
        try (Connection c = open(); PreparedStatement st = c.prepareStatement("SELECT body FROM notes WHERE id = ?")) {
            st.setInt(1, Integer.parseInt(id));
            ResultSet rs = st.executeQuery();
            return rs.next() ? rs.getString(1) : "";
        } catch (SQLException e) {
            throw new IllegalStateException(e);
        }
    }

    public void insert(String title, String body) {
        try (Connection c = open(); PreparedStatement st = c.prepareStatement("INSERT INTO notes(title, body) VALUES (?, ?)")) {
            st.setString(1, title);
            st.setString(2, body);
            st.executeUpdate();
        } catch (SQLException e) {
            throw new IllegalStateException(e);
        }
    }
}
