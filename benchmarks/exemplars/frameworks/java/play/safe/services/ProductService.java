package services;

import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.PreparedStatement;
import javax.inject.Inject;
import play.db.Database;

public class ProductService {

    private final Database db;

    @Inject
    public ProductService(Database db) {
        this.db = db;
    }

    public String search(String q) {
        return db.withConnection(conn -> {
            PreparedStatement st = conn.prepareStatement("SELECT name FROM product WHERE name LIKE ?");
            st.setString(1, "%" + q + "%");
            ResultSet rs = st.executeQuery();
            return rs.next() ? rs.getString(1) : "";
        });
    }

    public String find(String id) {
        try (Connection conn = db.getConnection(); PreparedStatement st = conn.prepareStatement("SELECT name FROM product WHERE id = ?")) {
            st.setLong(1, Long.parseLong(id));
            ResultSet rs = st.executeQuery();
            return rs.next() ? rs.getString(1) : "";
        } catch (SQLException e) {
            throw new IllegalStateException(e);
        }
    }

    public void insert(String name) {
        try (Connection conn = db.getConnection(); PreparedStatement st = conn.prepareStatement("INSERT INTO product(name) VALUES (?)")) {
            st.setString(1, name);
            st.executeUpdate();
        } catch (SQLException e) {
            throw new IllegalStateException(e);
        }
    }
}
