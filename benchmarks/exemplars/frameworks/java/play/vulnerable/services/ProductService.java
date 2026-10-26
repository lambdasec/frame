package services;

import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
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
            Statement st = conn.createStatement();
            ResultSet rs = st.executeQuery("SELECT name FROM product WHERE name LIKE '%" + q + "%'");   // frame-expect: CWE-89
            return rs.next() ? rs.getString(1) : "";
        });
    }

    public String find(String id) {
        try (Connection conn = db.getConnection(); Statement st = conn.createStatement()) {
            ResultSet rs = st.executeQuery("SELECT name FROM product WHERE id = " + id);   // frame-expect: CWE-89
            return rs.next() ? rs.getString(1) : "";
        } catch (SQLException e) {
            throw new IllegalStateException(e);
        }
    }

    public void insert(String name) {
        try (Connection conn = db.getConnection(); Statement st = conn.createStatement()) {
            st.executeUpdate("INSERT INTO product(name) VALUES ('" + name + "')");   // frame-expect: CWE-89
        } catch (SQLException e) {
            throw new IllegalStateException(e);
        }
    }
}
