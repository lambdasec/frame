package com.example.shop;

import java.util.List;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.BeanPropertyRowMapper;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Repository;

@Repository
public class ProductRepository {

    @Autowired
    private JdbcTemplate jdbcTemplate;

    public List<Product> searchByName(String name, String order) {
        String sql = "SELECT * FROM products WHERE name LIKE '%" + name + "%' ORDER BY price " + order;
        return jdbcTemplate.query(sql, new BeanPropertyRowMapper<>(Product.class));   // frame-expect: CWE-89
    }

    public Product findOne(String id) {
        return jdbcTemplate.queryForObject("SELECT * FROM products WHERE sku = '" + id + "'",   // frame-expect: CWE-89
                new BeanPropertyRowMapper<>(Product.class));
    }

    public List<Product> inCategory(String category) {
        String sql = String.format("SELECT * FROM products WHERE category = '%s'", category);
        return jdbcTemplate.query(sql, new BeanPropertyRowMapper<>(Product.class));   // frame-expect: CWE-89
    }

    public List<Product> tenantProducts(String tenant) {
        return jdbcTemplate.query("SELECT * FROM products WHERE tenant = '" + tenant + "'",   // frame-expect: CWE-89
                new BeanPropertyRowMapper<>(Product.class));
    }

    public List<Product> after(String sku) {
        return jdbcTemplate.query("SELECT * FROM products WHERE sku > '" + sku + "'",   // frame-expect: CWE-89
                new BeanPropertyRowMapper<>(Product.class));
    }
}
