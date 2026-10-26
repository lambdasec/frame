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
        String direction = "desc".equalsIgnoreCase(order) ? "DESC" : "ASC";
        String sql = "SELECT * FROM products WHERE name LIKE ? ORDER BY price " + direction;
        return jdbcTemplate.query(sql, new BeanPropertyRowMapper<>(Product.class), "%" + name + "%");
    }

    public Product findOne(String id) {
        return jdbcTemplate.queryForObject("SELECT * FROM products WHERE sku = ?",
                new BeanPropertyRowMapper<>(Product.class), id);
    }

    public List<Product> inCategory(String category) {
        return jdbcTemplate.query("SELECT * FROM products WHERE category = ?",
                new BeanPropertyRowMapper<>(Product.class), category);
    }

    public List<Product> tenantProducts(String tenant) {
        return jdbcTemplate.query("SELECT * FROM products WHERE tenant = ?",
                new BeanPropertyRowMapper<>(Product.class), tenant);
    }

    public List<Product> after(String sku) {
        return jdbcTemplate.query("SELECT * FROM products WHERE sku > ?",
                new BeanPropertyRowMapper<>(Product.class), sku);
    }
}
