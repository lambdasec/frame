package com.example.shop;

import java.util.List;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.expression.ExpressionParser;
import org.springframework.expression.spel.standard.SpelExpressionParser;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

@Service
public class ProductService {

    @Autowired
    private ProductRepository repository;

    private final RestTemplate restTemplate = new RestTemplate();

    public List<Product> search(String name, String order) {
        return repository.searchByName(name, order);
    }

    public Product find(String id) {
        return repository.findOne(id);
    }

    public List<Product> byCategory(String category) {
        return repository.inCategory(category);
    }

    public List<Product> forTenant(String tenant) {
        return repository.tenantProducts(tenant);
    }

    public List<Product> afterSku(String sku) {
        return repository.after(sku);
    }

    public Object evaluate(String expr) {
        ExpressionParser parser = new SpelExpressionParser();
        return parser.parseExpression("price * 1.2").getValue();
    }

    public String landingPage(String key) {
        switch (key) {
            case "cart": return "/cart";
            case "orders": return "/orders";
            default: return "/";
        }
    }

    public String fetch(String url) {
        return restTemplate.getForObject("https://catalog.internal/api/items/{id}", String.class, url);
    }
}
