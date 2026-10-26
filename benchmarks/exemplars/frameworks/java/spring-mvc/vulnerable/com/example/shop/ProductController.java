package com.example.shop;

import java.util.List;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.CookieValue;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.view.RedirectView;

@RestController
@RequestMapping("/api/products")
public class ProductController {

    @Autowired
    private ProductService service;

    @GetMapping("/search")
    public List<Product> search(@RequestParam String name, @RequestParam(defaultValue = "asc") String order) {
        return service.search(name, order);
    }

    @GetMapping("/{id}")
    public Product byId(@PathVariable("id") String id) {
        return service.find(id);
    }

    @PostMapping("/filter")
    public List<Product> filter(@RequestBody FilterRequest body) {
        return service.byCategory(body.getCategory());
    }

    @GetMapping("/by-tenant")
    public List<Product> byTenant(@RequestHeader("X-Tenant") String tenant) {
        return service.forTenant(tenant);
    }

    @GetMapping("/recent")
    public List<Product> recent(@CookieValue("last") String last) {
        return service.afterSku(last);
    }

    @GetMapping("/go")
    public RedirectView go(@RequestParam String next) {
        return new RedirectView(next);   // frame-expect: CWE-601
    }

    @GetMapping("/export")
    public ResponseEntity<String> export(@RequestParam String note) {
        return ResponseEntity.ok("<p>" + note + "</p>");   // frame-expect: CWE-79
    }

    @GetMapping("/calc")
    public Object calc(@RequestParam String expr) {
        return service.evaluate(expr);
    }

    @GetMapping("/proxy")
    public String proxy(@RequestParam String url) {
        return service.fetch(url);
    }
}
