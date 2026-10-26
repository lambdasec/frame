package com.example.inventory;

import io.micronaut.http.HttpRequest;
import io.micronaut.http.HttpResponse;
import io.micronaut.http.MediaType;
import io.micronaut.http.annotation.Body;
import io.micronaut.http.annotation.Controller;
import io.micronaut.http.annotation.CookieValue;
import io.micronaut.http.annotation.Get;
import io.micronaut.http.annotation.Header;
import io.micronaut.http.annotation.Post;
import io.micronaut.http.annotation.Produces;
import io.micronaut.http.annotation.QueryValue;
import jakarta.inject.Inject;
import java.net.URI;
import java.util.List;
import org.owasp.encoder.Encode;

@Controller("/stock")
public class StockController {

    @Inject
    StockService service;

    @Get("/search{?q,warehouse}")
    public List<Item> search(@QueryValue String q, @QueryValue String warehouse) {
        return service.search(q, warehouse);
    }

    @Get("/{sku}")
    public Item bySku(String sku) {
        return service.bySku(sku);
    }

    @Post("/adjust")
    public HttpResponse<String> adjust(@Body AdjustRequest request, @Header("X-Operator") String operator) {
        service.adjust(request.getSku(), request.getNote(), operator);
        return HttpResponse.ok("done");
    }

    @Get("/recent")
    public List<Item> recent(@CookieValue("lastSku") String lastSku) {
        return service.after(lastSku);
    }

    @Get("/raw")
    public List<Item> raw(HttpRequest<?> request) {
        String category = request.getParameters().get("category");
        return service.byCategory(category);
    }

    @Get("/jump")
    public HttpResponse<?> jump(@QueryValue String target) {
        return HttpResponse.redirect(URI.create(target.startsWith("/") && !target.startsWith("//") ? "/stock" : "/home"));
    }

    @Get("/banner")
    @Produces(MediaType.TEXT_HTML)
    public String banner(@QueryValue String title) {
        return "<h1>" + Encode.forHtml(title) + "</h1>";
    }
}
