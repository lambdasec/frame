package controllers;

import javax.inject.Inject;
import play.mvc.Controller;
import play.mvc.Http;
import play.mvc.Result;
import services.ProductService;

public class ProductController extends Controller {

    private final ProductService service;

    @Inject
    public ProductController(ProductService service) {
        this.service = service;
    }

    public Result search(Http.Request request) {
        String q = request.queryString("q").orElse("");
        return ok(service.search(q));
    }

    public Result show(String id) {
        return ok(service.find(id));
    }

    public Result login(Http.Request request) {
        String next = request.getQueryString("next");
        return redirect(next);   // frame-expect: CWE-601
    }

    public Result create(Http.Request request) {
        String name = request.body().asJson().get("name").asText();
        service.insert(name);
        return created();
    }
}
