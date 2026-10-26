package com.example.blog;

import java.net.URI;
import java.util.List;
import javax.inject.Inject;
import javax.ws.rs.BeanParam;
import javax.ws.rs.CookieParam;
import javax.ws.rs.FormParam;
import javax.ws.rs.GET;
import javax.ws.rs.HeaderParam;
import javax.ws.rs.MatrixParam;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.QueryParam;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.UriInfo;

@Path("/articles")
public class ArticleResource {

    @Inject
    ArticleService service;

    @GET
    @Path("/search")
    @Produces(MediaType.APPLICATION_JSON)
    public List<Article> search(@QueryParam("q") String q, @QueryParam("sort") String sort) {
        return service.search(q, sort);
    }

    @GET
    @Path("/{slug}")
    @Produces(MediaType.APPLICATION_JSON)
    public Article bySlug(@PathParam("slug") String slug) {
        return service.bySlug(slug);
    }

    @GET
    @Path("/by-author")
    public List<Article> byAuthor(@BeanParam AuthorFilter filter) {
        return service.byAuthor(filter.getAuthor());
    }

    @GET
    @Path("/tagged")
    public List<Article> tagged(@MatrixParam("tag") String tag, @HeaderParam("X-Site") String site) {
        return service.tagged(tag, site);
    }

    @GET
    @Path("/drafts")
    public List<Article> drafts(@CookieParam("editor") String editor) {
        return service.draftsOf(editor);
    }

    @POST
    @Path("/new")
    public Response create(Article article) {
        service.insert(article.getTitle(), article.getBody());
        return Response.status(Response.Status.CREATED).build();
    }

    @POST
    @Path("/login")
    public Response login(@FormParam("next") String next) {
        return Response.seeOther(URI.create(next)).build();   // frame-expect: CWE-601
    }

    @GET
    @Path("/filtered")
    public List<Article> filtered(@Context UriInfo uriInfo) {
        String topic = uriInfo.getQueryParameters().getFirst("topic");
        return service.byTopic(topic);
    }

    @GET
    @Path("/hello")
    @Produces(MediaType.TEXT_HTML)
    public String hello(@QueryParam("name") String name) {
        return "<h1>Hello " + name + "</h1>";   // frame-expect: CWE-79
    }
}
