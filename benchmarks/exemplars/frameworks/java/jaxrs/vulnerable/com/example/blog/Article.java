package com.example.blog;

public class Article {
    private String slug;
    private String title;
    private String body;
    public String getSlug() { return slug; }
    public String getTitle() { return title; }
    public String getBody() { return body; }
    public void setTitle(String title) { this.title = title; }
    public void setBody(String body) { this.body = body; }
}
