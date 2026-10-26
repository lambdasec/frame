package com.example.blog;

import javax.ws.rs.QueryParam;

public class AuthorFilter {
    @QueryParam("author")
    private String author;

    public String getAuthor() { return author; }
    public void setAuthor(String author) { this.author = author; }
}
