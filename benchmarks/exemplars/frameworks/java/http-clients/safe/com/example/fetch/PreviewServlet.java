package com.example.fetch;

import java.io.IOException;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class PreviewServlet extends HttpServlet {

    private final Fetcher fetcher = new Fetcher();

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        String target = request.getParameter("url");
        String how = request.getParameter("via");
        String body;
        switch (how == null ? "apache" : how) {
            case "okhttp":
                body = fetcher.withOkHttp(target);
                break;
            case "jdk":
                body = fetcher.withJdkClient(target);
                break;
            case "url":
                body = fetcher.withUrl(target);
                break;
            case "jsoup":
                body = fetcher.withJsoup(target);
                break;
            default:
                body = fetcher.withApache(target);
        }
        response.setStatus(body.isEmpty() ? 204 : 200);
    }
}
