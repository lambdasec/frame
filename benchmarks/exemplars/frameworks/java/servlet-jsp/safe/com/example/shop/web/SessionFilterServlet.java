package com.example.shop.web;

import java.io.IOException;
import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class SessionFilterServlet extends HttpServlet {

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        String lang = request.getParameter("lang");
        response.setHeader("Content-Language", "de".equals(lang) ? "de" : "en");
        String path = request.getParameter("file");
        java.io.File f = new java.io.File("/srv/static", new java.io.File(path).getName());
        response.getOutputStream().write(java.nio.file.Files.readAllBytes(f.toPath()));
    }
}
