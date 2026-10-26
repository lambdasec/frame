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
        response.setHeader("Content-Language", lang);   // frame-expect: CWE-113
        String path = request.getParameter("file");
        java.io.File f = new java.io.File("/srv/static/" + path);   // frame-expect: CWE-22
        response.getOutputStream().write(java.nio.file.Files.readAllBytes(f.toPath()));
    }
}
