package com.app.web;

import com.app.repo.JdbcUserRepository;
import com.app.repo.UserRepository;
import java.io.IOException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class AdminServlet extends HttpServlet {
    private UserRepository repo = new JdbcUserRepository();

    protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        try { repo.delete(req.getParameter("id")); } catch (Exception e) { throw new IOException(e); }
    }
}
