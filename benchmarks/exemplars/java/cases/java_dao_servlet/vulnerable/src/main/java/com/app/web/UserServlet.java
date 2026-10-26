package com.app.web;

import com.app.dao.UserDao;
import java.io.IOException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class UserServlet extends HttpServlet {
    private final UserDao dao = new UserDao();

    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        String name = req.getParameter("name");
        try { dao.find(name); } catch (Exception e) { throw new IOException(e); }
    }
}
