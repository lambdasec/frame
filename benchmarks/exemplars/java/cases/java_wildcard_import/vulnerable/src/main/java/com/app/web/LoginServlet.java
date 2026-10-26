package com.app.web;

import com.app.dao.*;
import java.io.IOException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class LoginServlet extends HttpServlet {
    @org.springframework.beans.factory.annotation.Autowired
    private AuditDao audit;

    protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        try { audit.log(req.getParameter("user")); } catch (Exception e) { throw new IOException(e); }
    }
}
