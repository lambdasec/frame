package com.app.web;

import com.app.service.BackupService;
import java.io.IOException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class RestoreServlet extends HttpServlet {
    private final BackupService service = new BackupService();

    protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        service.restore(req.getParameter("backup"));
    }
}
