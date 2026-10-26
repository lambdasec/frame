package com.app.web;

import com.app.util.Params;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class FileServlet extends HttpServlet {
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        File f = new File("/srv/files/" + Params.path(req));
        new FileInputStream(f).transferTo(resp.getOutputStream());
    }
}
