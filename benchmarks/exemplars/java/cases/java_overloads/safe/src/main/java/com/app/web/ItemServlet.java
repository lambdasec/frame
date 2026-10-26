package com.app.web;

import com.app.dao.ItemDao;
import java.io.IOException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class ItemServlet extends HttpServlet {
    private final ItemDao dao = new ItemDao();

    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        String v = req.getParameter("v");
        try { dao.find(Integer.parseInt(v)); } catch (Exception e) { throw new IOException(e); }
    }
}
