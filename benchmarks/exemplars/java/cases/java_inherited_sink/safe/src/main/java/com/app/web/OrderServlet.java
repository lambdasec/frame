package com.app.web;

import com.app.dao.OrderDao;
import java.io.IOException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class OrderServlet extends HttpServlet {
    private final OrderDao dao = new OrderDao();

    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        try { dao.byCustomer("acme"); } catch (Exception e) { throw new IOException(e); }
    }
}
