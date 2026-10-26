package com.example.shop.web;

import com.example.shop.dao.OrderDao;
import java.io.IOException;
import java.io.PrintWriter;
import javax.servlet.RequestDispatcher;
import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.Cookie;
import org.owasp.encoder.Encode;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

@WebServlet("/orders")
public class OrderServlet extends HttpServlet {

    private final OrderDao dao = new OrderDao();

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        String customer = request.getParameter("customer");
        PrintWriter out = response.getWriter();
        out.println("<h2>Orders of " + Encode.forHtml(customer) + "</h2>");
        for (String line : dao.findByCustomer(customer)) {
            out.println("<li>" + Encode.forHtml(line) + "</li>");
        }
    }

    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        String action = request.getParameter("action");
        if ("cancel".equals(action)) {
            dao.cancel(request.getParameter("id"));
            response.sendRedirect(request.getContextPath() + "/orders");
            return;
        }
        String view = request.getParameter("view");
        RequestDispatcher rd = request.getRequestDispatcher("/WEB-INF/views/" + ("list".equals(view) ? "list" : "detail") + ".jsp");
        rd.forward(request, response);
    }
}
