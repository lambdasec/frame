package com.example.billing;

import java.io.IOException;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.jooq.SQLDialect;
import org.jooq.impl.DSL;

public class InvoiceServlet extends HttpServlet {

    private final InvoiceRepository repository = new InvoiceRepository(DSL.using("jdbc:postgresql://db/billing", "billing", "x"));

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String action = request.getParameter("action");
        if ("customer".equals(action)) {
            response.getWriter().print(repository.byCustomer(request.getParameter("customer")).size());
        } else if ("status".equals(action)) {
            response.getWriter().print(repository.byStatus(request.getParameter("status"), request.getParameter("sort")).size());
        } else if ("search".equals(action)) {
            response.getWriter().print(repository.search(request.getParameter("where")).size());
        } else if ("sorted".equals(action)) {
            response.getWriter().print(repository.sorted(request.getParameter("column")).size());
        } else if ("close".equals(action)) {
            response.getWriter().print(repository.close(request.getParameter("id")));
        }
    }
}
