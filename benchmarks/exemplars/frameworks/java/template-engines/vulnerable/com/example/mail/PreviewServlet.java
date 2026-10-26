package com.example.mail;

import java.io.IOException;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class PreviewServlet extends HttpServlet {

    private final TemplateService templates = new TemplateService();

    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        String engine = request.getParameter("engine");
        String source = request.getParameter("template");
        String name = request.getParameter("name");
        String out;
        switch (engine) {
            case "velocity":
                out = templates.velocity(source, name);
                break;
            case "freemarker":
                out = templates.freemarker(source, name);
                break;
            case "thymeleaf":
                out = templates.thymeleaf(source, name);
                break;
            case "groovy":
                out = templates.groovy(source);
                break;
            case "mvel":
                out = String.valueOf(templates.mvel(source));
                break;
            case "jexl":
                out = String.valueOf(templates.jexl(source));
                break;
            default:
                out = "";
        }
        response.setContentType("text/plain");
        response.setStatus(out.isEmpty() ? 204 : 200);
    }
}
