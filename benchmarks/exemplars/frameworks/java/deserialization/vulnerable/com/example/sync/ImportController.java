package com.example.sync;

import java.io.IOException;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class ImportController extends HttpServlet {

    private final ImportService service = new ImportService();

    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        String format = request.getParameter("format");
        String payload = request.getParameter("payload");
        Object result;
        switch (format) {
            case "xml":
                result = service.fromXml(payload);
                break;
            case "yaml":
                result = service.fromYaml(payload);
                break;
            case "json":
                result = service.fromJson(new String(request.getInputStream().readAllBytes(), "UTF-8"));
                break;
            case "java":
                result = service.fromJava(request);
                break;
            default:
                response.sendError(400);
                return;
        }
        response.getWriter().print(result == null ? "empty" : "ok");
    }
}
