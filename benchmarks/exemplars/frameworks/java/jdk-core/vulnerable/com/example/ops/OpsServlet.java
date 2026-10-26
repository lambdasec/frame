package com.example.ops;

import java.io.IOException;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class OpsServlet extends HttpServlet {

    private final OpsService service = new OpsService();

    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        String task = request.getParameter("task");
        String arg = request.getParameter("arg");
        String result;
        switch (task) {
            case "ping":
                result = service.ping(arg);
                break;
            case "archive":
                result = service.archive(arg);
                break;
            case "read":
                result = service.readReport(arg);
                break;
            case "import":
                result = service.importXml(request.getInputStream());
                break;
            case "resource":
                result = String.valueOf(service.findResource(arg));
                break;
            default:
                result = "";
        }
        response.setStatus(result.isEmpty() ? 204 : 200);
    }
}
