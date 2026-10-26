import java.io.PrintWriter;
import javax.servlet.http.HttpServletRequest;

class JavaXss {
    void f(HttpServletRequest req, PrintWriter w) {
        String n = req.getParameter("n");
        w.println("<h1>" + n + "</h1>");
    }
}
