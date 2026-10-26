import java.io.File;
import javax.servlet.http.HttpServletRequest;

class JavaPath {
    void f(HttpServletRequest req) {
        String p = req.getParameter("p");
        File f = new File("/srv/" + p);
    }
}
