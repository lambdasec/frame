import java.sql.Statement;
import javax.servlet.http.HttpServletRequest;

class JavaSqli {
    void f(HttpServletRequest req, Statement st) throws Exception {
        String n = req.getParameter("n");
        st.executeQuery("SELECT * FROM u WHERE n = '" + n + "'");
    }
}
