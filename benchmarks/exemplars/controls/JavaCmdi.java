import javax.servlet.http.HttpServletRequest;

class JavaCmdi {
    void f(HttpServletRequest req) throws Exception {
        String c = req.getParameter("c");
        Runtime.getRuntime().exec("sh -c " + c);
    }
}
