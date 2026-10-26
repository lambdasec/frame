"""Java taint across files: a servlet or controller passes request data to a method of another
class and the sink is there. Calls are followed through imports, packages, supertypes and the
single implementation of an interface; a choice the code does not force stays unresolved.
Each positive is paired with the nearest safe form (a constant, a bound parameter, two
implementations)."""

from pathlib import Path

import pytest

from frame.sil.scanner import FrameScanner

SERVLET = """package {pkg};
{imports}
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class Web extends HttpServlet {{
{fields}
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws Exception {{
        String v = {source};
        {call}
    }}
}}
"""
DAO = """package com.app.dao;

import java.sql.Connection;
import java.sql.DriverManager;

public class UserDao {
    public void find(String name) throws Exception {
        Connection c = DriverManager.getConnection("jdbc:h2:mem:");
        c.createStatement().executeQuery("SELECT * FROM u WHERE n = '" + name + "'");
    }
}
"""
SRC = 'req.getParameter("n")'


def write(root: Path, files: dict) -> Path:
    for rel, text in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text)
    return root


def found(root: Path, cwe: str = "CWE-89"):
    s = FrameScanner(verify=False)
    res = s.scan_directory(str(root), None, project_root=str(root))
    return {(Path(r.filename).name, v.cwe_id) for r in res for v in r.vulnerabilities if v.cwe_id == cwe}


def web(pkg="com.app.web", imports="import com.app.dao.UserDao;", fields="    private UserDao dao;",
        source=SRC, call="dao.find(v);"):
    return SERVLET.format(pkg=pkg, imports=imports, fields=fields, source=source, call=call)


def test_dao_in_another_package_through_an_explicit_import(tmp_path):
    write(tmp_path, {"dao/UserDao.java": DAO, "web/Web.java": web()})
    assert ("UserDao.java", "CWE-89") in found(tmp_path)


def test_constant_argument_is_clean(tmp_path):
    write(tmp_path, {"dao/UserDao.java": DAO, "web/Web.java": web(source='"admin"')})
    assert not found(tmp_path)


def test_same_package_needs_no_import(tmp_path):
    write(tmp_path, {"UserDao.java": DAO.replace("com.app.dao", "com.app.web"),
                     "Web.java": web(imports="")})
    assert ("UserDao.java", "CWE-89") in found(tmp_path)


def test_on_demand_import(tmp_path):
    write(tmp_path, {"dao/UserDao.java": DAO, "web/Web.java": web(imports="import com.app.dao.*;")})
    assert ("UserDao.java", "CWE-89") in found(tmp_path)


def test_type_imported_from_outside_the_project_is_not_a_project_type(tmp_path):
    write(tmp_path, {"dao/UserDao.java": DAO,
                     "web/Web.java": web(imports="import org.other.UserDao;")})
    assert not found(tmp_path)


def test_static_method_through_the_class_name(tmp_path):
    util = ("package com.app.util;\npublic class Shell {\n    public static void run(String c) throws Exception {\n"
            "        Runtime.getRuntime().exec(\"sh -c \" + c);\n    }\n}\n")
    write(tmp_path, {"util/Shell.java": util,
                     "web/Web.java": web(imports="import com.app.util.Shell;", fields="", call="Shell.run(v);")})
    assert ("Shell.java", "CWE-78") in found(tmp_path, "CWE-78")


def test_helper_that_returns_the_request_value(tmp_path):
    helper = ("package com.app.util;\nimport javax.servlet.http.HttpServletRequest;\npublic class Params {\n"
              "    public static String name(HttpServletRequest r) { return r.getParameter(\"n\"); }\n}\n")
    other = web(imports="import com.app.util.Params;\nimport com.app.dao.UserDao;", source='"x"',
                call="new UserDao().find(Params.name(req));")
    write(tmp_path, {"util/Params.java": helper, "dao/UserDao.java": DAO, "web/Web.java": other})
    assert ("UserDao.java", "CWE-89") in found(tmp_path)


IFACE = "package com.app.repo;\npublic interface Repo {\n    void delete(String id) throws Exception;\n}\n"
IMPL = ("package com.app.repo;\npublic class {name} implements Repo {{\n    public void delete(String id) throws Exception {{\n"
        "        java.sql.DriverManager.getConnection(\"jdbc:h2:mem:\").createStatement().executeUpdate(\"DELETE FROM u WHERE id=\" + id);\n"
        "    }}\n}}\n")


def test_interface_with_one_implementation(tmp_path):
    write(tmp_path, {"repo/Repo.java": IFACE, "repo/JdbcRepo.java": IMPL.format(name="JdbcRepo"),
                     "web/Web.java": web(imports="import com.app.repo.Repo;", fields="    private Repo dao;",
                                         call="dao.delete(v);")})
    assert ("JdbcRepo.java", "CWE-89") in found(tmp_path)


def test_interface_with_two_implementations_is_not_guessed(tmp_path):
    write(tmp_path, {"repo/Repo.java": IFACE, "repo/JdbcRepo.java": IMPL.format(name="JdbcRepo"),
                     "repo/MemRepo.java": IMPL.format(name="MemRepo").replace("executeUpdate", "toString"),
                     "web/Web.java": web(imports="import com.app.repo.Repo;", fields="    private Repo dao;",
                                         call="dao.delete(v);")})
    assert not found(tmp_path)


def test_method_inherited_from_a_project_base_class(tmp_path):
    base = ("package com.app.dao;\npublic abstract class Base {\n    protected void run(String sql) throws Exception {\n"
            "        java.sql.DriverManager.getConnection(\"jdbc:h2:mem:\").createStatement().executeQuery(sql);\n    }\n}\n")
    sub = ("package com.app.dao;\npublic class OrderDao extends Base {\n    public void by(String c) throws Exception {\n"
           "        run(\"SELECT * FROM o WHERE c = '\" + c + \"'\");\n    }\n}\n")
    write(tmp_path, {"dao/Base.java": base, "dao/OrderDao.java": sub,
                     "web/Web.java": web(imports="import com.app.dao.OrderDao;", fields="    private OrderDao dao;",
                                         call="dao.by(v);")})
    assert ("Base.java", "CWE-89") in found(tmp_path)


OVERLOADED = DAO.replace("public void find(String name)", "public void find(int id) throws Exception {\n"
                         "        java.sql.DriverManager.getConnection(\"jdbc:h2:mem:\").prepareStatement(\"SELECT 1 WHERE id = ?\");\n"
                         "    }\n\n    public void find(String name)")


def test_overload_chosen_by_argument_type(tmp_path):
    write(tmp_path, {"dao/UserDao.java": OVERLOADED, "web/Web.java": web()})
    assert ("UserDao.java", "CWE-89") in found(tmp_path)
    write(tmp_path, {"web/Web.java": web(call="dao.find(Integer.parseInt(v));")})
    assert not found(tmp_path)


def test_calls_on_library_types_do_not_confuse_resolution(tmp_path):
    write(tmp_path, {"dao/UserDao.java": DAO,
                     "web/Web.java": web(call="resp.getWriter().println(v.length()); dao.find(v);")})
    assert ("UserDao.java", "CWE-89") in found(tmp_path)


def test_creation_chain_is_analysed_in_a_single_file():
    code = ("public class T { void f(javax.servlet.http.HttpServletRequest req) throws Exception {"
            " String c = req.getParameter(\"c\"); new ProcessBuilder(\"sh\", \"-c\", \"tar \" + c).start(); } }")
    r = FrameScanner(language="java").scan(code, "T.java")
    assert any(v.cwe_id == "CWE-78" for v in r.vulnerabilities)


def test_changed_file_widens_to_the_classes_that_mention_it(tmp_path):
    import subprocess
    write(tmp_path, {"dao/UserDao.java": DAO, "web/Web.java": web()})
    for c in (["git", "init", "-q"], ["git", "add", "."],
              ["git", "-c", "user.name=x", "-c", "user.email=x@x", "commit", "-qm", "a"]):
        subprocess.run(c, cwd=tmp_path, check=True, capture_output=True)
    (tmp_path / "dao" / "UserDao.java").write_text(DAO + "// touched\n")
    s = FrameScanner(verify=False)
    res = s.scan_directory(str(tmp_path), None, only_files=[tmp_path / "dao" / "UserDao.java"],
                           project_root=str(tmp_path))
    scanned = {Path(r.filename).name for r in res}
    assert {"UserDao.java", "Web.java"} <= scanned


def test_overloaded_method_names_are_not_tainted_by_name():
    # `f(x)` from a request-bound parameter must not make the unrelated two-argument `f` a source.
    code = """public class C {
    void a(@org.springframework.web.bind.annotation.RequestParam String x) throws Exception { f(x); }
    void f(String a) { }
    void f(String a, String b) throws Exception {
        java.sql.DriverManager.getConnection("jdbc:h2:mem:").createStatement().executeQuery("SELECT " + a + b);
    }
}"""
    r = FrameScanner(language="java").scan(code, "C.java")
    assert not [v for v in r.vulnerabilities if v.cwe_id == "CWE-89"]
