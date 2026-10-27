"""More realistic multi-file Java projects (vulnerable tree + safe twin): shapes beyond projects_java.py."""

CASES = {}


def case(name, vulnerable, safe):
    CASES[name] = (vulnerable, safe)


def _servlet(pkg_call, call, extra_import=""):
    return f'''package com.acme.web;

{extra_import}import java.io.IOException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class EntryServlet extends HttpServlet {{
    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {{
        String v = req.getParameter("v");
{call}
    }}
}}
'''


# 1 -- abstract base class, subclass overrides the sink method
_ABS_BASE = '''package com.acme.dao;

public abstract class BaseDao {
    protected abstract String table();

    public String find(String key) {
        return run(key);
    }

    protected abstract String run(String key);
}
'''
_ABS_SERVLET = _servlet("", '''        BaseDao dao = new OrderDao();
        resp.getWriter().println(dao.find(v));''', "import com.acme.dao.BaseDao;\nimport com.acme.dao.OrderDao;\n")
case("abstract_base_subclass_sink", {
    "src/com/acme/web/EntryServlet.java": _ABS_SERVLET,
    "src/com/acme/dao/BaseDao.java": _ABS_BASE,
    "src/com/acme/dao/OrderDao.java": '''package com.acme.dao;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class OrderDao extends BaseDao {
    protected String table() { return "orders"; }

    protected String run(String key) {
        try (Connection c = DriverManager.getConnection("jdbc:h2:mem:app")) {
            Statement st = c.createStatement();
            ResultSet rs = st.executeQuery("SELECT note FROM " + table() + " WHERE ref = '" + key + "'");  // frame-expect: CWE-89
            return rs.next() ? rs.getString(1) : "";
        } catch (SQLException e) {
            throw new IllegalStateException(e);
        }
    }
}
''',
}, {
    "src/com/acme/web/EntryServlet.java": _ABS_SERVLET,
    "src/com/acme/dao/BaseDao.java": _ABS_BASE,
    "src/com/acme/dao/OrderDao.java": '''package com.acme.dao;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;

public class OrderDao extends BaseDao {
    protected String table() { return "orders"; }

    protected String run(String key) {
        try (Connection c = DriverManager.getConnection("jdbc:h2:mem:app")) {
            PreparedStatement st = c.prepareStatement("SELECT note FROM " + table() + " WHERE ref = ?");
            st.setString(1, key);
            ResultSet rs = st.executeQuery();
            return rs.next() ? rs.getString(1) : "";
        } catch (SQLException e) {
            throw new IllegalStateException(e);
        }
    }
}
''',
})

# 2 -- two implementations of an interface (unresolved) but each one has its own sink; both reached from entry
_IFACE = '''package com.acme.exec;

public interface Runner {
    String run(String arg);
}
'''
_RUN_SERVLET = _servlet("", '''        Runner r = new PingRunner();
        resp.getWriter().println(r.run(v));''', "import com.acme.exec.PingRunner;\nimport com.acme.exec.Runner;\n")
case("interface_runner_runtime_exec", {
    "src/com/acme/web/EntryServlet.java": _RUN_SERVLET,
    "src/com/acme/exec/Runner.java": _IFACE,
    "src/com/acme/exec/PingRunner.java": '''package com.acme.exec;

import java.io.IOException;

public class PingRunner implements Runner {
    public String run(String host) {
        try {
            Process p = Runtime.getRuntime().exec("ping -c 1 " + host);  // frame-expect: CWE-78
            return String.valueOf(p.waitFor());
        } catch (IOException | InterruptedException e) {
            return "failed";
        }
    }
}
''',
}, {
    "src/com/acme/web/EntryServlet.java": _RUN_SERVLET,
    "src/com/acme/exec/Runner.java": _IFACE,
    "src/com/acme/exec/PingRunner.java": '''package com.acme.exec;

import java.io.IOException;

public class PingRunner implements Runner {
    public String run(String host) {
        try {
            Process p = Runtime.getRuntime().exec(new String[] {"ping", "-c", "1", host});
            return String.valueOf(p.waitFor());
        } catch (IOException | InterruptedException e) {
            return "failed";
        }
    }
}
''',
})

# 3 -- static factory + builder carrying request data into a ProcessBuilder
_BUILD_SERVLET = _servlet("", '''        String out = Tool.of("convert").input(v).run();
        resp.getWriter().println(out);''', "import com.acme.build.Tool;\n")
case("builder_static_factory_processbuilder", {
    "src/com/acme/web/EntryServlet.java": _BUILD_SERVLET,
    "src/com/acme/build/Tool.java": '''package com.acme.build;

import java.io.IOException;

public class Tool {
    private final String name;
    private String input = "";

    private Tool(String name) { this.name = name; }

    public static Tool of(String name) { return new Tool(name); }

    public Tool input(String in) {
        this.input = in;
        return this;
    }

    public String run() throws IOException {
        ProcessBuilder pb = new ProcessBuilder("sh", "-c", name + " " + input);  // frame-expect: CWE-78
        return String.valueOf(pb.start().hashCode());
    }
}
''',
}, {
    "src/com/acme/web/EntryServlet.java": _BUILD_SERVLET,
    "src/com/acme/build/Tool.java": '''package com.acme.build;

import java.io.IOException;

public class Tool {
    private final String name;
    private String input = "";

    private Tool(String name) { this.name = name; }

    public static Tool of(String name) { return new Tool(name); }

    public Tool input(String in) {
        this.input = in;
        return this;
    }

    public String run() throws IOException {
        ProcessBuilder pb = new ProcessBuilder(name, "--", input);
        return String.valueOf(pb.start().hashCode());
    }
}
''',
})

# 4 -- Spring @RequestBody DTO, getter carries request data into NamedParameterJdbcTemplate / JdbcTemplate
_DTO = '''package com.acme.dto;

public class SearchRequest {
    private String term;
    private int limit;

    public String getTerm() { return term; }
    public void setTerm(String term) { this.term = term; }
    public int getLimit() { return limit; }
    public void setLimit(int limit) { this.limit = limit; }
}
'''
_DTO_CTRL = '''package com.acme.api;

import com.acme.dto.SearchRequest;
import com.acme.repo.SearchRepository;
import java.util.List;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class SearchController {
    private final SearchRepository repo;

    public SearchController(SearchRepository repo) { this.repo = repo; }

    @PostMapping("/search")
    public List<String> search(@RequestBody SearchRequest body) {
        return repo.find(body.getTerm());
    }
}
'''
case("requestbody_dto_getter_jdbctemplate", {
    "src/com/acme/dto/SearchRequest.java": _DTO,
    "src/com/acme/api/SearchController.java": _DTO_CTRL,
    "src/com/acme/repo/SearchRepository.java": '''package com.acme.repo;

import java.util.List;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Repository;

@Repository
public class SearchRepository {
    private final JdbcTemplate jdbc;

    public SearchRepository(JdbcTemplate jdbc) { this.jdbc = jdbc; }

    public List<String> find(String term) {
        String sql = String.format("SELECT title FROM docs WHERE body LIKE '%%%s%%'", term);
        return jdbc.queryForList(sql, String.class);  // frame-expect: CWE-89
    }
}
''',
}, {
    "src/com/acme/dto/SearchRequest.java": _DTO,
    "src/com/acme/api/SearchController.java": _DTO_CTRL,
    "src/com/acme/repo/SearchRepository.java": '''package com.acme.repo;

import java.util.List;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Repository;

@Repository
public class SearchRepository {
    private final JdbcTemplate jdbc;

    public SearchRepository(JdbcTemplate jdbc) { this.jdbc = jdbc; }

    public List<String> find(String term) {
        return jdbc.queryForList("SELECT title FROM docs WHERE body LIKE ?", String.class, "%" + term + "%");
    }
}
''',
})

# 5 -- @PathVariable + @Autowired field injection + EntityManager native query
_PV_CTRL = '''package com.acme.api;

import com.acme.repo.AccountRepo;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class AccountController {
    @Autowired
    private AccountRepo repo;

    @GetMapping("/accounts/{owner}")
    public Object byOwner(@PathVariable String owner) {
        return repo.lookup(owner);
    }
}
'''
case("pathvariable_autowired_entitymanager_native", {
    "src/com/acme/api/AccountController.java": _PV_CTRL,
    "src/com/acme/repo/AccountRepo.java": '''package com.acme.repo;

import javax.persistence.EntityManager;
import javax.persistence.PersistenceContext;
import org.springframework.stereotype.Repository;

@Repository
public class AccountRepo {
    @PersistenceContext
    private EntityManager em;

    public Object lookup(String owner) {
        return em.createNativeQuery("SELECT * FROM accounts WHERE owner = '" + owner + "'").getResultList();  // frame-expect: CWE-89
    }
}
''',
}, {
    "src/com/acme/api/AccountController.java": _PV_CTRL,
    "src/com/acme/repo/AccountRepo.java": '''package com.acme.repo;

import javax.persistence.EntityManager;
import javax.persistence.PersistenceContext;
import org.springframework.stereotype.Repository;

@Repository
public class AccountRepo {
    @PersistenceContext
    private EntityManager em;

    public Object lookup(String owner) {
        return em.createNativeQuery("SELECT * FROM accounts WHERE owner = ?1").setParameter(1, owner).getResultList();
    }
}
''',
})

# 6 -- Hibernate HQL concatenation vs parameter
_HQL_SERVLET = _servlet("", '''        resp.getWriter().println(new PersonRepo(null).byLastName(v));''', "import com.acme.repo.PersonRepo;\n")
case("hibernate_hql_concat", {
    "src/com/acme/web/EntryServlet.java": _HQL_SERVLET,
    "src/com/acme/repo/PersonRepo.java": '''package com.acme.repo;

import java.util.List;
import org.hibernate.Session;

public class PersonRepo {
    private final Session session;

    public PersonRepo(Session session) { this.session = session; }

    public List<?> byLastName(String last) {
        return session.createQuery("from Person p where p.lastName = '" + last + "'").list();  // frame-expect: CWE-89
    }
}
''',
}, {
    "src/com/acme/web/EntryServlet.java": _HQL_SERVLET,
    "src/com/acme/repo/PersonRepo.java": '''package com.acme.repo;

import java.util.List;
import org.hibernate.Session;

public class PersonRepo {
    private final Session session;

    public PersonRepo(Session session) { this.session = session; }

    public List<?> byLastName(String last) {
        return session.createQuery("from Person p where p.lastName = :last").setParameter("last", last).list();
    }
}
''',
})

# 7 -- StringBuilder query building in a generic repository subclass
_GEN_SERVLET = _servlet("", '''        Repository<String> r = new UserNameRepository();
        resp.getWriter().println(r.findBy("name", v));''', "import com.acme.repo.Repository;\nimport com.acme.repo.UserNameRepository;\n")
_GEN_BASE = '''package com.acme.repo;

import java.util.List;

public interface Repository<T> {
    List<T> findBy(String column, String value);
}
'''
case("generic_repository_stringbuilder", {
    "src/com/acme/web/EntryServlet.java": _GEN_SERVLET,
    "src/com/acme/repo/Repository.java": _GEN_BASE,
    "src/com/acme/repo/UserNameRepository.java": '''package com.acme.repo;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.List;

public class UserNameRepository implements Repository<String> {
    public List<String> findBy(String column, String value) {
        List<String> out = new ArrayList<>();
        StringBuilder sb = new StringBuilder("SELECT name FROM users WHERE ");
        sb.append(column).append(" = '").append(value).append("'");
        try (Connection c = DriverManager.getConnection("jdbc:h2:mem:app"); Statement st = c.createStatement()) {
            ResultSet rs = st.executeQuery(sb.toString());  // frame-expect: CWE-89
            while (rs.next()) out.add(rs.getString(1));
        } catch (SQLException e) {
            throw new IllegalStateException(e);
        }
        return out;
    }
}
''',
}, {
    "src/com/acme/web/EntryServlet.java": _GEN_SERVLET,
    "src/com/acme/repo/Repository.java": _GEN_BASE,
    "src/com/acme/repo/UserNameRepository.java": '''package com.acme.repo;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;

public class UserNameRepository implements Repository<String> {
    private static final Set<String> COLUMNS = Set.of("name", "email");

    public List<String> findBy(String column, String value) {
        if (!COLUMNS.contains(column)) throw new IllegalArgumentException(column);
        List<String> out = new ArrayList<>();
        try (Connection c = DriverManager.getConnection("jdbc:h2:mem:app");
             PreparedStatement st = c.prepareStatement("SELECT name FROM users WHERE " + column + " = ?")) {
            st.setString(1, value);
            ResultSet rs = st.executeQuery();
            while (rs.next()) out.add(rs.getString(1));
        } catch (SQLException e) {
            throw new IllegalStateException(e);
        }
        return out;
    }
}
''',
})

# 8 -- path traversal guarded by canonical path prefix
_FILE_SERVLET = _servlet("", '''        resp.getWriter().println(new Documents("/srv/docs").read(v));''', "import com.acme.files.Documents;\n")
case("canonical_path_guard", {
    "src/com/acme/web/EntryServlet.java": _FILE_SERVLET,
    "src/com/acme/files/Documents.java": '''package com.acme.files;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;

public class Documents {
    private final File root;

    public Documents(String root) { this.root = new File(root); }

    public String read(String name) throws IOException {
        File f = new File(root, name);
        return new String(Files.readAllBytes(f.toPath()));  // frame-expect: CWE-22
    }
}
''',
}, {
    "src/com/acme/web/EntryServlet.java": _FILE_SERVLET,
    "src/com/acme/files/Documents.java": '''package com.acme.files;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;

public class Documents {
    private final File root;

    public Documents(String root) { this.root = new File(root); }

    public String read(String name) throws IOException {
        File f = new File(root, name);
        if (!f.getCanonicalPath().startsWith(root.getCanonicalPath() + File.separator)) {
            throw new SecurityException("outside root");
        }
        return new String(Files.readAllBytes(f.toPath()));
    }
}
''',
})

# 9 -- XXE through a factory helper in another file
_XXE_SERVLET = _servlet("", '''        resp.getWriter().println(XmlParsers.parse(req.getInputStream()));''', "import com.acme.xml.XmlParsers;\n")
case("xxe_factory_helper", {
    "src/com/acme/web/EntryServlet.java": _XXE_SERVLET,
    "src/com/acme/xml/XmlParsers.java": '''package com.acme.xml;

import java.io.InputStream;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import org.w3c.dom.Document;

public final class XmlParsers {
    private XmlParsers() {}

    public static String parse(InputStream in) {
        try {
            DocumentBuilderFactory f = DocumentBuilderFactory.newInstance();
            DocumentBuilder b = f.newDocumentBuilder();
            Document d = b.parse(in);  // frame-expect: CWE-611
            return d.getDocumentElement().getNodeName();
        } catch (Exception e) {
            return "bad";
        }
    }
}
''',
}, {
    "src/com/acme/web/EntryServlet.java": _XXE_SERVLET,
    "src/com/acme/xml/XmlParsers.java": '''package com.acme.xml;

import java.io.InputStream;
import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import org.w3c.dom.Document;

public final class XmlParsers {
    private XmlParsers() {}

    public static String parse(InputStream in) {
        try {
            DocumentBuilderFactory f = DocumentBuilderFactory.newInstance();
            f.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
            f.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
            DocumentBuilder b = f.newDocumentBuilder();
            Document d = b.parse(in);
            return d.getDocumentElement().getNodeName();
        } catch (Exception e) {
            return "bad";
        }
    }
}
''',
})

# 10 -- deserialization
_DES_SERVLET = _servlet("", '''        resp.getWriter().println(Codec.decode(req.getInputStream()));''', "import com.acme.io.Codec;\n")
case("object_input_stream_helper", {
    "src/com/acme/web/EntryServlet.java": _DES_SERVLET,
    "src/com/acme/io/Codec.java": '''package com.acme.io;

import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInputStream;

public final class Codec {
    private Codec() {}

    public static String decode(InputStream in) throws IOException {
        try (ObjectInputStream ois = new ObjectInputStream(in)) {
            return String.valueOf(ois.readObject());  // frame-expect: CWE-502
        } catch (ClassNotFoundException e) {
            return "?";
        }
    }
}
''',
}, {
    "src/com/acme/web/EntryServlet.java": _DES_SERVLET,
    "src/com/acme/io/Codec.java": '''package com.acme.io;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.io.InputStream;

public final class Codec {
    private static final ObjectMapper MAPPER = new ObjectMapper();

    private Codec() {}

    public static String decode(InputStream in) throws IOException {
        return MAPPER.readValue(in, java.util.Map.class).toString();
    }
}
''',
})

# 11 -- SSRF through an HttpClient helper
_SSRF_SERVLET = _servlet("", '''        resp.getWriter().println(new Fetcher().get(v));''', "import com.acme.net.Fetcher;\n")
case("ssrf_url_helper", {
    "src/com/acme/web/EntryServlet.java": _SSRF_SERVLET,
    "src/com/acme/net/Fetcher.java": '''package com.acme.net;

import java.io.IOException;
import java.io.InputStream;
import java.net.URL;

public class Fetcher {
    public String get(String target) throws IOException {
        URL u = new URL(target);
        try (InputStream in = u.openStream()) {  // frame-expect: CWE-918
            return new String(in.readAllBytes());
        }
    }
}
''',
}, {
    "src/com/acme/web/EntryServlet.java": _SSRF_SERVLET,
    "src/com/acme/net/Fetcher.java": '''package com.acme.net;

import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.util.Set;

public class Fetcher {
    private static final Set<String> HOSTS = Set.of("api.acme.com", "cdn.acme.com");

    public String get(String target) throws IOException {
        URL u = new URL(target);
        if (!HOSTS.contains(u.getHost())) throw new IllegalArgumentException("host not allowed");
        try (InputStream in = u.openStream()) {
            return new String(in.readAllBytes());
        }
    }
}
''',
})

# 12 -- open redirect with Spring RedirectView, allow-list
_RV_CTRL = '''package com.acme.api;

import com.acme.nav.Targets;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.view.RedirectView;

@RestController
public class GoController {
    @GetMapping("/go")
    public RedirectView go(@RequestParam String next) {
        return new RedirectView(Targets.resolve(next));  // frame-expect: CWE-601
    }
}
'''
case("redirectview_allowlist", {
    "src/com/acme/api/GoController.java": _RV_CTRL,
    "src/com/acme/nav/Targets.java": '''package com.acme.nav;

public final class Targets {
    private Targets() {}

    public static String resolve(String next) {
        return next.trim();
    }
}
''',
}, {
    "src/com/acme/api/GoController.java": _RV_CTRL.replace("  // frame-expect: CWE-601", ""),
    "src/com/acme/nav/Targets.java": '''package com.acme.nav;

import java.util.Map;

public final class Targets {
    private static final Map<String, String> KNOWN = Map.of("home", "/home", "help", "/help");

    private Targets() {}

    public static String resolve(String next) {
        return KNOWN.getOrDefault(next, "/home");
    }
}
''',
})
