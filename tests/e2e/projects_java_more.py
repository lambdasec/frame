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
_BUILD_SERVLET = _servlet("", '''        Tool tool = Tool.of("convert");
        String out = tool.run(v);
        resp.getWriter().println(out);''', "import com.acme.build.Tool;\n")
case("builder_static_factory_processbuilder", {
    "src/com/acme/web/EntryServlet.java": _BUILD_SERVLET,
    "src/com/acme/build/Tool.java": '''package com.acme.build;

import java.io.IOException;

public class Tool {
    private final String name;

    private Tool(String name) { this.name = name; }

    public static Tool of(String name) { return new Tool(name); }

    public String run(String input) throws IOException {
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

    private Tool(String name) { this.name = name; }

    public static Tool of(String name) { return new Tool(name); }

    public String run(String input) throws IOException {
        if (!input.matches("[A-Za-z0-9_.-]+")) throw new IllegalArgumentException(input);
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
import java.nio.file.Path;

public class Documents {
    private final File root;

    public Documents(String root) { this.root = new File(root); }

    public String read(String name) throws IOException {
        Path f = root.toPath().resolve(name);
        return new String(Files.readAllBytes(f));  // frame-expect: CWE-22
    }
}
''',
}, {
    "src/com/acme/web/EntryServlet.java": _FILE_SERVLET,
    "src/com/acme/files/Documents.java": '''package com.acme.files;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

public class Documents {
    private final File root;

    public Documents(String root) { this.root = new File(root); }

    public String read(String name) throws IOException {
        Path f = root.toPath().resolve(new File(name).getName());
        return new String(Files.readAllBytes(f));
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
        try (ObjectInputStream ois = new ObjectInputStream(in)) {  // frame-expect: CWE-502
            return String.valueOf(ois.readObject());
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
        URL u = new URL(target);  // frame-expect: CWE-918
        try (InputStream in = u.openStream()) {
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
        if (!HOSTS.contains(new URL(target).getHost())) throw new IllegalArgumentException("host not allowed");
        URL u = new URL(target);
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


# 13 -- enum with per-constant behaviour running a command
_ENUM_SERVLET = _servlet("", '''        Converter c = Converter.valueOf(req.getParameter("fmt").toUpperCase());
        resp.getWriter().println(c.convert(v));''', "import com.acme.conv.Converter;\n")
case("enum_constant_behaviour_exec", {
    "src/com/acme/web/EntryServlet.java": _ENUM_SERVLET,
    "src/com/acme/conv/Converter.java": '''package com.acme.conv;

import java.io.IOException;

public enum Converter {
    PDF("wkhtmltopdf"),
    PNG("convert");

    private final String binary;

    Converter(String binary) { this.binary = binary; }

    public String convert(String file) throws IOException {
        Process p = Runtime.getRuntime().exec(binary + " " + file);  // frame-expect: CWE-78
        return String.valueOf(p.hashCode());
    }
}
''',
}, {
    "src/com/acme/web/EntryServlet.java": _ENUM_SERVLET,
    "src/com/acme/conv/Converter.java": '''package com.acme.conv;

import java.io.IOException;

public enum Converter {
    PDF("wkhtmltopdf"),
    PNG("convert");

    private final String binary;

    Converter(String binary) { this.binary = binary; }

    public String convert(String file) throws IOException {
        Process p = Runtime.getRuntime().exec(new String[] {binary, file});
        return String.valueOf(p.hashCode());
    }
}
''',
})

# 14 -- anonymous Runnable / inner class capturing the request value
_ANON_SERVLET = _servlet("", '''        new Scheduler().later(v);''', "import com.acme.jobs.Scheduler;\n")
case("anonymous_runnable_exec", {
    "src/com/acme/web/EntryServlet.java": _ANON_SERVLET,
    "src/com/acme/jobs/Scheduler.java": '''package com.acme.jobs;

import java.io.IOException;

public class Scheduler {
    public void later(final String target) {
        Runnable job = new Runnable() {
            public void run() {
                try {
                    Runtime.getRuntime().exec("backup.sh " + target);  // frame-expect: CWE-78
                } catch (IOException e) {
                    throw new IllegalStateException(e);
                }
            }
        };
        new Thread(job).start();
    }
}
''',
}, {
    "src/com/acme/web/EntryServlet.java": _ANON_SERVLET,
    "src/com/acme/jobs/Scheduler.java": '''package com.acme.jobs;

import java.io.IOException;

public class Scheduler {
    public void later(final String target) {
        Runnable job = new Runnable() {
            public void run() {
                try {
                    Runtime.getRuntime().exec(new String[] {"backup.sh", target});
                } catch (IOException e) {
                    throw new IllegalStateException(e);
                }
            }
        };
        new Thread(job).start();
    }
}
''',
})

# 15 -- lambda / stream over request values into JdbcTemplate.execute
_STREAM_CTRL = '''package com.acme.api;

import com.acme.repo.BulkRepo;
import java.util.Arrays;
import java.util.List;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class BulkController {
    private final BulkRepo repo;

    public BulkController(BulkRepo repo) { this.repo = repo; }

    @PostMapping("/bulk")
    public void delete(@RequestParam("ids") String ids) {
        List<String> parts = Arrays.asList(ids.split(","));
        repo.deleteAll(parts);
    }
}
'''
case("stream_foreach_jdbc_execute", {
    "src/com/acme/api/BulkController.java": _STREAM_CTRL,
    "src/com/acme/repo/BulkRepo.java": '''package com.acme.repo;

import java.util.List;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Repository;

@Repository
public class BulkRepo {
    private final JdbcTemplate jdbc;

    public BulkRepo(JdbcTemplate jdbc) { this.jdbc = jdbc; }

    public void deleteAll(List<String> ids) {
        for (String id : ids) {
            jdbc.execute("DELETE FROM items WHERE id = " + id);  // frame-expect: CWE-89
        }
    }
}
''',
}, {
    "src/com/acme/api/BulkController.java": _STREAM_CTRL,
    "src/com/acme/repo/BulkRepo.java": '''package com.acme.repo;

import java.util.List;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Repository;

@Repository
public class BulkRepo {
    private final JdbcTemplate jdbc;

    public BulkRepo(JdbcTemplate jdbc) { this.jdbc = jdbc; }

    public void deleteAll(List<String> ids) {
        for (String id : ids) {
            jdbc.update("DELETE FROM items WHERE id = ?", Long.parseLong(id));
        }
    }
}
''',
})

# 16 -- import static utility in another package
_STATIC_SERVLET = _servlet("", '''        resp.getWriter().println(run(v));''', "import static com.acme.util.Shell.run;\n")
case("import_static_utility", {
    "src/com/acme/web/EntryServlet.java": _STATIC_SERVLET,
    "src/com/acme/util/Shell.java": '''package com.acme.util;

import java.io.IOException;

public final class Shell {
    private Shell() {}

    public static String run(String cmd) throws IOException {
        Process p = Runtime.getRuntime().exec(new String[] {"/bin/sh", "-c", cmd});  // frame-expect: CWE-78
        return String.valueOf(p.hashCode());
    }
}
''',
}, {
    "src/com/acme/web/EntryServlet.java": _STATIC_SERVLET,
    "src/com/acme/util/Shell.java": '''package com.acme.util;

import java.io.IOException;

public final class Shell {
    private Shell() {}

    public static String run(String cmd) throws IOException {
        if (!cmd.matches("[a-z]+")) throw new IllegalArgumentException(cmd);
        Process p = Runtime.getRuntime().exec(new String[] {"/bin/sh", "-c", cmd});
        return String.valueOf(p.hashCode());
    }
}
''',
})

# 17 -- MyBatis mapper interface: ${} vs #{}
_MB_CTRL = '''package com.acme.api;

import com.acme.mapper.UserMapper;
import java.util.List;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class UserListController {
    private final UserMapper mapper;

    public UserListController(UserMapper mapper) { this.mapper = mapper; }

    @GetMapping("/users")
    public List<String> list(@RequestParam String sort) {
        return mapper.names(sort);
    }
}
'''
case("mybatis_dollar_vs_hash", {
    "src/com/acme/api/UserListController.java": _MB_CTRL,
    "src/com/acme/mapper/UserMapper.java": '''package com.acme.mapper;

import java.util.List;
import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Param;
import org.apache.ibatis.annotations.Select;

@Mapper
public interface UserMapper {
    @Select("SELECT name FROM users ORDER BY ${sort}")  // frame-expect: CWE-89
    List<String> names(@Param("sort") String sort);
}
''',
}, {
    "src/com/acme/api/UserListController.java": _MB_CTRL,
    "src/com/acme/mapper/UserMapper.java": '''package com.acme.mapper;

import java.util.List;
import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Param;
import org.apache.ibatis.annotations.Select;

@Mapper
public interface UserMapper {
    @Select("SELECT name FROM users WHERE role = #{sort}")
    List<String> names(@Param("sort") String sort);
}
''',
})

# 18 -- NamedParameterJdbcTemplate with a MessageFormat-built statement
_NP_CTRL = '''package com.acme.api;

import com.acme.repo.ReportRepo;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class ReportController {
    private final ReportRepo repo;

    public ReportController(ReportRepo repo) { this.repo = repo; }

    @GetMapping("/report")
    public Object report(@RequestParam String region) {
        return repo.totals(region);
    }
}
'''
case("named_parameter_template_messageformat", {
    "src/com/acme/api/ReportController.java": _NP_CTRL,
    "src/com/acme/repo/ReportRepo.java": '''package com.acme.repo;

import java.text.MessageFormat;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.stereotype.Repository;

@Repository
public class ReportRepo {
    private final NamedParameterJdbcTemplate jdbc;

    public ReportRepo(NamedParameterJdbcTemplate jdbc) { this.jdbc = jdbc; }

    public List<Map<String, Object>> totals(String region) {
        String sql = MessageFormat.format("SELECT sum(amount) AS total FROM sales WHERE region = ''{0}''", region);
        return jdbc.queryForList(sql, Collections.emptyMap());  // frame-expect: CWE-89
    }
}
''',
}, {
    "src/com/acme/api/ReportController.java": _NP_CTRL,
    "src/com/acme/repo/ReportRepo.java": '''package com.acme.repo;

import java.util.List;
import java.util.Map;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.stereotype.Repository;

@Repository
public class ReportRepo {
    private final NamedParameterJdbcTemplate jdbc;

    public ReportRepo(NamedParameterJdbcTemplate jdbc) { this.jdbc = jdbc; }

    public List<Map<String, Object>> totals(String region) {
        return jdbc.queryForList("SELECT sum(amount) AS total FROM sales WHERE region = :region",
                                 Map.of("region", region));
    }
}
''',
})

# 19 -- overloads: the String overload is the dangerous one
_OV_SERVLET = _servlet("", '''        Lookup l = new Lookup();
        resp.getWriter().println(l.byKey(v));''', "import com.acme.repo.Lookup;\n")
case("overloaded_methods_string_overload", {
    "src/com/acme/web/EntryServlet.java": _OV_SERVLET,
    "src/com/acme/repo/Lookup.java": '''package com.acme.repo;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class Lookup {
    public String byKey(int id) {
        try (Connection c = DriverManager.getConnection("jdbc:h2:mem:app");
             PreparedStatement ps = c.prepareStatement("SELECT v FROM kv WHERE id = ?")) {
            ps.setInt(1, id);
            ResultSet rs = ps.executeQuery();
            return rs.next() ? rs.getString(1) : "";
        } catch (SQLException e) {
            throw new IllegalStateException(e);
        }
    }

    public String byKey(String key) {
        try (Connection c = DriverManager.getConnection("jdbc:h2:mem:app"); Statement st = c.createStatement()) {
            ResultSet rs = st.executeQuery("SELECT v FROM kv WHERE k = '" + key + "'");  // frame-expect: CWE-89
            return rs.next() ? rs.getString(1) : "";
        } catch (SQLException e) {
            throw new IllegalStateException(e);
        }
    }
}
''',
}, {
    "src/com/acme/web/EntryServlet.java": _OV_SERVLET,
    "src/com/acme/repo/Lookup.java": '''package com.acme.repo;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;

public class Lookup {
    public String byKey(int id) {
        return byKey(String.valueOf(id));
    }

    public String byKey(String key) {
        try (Connection c = DriverManager.getConnection("jdbc:h2:mem:app");
             PreparedStatement ps = c.prepareStatement("SELECT v FROM kv WHERE k = ?")) {
            ps.setString(1, key);
            ResultSet rs = ps.executeQuery();
            return rs.next() ? rs.getString(1) : "";
        } catch (SQLException e) {
            throw new IllegalStateException(e);
        }
    }
}
''',
})

# 20 -- servlet filter wraps the request, servlet uses what the filter stored
_FILTER = '''package com.acme.web;

import java.io.IOException;
import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;

public class TenantFilter implements Filter {
    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        HttpServletRequest req = (HttpServletRequest) request;
        request.setAttribute("tenant", req.getHeader("X-Tenant"));
        chain.doFilter(request, response);
    }
}
'''
_TENANT_SERVLET = '''package com.acme.web;

import com.acme.repo.TenantStore;
import java.io.IOException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class TenantServlet extends HttpServlet {
    private final TenantStore store = new TenantStore();

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        String tenant = (String) req.getAttribute("tenant");
        resp.getWriter().println(store.settings(tenant));
    }
}
'''
case("filter_sets_attribute_servlet_reads", {
    "src/com/acme/web/TenantFilter.java": _FILTER,
    "src/com/acme/web/TenantServlet.java": _TENANT_SERVLET,
    "src/com/acme/repo/TenantStore.java": '''package com.acme.repo;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class TenantStore {
    public String settings(String tenant) {
        try (Connection c = DriverManager.getConnection("jdbc:h2:mem:app"); Statement st = c.createStatement()) {
            ResultSet rs = st.executeQuery("SELECT json FROM settings WHERE tenant = '" + tenant + "'");  // frame-expect: CWE-89
            return rs.next() ? rs.getString(1) : "{}";
        } catch (SQLException e) {
            throw new IllegalStateException(e);
        }
    }
}
''',
}, {
    "src/com/acme/web/TenantFilter.java": _FILTER,
    "src/com/acme/web/TenantServlet.java": _TENANT_SERVLET,
    "src/com/acme/repo/TenantStore.java": '''package com.acme.repo;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;

public class TenantStore {
    public String settings(String tenant) {
        try (Connection c = DriverManager.getConnection("jdbc:h2:mem:app");
             PreparedStatement ps = c.prepareStatement("SELECT json FROM settings WHERE tenant = ?")) {
            ps.setString(1, tenant);
            ResultSet rs = ps.executeQuery();
            return rs.next() ? rs.getString(1) : "{}";
        } catch (SQLException e) {
            throw new IllegalStateException(e);
        }
    }
}
''',
})

# 21 -- exception handling around the sink: the sink is in a try with catch/finally and rethrow
_EXC_SERVLET = _servlet("", '''        resp.getWriter().println(new Archiver().pack(v));''', "import com.acme.io.Archiver;\n")
case("exception_wrapped_sink", {
    "src/com/acme/web/EntryServlet.java": _EXC_SERVLET,
    "src/com/acme/io/Archiver.java": '''package com.acme.io;

import java.io.IOException;

public class Archiver {
    public String pack(String dir) {
        try {
            Process p = new ProcessBuilder("sh", "-c", "tar czf out.tgz " + dir).start();  // frame-expect: CWE-78
            return "pid " + p.hashCode();
        } catch (IOException e) {
            throw new IllegalStateException("tar failed", e);
        } finally {
            System.gc();
        }
    }
}
''',
}, {
    "src/com/acme/web/EntryServlet.java": _EXC_SERVLET,
    "src/com/acme/io/Archiver.java": '''package com.acme.io;

import java.io.IOException;

public class Archiver {
    public String pack(String dir) {
        try {
            Process p = new ProcessBuilder("tar", "czf", "out.tgz", "--", "data").start();
            return "pid " + p.hashCode() + dir.length();
        } catch (IOException e) {
            throw new IllegalStateException("tar failed", e);
        } finally {
            System.gc();
        }
    }
}
''',
})

# 22 -- interface default method calling the abstract one, sink in the single implementor
_DEF_SERVLET = _servlet("", '''        Notifier n = new MailNotifier();
        n.notifyUser(v);''', "import com.acme.notify.MailNotifier;\nimport com.acme.notify.Notifier;\n")
case("interface_default_method", {
    "src/com/acme/web/EntryServlet.java": _DEF_SERVLET,
    "src/com/acme/notify/Notifier.java": '''package com.acme.notify;

public interface Notifier {
    void send(String address);

    default void notifyUser(String address) {
        send(address.trim());
    }
}
''',
    "src/com/acme/notify/MailNotifier.java": '''package com.acme.notify;

import java.io.IOException;

public class MailNotifier implements Notifier {
    public void send(String address) {
        try {
            Runtime.getRuntime().exec("mail -s hello " + address);  // frame-expect: CWE-78
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
    }
}
''',
}, {
    "src/com/acme/web/EntryServlet.java": _DEF_SERVLET,
    "src/com/acme/notify/Notifier.java": '''package com.acme.notify;

public interface Notifier {
    void send(String address);

    default void notifyUser(String address) {
        send(address.trim());
    }
}
''',
    "src/com/acme/notify/MailNotifier.java": '''package com.acme.notify;

import java.io.IOException;

public class MailNotifier implements Notifier {
    public void send(String address) {
        try {
            Runtime.getRuntime().exec(new String[] {"mail", "-s", "hello", address});
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
    }
}
''',
})

# 23 -- XStream through a helper
_XS_SERVLET = _servlet("", '''        resp.getWriter().println(Marshal.fromXml(req.getReader()));''', "import com.acme.io.Marshal;\n")
case("xstream_helper", {
    "src/com/acme/web/EntryServlet.java": _XS_SERVLET,
    "src/com/acme/io/Marshal.java": '''package com.acme.io;

import com.thoughtworks.xstream.XStream;
import java.io.Reader;

public final class Marshal {
    private Marshal() {}

    public static Object fromXml(Reader in) {
        XStream xs = new XStream();
        return xs.fromXML(in);  // frame-expect: CWE-502
    }
}
''',
}, {
    "src/com/acme/web/EntryServlet.java": _XS_SERVLET,
    "src/com/acme/io/Marshal.java": '''package com.acme.io;

import com.thoughtworks.xstream.XStream;
import com.thoughtworks.xstream.security.NoTypePermission;
import com.thoughtworks.xstream.security.AnyTypePermission;
import java.io.Reader;

public final class Marshal {
    private Marshal() {}

    public static Object fromXml(Reader in) {
        XStream xs = new XStream();
        xs.addPermission(NoTypePermission.NONE);
        xs.allowTypes(new Class[] {com.acme.io.Marshal.class});
        return xs.fromXML(in);
    }
}
''',
})

# 24 -- open redirect: sendRedirect with a relative-path guard
_RD_HEAD = '''package com.acme.web;

import java.io.IOException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class LoginServlet extends HttpServlet {
    @Override
    protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        String next = req.getParameter("next");
'''
case("sendredirect_relative_guard", {
    "src/com/acme/web/LoginServlet.java": _RD_HEAD + '''        resp.sendRedirect(next);  // frame-expect: CWE-601
    }
}
''',
}, {
    "src/com/acme/web/LoginServlet.java": _RD_HEAD + '''        if (next == null || !next.startsWith("/") || next.startsWith("//")) {
            next = "/home";
        }
        resp.sendRedirect(next);
    }
}
''',
})
