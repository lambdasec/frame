"""Realistic multi-file Java projects (vulnerable tree + safe twin)."""

CASES = {}


def case(name, vulnerable, safe):
    CASES[name] = (vulnerable, safe)


# --------------------------------------------------------------------------------------
_SERVLET = '''package com.acme.web;

import com.acme.service.UserService;
import java.io.IOException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class UserServlet extends HttpServlet {
    private final UserService service = new UserService();

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        String name = req.getParameter("name");
        resp.getWriter().println(service.describe(name));
    }
}
'''
_SERVICE = '''package com.acme.service;

import com.acme.dao.UserDao;

public class UserService {
    private final UserDao dao = new UserDao();

    public String describe(String name) {
        return dao.findByName(name.trim());
    }
}
'''
case("servlet_service_dao_jdbc", {
    "src/com/acme/web/UserServlet.java": _SERVLET,
    "src/com/acme/service/UserService.java": _SERVICE,
    "src/com/acme/dao/UserDao.java": '''package com.acme.dao;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class UserDao {
    public String findByName(String name) {
        try (Connection c = DriverManager.getConnection("jdbc:h2:mem:app")) {
            Statement st = c.createStatement();
            ResultSet rs = st.executeQuery("SELECT email FROM users WHERE name = '" + name + "'");  // frame-expect: CWE-89
            return rs.next() ? rs.getString(1) : "";
        } catch (SQLException e) {
            throw new IllegalStateException(e);
        }
    }
}
''',
}, {
    "src/com/acme/web/UserServlet.java": _SERVLET,
    "src/com/acme/service/UserService.java": _SERVICE,
    "src/com/acme/dao/UserDao.java": '''package com.acme.dao;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;

public class UserDao {
    public String findByName(String name) {
        try (Connection c = DriverManager.getConnection("jdbc:h2:mem:app")) {
            PreparedStatement st = c.prepareStatement("SELECT email FROM users WHERE name = ?");
            st.setString(1, name);
            ResultSet rs = st.executeQuery();
            return rs.next() ? rs.getString(1) : "";
        } catch (SQLException e) {
            throw new IllegalStateException(e);
        }
    }
}
''',
})

# --------------------------------------------------------------------------------------
_SPRING_CTRL = '''package com.acme.api;

import com.acme.repo.ProductRepository;
import java.util.List;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class ProductController {
    private final ProductRepository repo;

    public ProductController(ProductRepository repo) {
        this.repo = repo;
    }

    @GetMapping("/products")
    public List<String> search(@RequestParam("q") String q) {
        return repo.search(q);
    }
}
'''
case("spring_controller_jdbctemplate_repository", {
    "src/com/acme/api/ProductController.java": _SPRING_CTRL,
    "src/com/acme/repo/ProductRepository.java": '''package com.acme.repo;

import java.util.List;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Repository;

@Repository
public class ProductRepository {
    private final JdbcTemplate jdbc;

    public ProductRepository(JdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    public List<String> search(String q) {
        return jdbc.queryForList("SELECT title FROM products WHERE title LIKE '%" + q + "%'", String.class);  // frame-expect: CWE-89
    }
}
''',
}, {
    "src/com/acme/api/ProductController.java": _SPRING_CTRL,
    "src/com/acme/repo/ProductRepository.java": '''package com.acme.repo;

import java.util.List;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Repository;

@Repository
public class ProductRepository {
    private final JdbcTemplate jdbc;

    public ProductRepository(JdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    public List<String> search(String q) {
        return jdbc.queryForList("SELECT title FROM products WHERE title LIKE ?", String.class, "%" + q + "%");
    }
}
''',
})

# --------------------------------------------------------------------------------------
_IFACE = '''package com.acme.repo;

public interface AccountRepository {
    String balanceFor(String owner);
}
'''
_ACCT_CTRL = '''package com.acme.web;

import com.acme.repo.AccountRepository;
import javax.servlet.http.HttpServletRequest;

public class AccountController {
    private final AccountRepository accounts;

    public AccountController(AccountRepository accounts) {
        this.accounts = accounts;
    }

    public String show(HttpServletRequest request) {
        return accounts.balanceFor(request.getParameter("owner"));
    }
}
'''
case("interface_with_single_implementation", {
    "src/com/acme/repo/AccountRepository.java": _IFACE,
    "src/com/acme/web/AccountController.java": _ACCT_CTRL,
    "src/com/acme/repo/JdbcAccountRepository.java": '''package com.acme.repo;

import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class JdbcAccountRepository implements AccountRepository {
    private final Connection connection;

    public JdbcAccountRepository(Connection connection) {
        this.connection = connection;
    }

    @Override
    public String balanceFor(String owner) {
        try {
            Statement st = connection.createStatement();
            ResultSet rs = st.executeQuery("SELECT balance FROM accounts WHERE owner = '" + owner + "'");  // frame-expect: CWE-89
            return rs.next() ? rs.getString(1) : "0";
        } catch (SQLException e) {
            throw new IllegalStateException(e);
        }
    }
}
''',
}, {
    "src/com/acme/repo/AccountRepository.java": _IFACE,
    "src/com/acme/web/AccountController.java": _ACCT_CTRL,
    "src/com/acme/repo/JdbcAccountRepository.java": '''package com.acme.repo;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;

public class JdbcAccountRepository implements AccountRepository {
    private final Connection connection;

    public JdbcAccountRepository(Connection connection) {
        this.connection = connection;
    }

    @Override
    public String balanceFor(String owner) {
        try {
            PreparedStatement st = connection.prepareStatement("SELECT balance FROM accounts WHERE owner = ?");
            st.setString(1, owner);
            ResultSet rs = st.executeQuery();
            return rs.next() ? rs.getString(1) : "0";
        } catch (SQLException e) {
            throw new IllegalStateException(e);
        }
    }
}
''',
})

# --------------------------------------------------------------------------------------
_PING_SERVLET = '''package com.acme.web;

import com.acme.ops.Network;
import java.io.IOException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class PingServlet extends HttpServlet {
    @Override
    protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        resp.getWriter().println(Network.ping(req.getParameter("host")));
    }
}
'''
case("static_utility_runs_command", {
    "src/com/acme/web/PingServlet.java": _PING_SERVLET,
    "src/com/acme/ops/Network.java": '''package com.acme.ops;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;

public final class Network {
    private Network() {}

    public static String ping(String host) throws IOException {
        Process p = Runtime.getRuntime().exec("ping -c 1 " + host);  // frame-expect: CWE-78
        try (BufferedReader r = new BufferedReader(new InputStreamReader(p.getInputStream()))) {
            return r.readLine();
        }
    }
}
''',
}, {
    "src/com/acme/web/PingServlet.java": _PING_SERVLET,
    "src/com/acme/ops/Network.java": '''package com.acme.ops;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.regex.Pattern;

public final class Network {
    private static final Pattern HOST = Pattern.compile("[A-Za-z0-9.-]{1,253}");

    private Network() {}

    public static String ping(String host) throws IOException {
        if (!HOST.matcher(host).matches()) {
            throw new IllegalArgumentException("bad host");
        }
        Process p = new ProcessBuilder("ping", "-c", "1", host).start();
        try (BufferedReader r = new BufferedReader(new InputStreamReader(p.getInputStream()))) {
            return r.readLine();
        }
    }
}
''',
})

# --------------------------------------------------------------------------------------
_FILE_SERVLET = '''package com.acme.web;

import com.acme.files.Storage;
import java.io.IOException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class DownloadServlet extends HttpServlet {
    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        resp.getOutputStream().write(Storage.read(req.getParameter("file")));
    }
}
'''
case("path_traversal_in_storage_helper", {
    "src/com/acme/web/DownloadServlet.java": _FILE_SERVLET,
    "src/com/acme/files/Storage.java": '''package com.acme.files;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;

public final class Storage {
    private static final File ROOT = new File("/srv/files");

    private Storage() {}

    public static byte[] read(String name) throws IOException {
        File f = new File(ROOT, name);  // frame-expect: CWE-22
        return Files.readAllBytes(f.toPath());
    }
}
''',
}, {
    "src/com/acme/web/DownloadServlet.java": _FILE_SERVLET,
    "src/com/acme/files/Storage.java": '''package com.acme.files;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;

public final class Storage {
    private static final File ROOT = new File("/srv/files");

    private Storage() {}

    public static byte[] read(String name) throws IOException {
        File f = new File(ROOT, new File(name).getName());
        return Files.readAllBytes(f.toPath());
    }
}
''',
})
