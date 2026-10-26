"""Realistic multi-file C# (ASP.NET Core) projects: vulnerable tree + safe twin."""

CASES = {}


def case(name, vulnerable, safe):
    CASES[name] = (vulnerable, safe)


_CTRL = '''using Microsoft.AspNetCore.Mvc;
using Shop.Services;

namespace Shop.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class UsersController : ControllerBase
    {
        private readonly UserService _service;

        public UsersController(UserService service)
        {
            _service = service;
        }

        [HttpGet]
        public IActionResult Search([FromQuery] string name)
        {
            return Ok(_service.Describe(name));
        }
    }
}
'''
_SERVICE = '''using Shop.Data;

namespace Shop.Services
{
    public class UserService
    {
        private readonly UserRepository _repo;

        public UserService(UserRepository repo)
        {
            _repo = repo;
        }

        public string Describe(string name)
        {
            return _repo.FindByName(name.Trim());
        }
    }
}
'''
case("controller_service_repository_ado_net", {
    "Controllers/UsersController.cs": _CTRL,
    "Services/UserService.cs": _SERVICE,
    "Data/UserRepository.cs": '''using System.Data.SqlClient;

namespace Shop.Data
{
    public class UserRepository
    {
        private readonly SqlConnection _connection;

        public UserRepository(SqlConnection connection)
        {
            _connection = connection;
        }

        public string FindByName(string name)
        {
            var cmd = new SqlCommand("SELECT Email FROM Users WHERE Name = '" + name + "'", _connection);  // frame-expect: CWE-89
            var result = cmd.ExecuteScalar();
            return result?.ToString() ?? "";
        }
    }
}
''',
}, {
    "Controllers/UsersController.cs": _CTRL,
    "Services/UserService.cs": _SERVICE,
    "Data/UserRepository.cs": '''using System.Data.SqlClient;

namespace Shop.Data
{
    public class UserRepository
    {
        private readonly SqlConnection _connection;

        public UserRepository(SqlConnection connection)
        {
            _connection = connection;
        }

        public string FindByName(string name)
        {
            var cmd = new SqlCommand("SELECT Email FROM Users WHERE Name = @name", _connection);
            cmd.Parameters.AddWithValue("@name", name);
            var result = cmd.ExecuteScalar();
            return result?.ToString() ?? "";
        }
    }
}
''',
})

# --------------------------------------------------------------------------------------
_IFACE = '''namespace Bank.Data
{
    public interface IAccountRepository
    {
        string BalanceFor(string owner);
    }
}
'''
_BANK_CTRL = '''using Bank.Data;
using Microsoft.AspNetCore.Mvc;

namespace Bank.Web
{
    public class AccountController : Controller
    {
        private readonly IAccountRepository _accounts;

        public AccountController(IAccountRepository accounts)
        {
            _accounts = accounts;
        }

        public IActionResult Show(string owner)
        {
            return Ok(_accounts.BalanceFor(owner));
        }
    }
}
'''
case("interface_with_single_implementation", {
    "Data/IAccountRepository.cs": _IFACE,
    "Web/AccountController.cs": _BANK_CTRL,
    "Data/SqlAccountRepository.cs": '''using System.Data.SqlClient;

namespace Bank.Data
{
    public class SqlAccountRepository : IAccountRepository
    {
        private readonly SqlConnection _connection;

        public SqlAccountRepository(SqlConnection connection)
        {
            _connection = connection;
        }

        public string BalanceFor(string owner)
        {
            var cmd = new SqlCommand("SELECT Balance FROM Accounts WHERE Owner = '" + owner + "'", _connection);  // frame-expect: CWE-89
            return cmd.ExecuteScalar()?.ToString() ?? "0";
        }
    }
}
''',
}, {
    "Data/IAccountRepository.cs": _IFACE,
    "Web/AccountController.cs": _BANK_CTRL,
    "Data/SqlAccountRepository.cs": '''using System.Data.SqlClient;

namespace Bank.Data
{
    public class SqlAccountRepository : IAccountRepository
    {
        private readonly SqlConnection _connection;

        public SqlAccountRepository(SqlConnection connection)
        {
            _connection = connection;
        }

        public string BalanceFor(string owner)
        {
            var cmd = new SqlCommand("SELECT Balance FROM Accounts WHERE Owner = @owner", _connection);
            cmd.Parameters.AddWithValue("@owner", owner);
            return cmd.ExecuteScalar()?.ToString() ?? "0";
        }
    }
}
''',
})

# --------------------------------------------------------------------------------------
_OPS_CTRL = '''using Microsoft.AspNetCore.Mvc;
using Ops.Tools;

namespace Ops.Web
{
    public class PingController : Controller
    {
        [HttpPost]
        public IActionResult Run(string host)
        {
            return Ok(Network.Ping(host));
        }
    }
}
'''
case("static_helper_starts_a_process", {
    "Web/PingController.cs": _OPS_CTRL,
    "Tools/Network.cs": '''using System.Diagnostics;

namespace Ops.Tools
{
    public static class Network
    {
        public static string Ping(string host)
        {
            var psi = new ProcessStartInfo("cmd.exe", "/c ping " + host) { RedirectStandardOutput = true };  // frame-expect: CWE-78
            var p = Process.Start(psi);
            return p.StandardOutput.ReadToEnd();
        }
    }
}
''',
}, {
    "Web/PingController.cs": _OPS_CTRL,
    "Tools/Network.cs": '''using System.Diagnostics;
using System.Text.RegularExpressions;

namespace Ops.Tools
{
    public static class Network
    {
        public static string Ping(string host)
        {
            if (!Regex.IsMatch(host, "^[A-Za-z0-9.-]{1,253}$"))
            {
                throw new System.ArgumentException("bad host");
            }
            var psi = new ProcessStartInfo("ping") { RedirectStandardOutput = true };
            psi.ArgumentList.Add("-c");
            psi.ArgumentList.Add("1");
            psi.ArgumentList.Add(host);
            var p = Process.Start(psi);
            return p.StandardOutput.ReadToEnd();
        }
    }
}
''',
})

# --------------------------------------------------------------------------------------
_FILE_CTRL = '''using Microsoft.AspNetCore.Mvc;
using Docs.Storage;

namespace Docs.Web
{
    public class DownloadController : Controller
    {
        private readonly FileStore _store = new FileStore();

        public IActionResult Get(string file)
        {
            return Ok(_store.Read(file));
        }
    }
}
'''
case("path_traversal_in_store", {
    "Web/DownloadController.cs": _FILE_CTRL,
    "Storage/FileStore.cs": '''using System.IO;

namespace Docs.Storage
{
    public class FileStore
    {
        private const string Root = "/srv/docs";

        public string Read(string name)
        {
            var path = Path.Combine(Root, name);
            return File.ReadAllText(path);  // frame-expect: CWE-22
        }
    }
}
''',
}, {
    "Web/DownloadController.cs": _FILE_CTRL,
    "Storage/FileStore.cs": '''using System.IO;

namespace Docs.Storage
{
    public class FileStore
    {
        private const string Root = "/srv/docs";

        public string Read(string name)
        {
            var path = Path.Combine(Root, Path.GetFileName(name));
            return File.ReadAllText(path);
        }
    }
}
''',
})
