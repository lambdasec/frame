"""More realistic multi-file C# (ASP.NET Core) projects (vulnerable tree + safe twin): shapes beyond projects_csharp.py."""

CASES = {}


KNOWN_GAPS = {}


def case(name, vulnerable, safe):
    CASES[name] = (vulnerable, safe)


def gap(name, vulnerable, safe):
    """A realistic project Frame does not follow yet: only the vulnerable tree is pinned
    (strict xfail in test_known_gaps_jvmnet.py); the safe twin documents the fix."""
    KNOWN_GAPS[name] = vulnerable


def _api(name, uses, stype, call, params="[FromQuery] string q", attrs="[HttpGet]", usings_extra=""):
    return f'''using Microsoft.AspNetCore.Mvc;
{uses}
namespace App.Web
{{
    [ApiController]
    [Route("api/[controller]")]
    public class {name}Controller : ControllerBase
    {{
        private readonly {stype} _svc;

        public {name}Controller({stype} svc)
        {{
            _svc = svc;
        }}

        {attrs}
        public IActionResult Get({params})
        {{
            return Ok({call});
        }}
    }}
}}
'''


# 1 -- abstract base service, subclass overrides the abstract step that runs the SQL
_ABS_CTRL = _api("Orders", "using App.Services;\n", "OrderService", "_svc.Find(q)")
_ABS_BASE = '''namespace App.Services
{
    public abstract class BaseService
    {
        public string Find(string key)
        {
            return Execute(key.Trim());
        }

        protected abstract string Execute(string key);
    }
}
'''
case("abstract_base_service_override", {
    "Web/OrdersController.cs": _ABS_CTRL,
    "Services/BaseService.cs": _ABS_BASE,
    "Services/OrderService.cs": '''using System.Data.SqlClient;

namespace App.Services
{
    public class OrderService : BaseService
    {
        private readonly SqlConnection _db;

        public OrderService(SqlConnection db)
        {
            _db = db;
        }

        protected override string Execute(string key)
        {
            var cmd = new SqlCommand("SELECT Note FROM Orders WHERE Ref = '" + key + "'", _db);  // frame-expect: CWE-89
            return cmd.ExecuteScalar()?.ToString();
        }
    }
}
''',
}, {
    "Web/OrdersController.cs": _ABS_CTRL,
    "Services/BaseService.cs": _ABS_BASE,
    "Services/OrderService.cs": '''using System.Data.SqlClient;

namespace App.Services
{
    public class OrderService : BaseService
    {
        private readonly SqlConnection _db;

        public OrderService(SqlConnection db)
        {
            _db = db;
        }

        protected override string Execute(string key)
        {
            var cmd = new SqlCommand("SELECT Note FROM Orders WHERE Ref = @ref", _db);
            cmd.Parameters.AddWithValue("@ref", key);
            return cmd.ExecuteScalar()?.ToString();
        }
    }
}
''',
})

# 2 -- generic repository interface, Dapper string building vs parameters
_GEN_CTRL = _api("People", "using App.Data;\n", "IRepository<Person>", "_svc.FindBy(\"Name\", q)")
_GEN_IFACE = '''using System.Collections.Generic;

namespace App.Data
{
    public class Person
    {
        public string Name { get; set; }
    }

    public interface IRepository<T>
    {
        IEnumerable<T> FindBy(string column, string value);
    }
}
'''
case("generic_repository_dapper", {
    "Web/PeopleController.cs": _GEN_CTRL,
    "Data/IRepository.cs": _GEN_IFACE,
    "Data/PersonRepository.cs": '''using System.Collections.Generic;
using System.Data;
using Dapper;

namespace App.Data
{
    public class PersonRepository : IRepository<Person>
    {
        private readonly IDbConnection _db;

        public PersonRepository(IDbConnection db)
        {
            _db = db;
        }

        public IEnumerable<Person> FindBy(string column, string value)
        {
            var sql = "SELECT * FROM People WHERE " + column + " = '" + value + "'";
            return _db.Query<Person>(sql);  // frame-expect: CWE-89
        }
    }
}
''',
}, {
    "Web/PeopleController.cs": _GEN_CTRL,
    "Data/IRepository.cs": _GEN_IFACE,
    "Data/PersonRepository.cs": '''using System;
using System.Collections.Generic;
using System.Data;
using Dapper;

namespace App.Data
{
    public class PersonRepository : IRepository<Person>
    {
        private readonly IDbConnection _db;

        public PersonRepository(IDbConnection db)
        {
            _db = db;
        }

        public IEnumerable<Person> FindBy(string column, string value)
        {
            if (column != "Name" && column != "Email") throw new ArgumentException(column);
            return _db.Query<Person>("SELECT * FROM People WHERE " + column + " = @value", new { value });
        }
    }
}
''',
})

# 3 -- [FromBody] record DTO whose property carries request data
_REC_CTRL = '''using App.Data;
using Microsoft.AspNetCore.Mvc;

namespace App.Web
{
    public record SearchRequest(string Term, int Limit);

    [ApiController]
    [Route("api/[controller]")]
    public class SearchController : ControllerBase
    {
        private readonly DocumentStore _store;

        public SearchController(DocumentStore store)
        {
            _store = store;
        }

        [HttpPost]
        public IActionResult Post([FromBody] SearchRequest body)
        {
            return Ok(_store.Search(body.Term));
        }
    }
}
'''
case("frombody_record_property", {
    "Web/SearchController.cs": _REC_CTRL,
    "Data/DocumentStore.cs": '''using Microsoft.EntityFrameworkCore;
using System.Linq;

namespace App.Data
{
    public class DocumentStore
    {
        private readonly AppDbContext _ctx;

        public DocumentStore(AppDbContext ctx)
        {
            _ctx = ctx;
        }

        public string[] Search(string term)
        {
            return _ctx.Documents.FromSqlRaw("SELECT * FROM Documents WHERE Body LIKE '%" + term + "%'")  // frame-expect: CWE-89
                .Select(d => d.Title).ToArray();
        }
    }
}
''',
}, {
    "Web/SearchController.cs": _REC_CTRL,
    "Data/DocumentStore.cs": '''using Microsoft.EntityFrameworkCore;
using System.Linq;

namespace App.Data
{
    public class DocumentStore
    {
        private readonly AppDbContext _ctx;

        public DocumentStore(AppDbContext ctx)
        {
            _ctx = ctx;
        }

        public string[] Search(string term)
        {
            return _ctx.Documents.FromSqlInterpolated($"SELECT * FROM Documents WHERE Body LIKE {"%" + term + "%"}")
                .Select(d => d.Title).ToArray();
        }
    }
}
''',
})

# 4 -- EF Core FromSqlRaw with an interpolated string (the interpolation IS the injection) vs FromSqlInterpolated
_EF_CTRL = _api("Products", "using App.Data;\n", "ProductQueries", "_svc.ByCategory(q)")
case("efcore_fromsqlraw_interpolated", {
    "Web/ProductsController.cs": _EF_CTRL,
    "Data/ProductQueries.cs": '''using System.Collections.Generic;
using System.Linq;
using Microsoft.EntityFrameworkCore;

namespace App.Data
{
    public class ProductQueries
    {
        private readonly AppDbContext _ctx;

        public ProductQueries(AppDbContext ctx)
        {
            _ctx = ctx;
        }

        public List<Product> ByCategory(string category)
        {
            return _ctx.Products.FromSqlRaw($"SELECT * FROM Products WHERE Category = '{category}'").ToList();  // frame-expect: CWE-89
        }
    }
}
''',
}, {
    "Web/ProductsController.cs": _EF_CTRL,
    "Data/ProductQueries.cs": '''using System.Collections.Generic;
using System.Linq;
using Microsoft.EntityFrameworkCore;

namespace App.Data
{
    public class ProductQueries
    {
        private readonly AppDbContext _ctx;

        public ProductQueries(AppDbContext ctx)
        {
            _ctx = ctx;
        }

        public List<Product> ByCategory(string category)
        {
            return _ctx.Products.FromSqlInterpolated($"SELECT * FROM Products WHERE Category = {category}").ToList();
        }
    }
}
''',
})

# 5 -- minimal API calling a static helper
_MIN_PROGRAM = '''using App.Data;

var builder = WebApplication.CreateBuilder(args);
var app = builder.Build();

app.MapGet("/users", (string name) => Users.Find(name));

app.Run();
'''
case("minimal_api_static_helper", {
    "Program.cs": _MIN_PROGRAM,
    "Data/Users.cs": '''using System.Data.SqlClient;

namespace App.Data
{
    public static class Users
    {
        public static string Find(string name)
        {
            using var conn = new SqlConnection("Server=.;Database=app");
            conn.Open();
            using var cmd = new SqlCommand("SELECT Email FROM Users WHERE Name = '" + name + "'", conn);  // frame-expect: CWE-89
            return cmd.ExecuteScalar()?.ToString();
        }
    }
}
''',
}, {
    "Program.cs": _MIN_PROGRAM,
    "Data/Users.cs": '''using System.Data.SqlClient;

namespace App.Data
{
    public static class Users
    {
        public static string Find(string name)
        {
            using var conn = new SqlConnection("Server=.;Database=app");
            conn.Open();
            using var cmd = new SqlCommand("SELECT Email FROM Users WHERE Name = @name", conn);
            cmd.Parameters.AddWithValue("@name", name);
            return cmd.ExecuteScalar()?.ToString();
        }
    }
}
''',
})

# 6 -- Razor Pages: code-behind binds a property from the query string
_PM_PAGE = '''@page
@model App.Pages.SearchModel
<h1>Search</h1>
'''
case("razor_page_bindproperty_code_behind", {
    "Pages/Search.cshtml": _PM_PAGE,
    "Pages/Search.cshtml.cs": '''using App.Data;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace App.Pages
{
    public class SearchModel : PageModel
    {
        private readonly TicketStore _tickets;

        [BindProperty(SupportsGet = true)]
        public string Query { get; set; }

        public string Result { get; set; }

        public SearchModel(TicketStore tickets)
        {
            _tickets = tickets;
        }

        public void OnGet()
        {
            Result = _tickets.Find(Query);
        }
    }
}
''',
    "Data/TicketStore.cs": '''using System.Data.SqlClient;

namespace App.Data
{
    public class TicketStore
    {
        private readonly SqlConnection _db;

        public TicketStore(SqlConnection db)
        {
            _db = db;
        }

        public string Find(string query)
        {
            var cmd = _db.CreateCommand();
            cmd.CommandText = "SELECT Title FROM Tickets WHERE Title LIKE '%" + query + "%'";  // frame-expect: CWE-89
            return cmd.ExecuteScalar()?.ToString();
        }
    }
}
''',
}, {
    "Pages/Search.cshtml": _PM_PAGE,
    "Pages/Search.cshtml.cs": '''using App.Data;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace App.Pages
{
    public class SearchModel : PageModel
    {
        private readonly TicketStore _tickets;

        [BindProperty(SupportsGet = true)]
        public string Query { get; set; }

        public string Result { get; set; }

        public SearchModel(TicketStore tickets)
        {
            _tickets = tickets;
        }

        public void OnGet()
        {
            Result = _tickets.Find(Query);
        }
    }
}
''',
    "Data/TicketStore.cs": '''using System.Data.SqlClient;

namespace App.Data
{
    public class TicketStore
    {
        private readonly SqlConnection _db;

        public TicketStore(SqlConnection db)
        {
            _db = db;
        }

        public string Find(string query)
        {
            var cmd = _db.CreateCommand();
            cmd.CommandText = "SELECT Title FROM Tickets WHERE Title LIKE @q";
            cmd.Parameters.AddWithValue("@q", "%" + query + "%");
            return cmd.ExecuteScalar()?.ToString();
        }
    }
}
''',
})

# 7 -- extension method on string that starts a shell
_EXT_CTRL = '''using App.Util;
using Microsoft.AspNetCore.Mvc;

namespace App.Web
{
    [ApiController]
    [Route("api/[controller]")]
    public class ToolsController : ControllerBase
    {
        [HttpGet]
        public IActionResult Get([FromQuery] string arg)
        {
            return Ok(arg.RunAsCommand());
        }
    }
}
'''
gap("extension_method_runs_process", {
    "Web/ToolsController.cs": _EXT_CTRL,
    "Util/ProcessExtensions.cs": '''using System.Diagnostics;

namespace App.Util
{
    public static class ProcessExtensions
    {
        public static string RunAsCommand(this string arg)
        {
            var p = Process.Start("/bin/sh", "-c \"tool " + arg + "\"");  // frame-expect: CWE-78
            return p.Id.ToString();
        }
    }
}
''',
}, {
    "Web/ToolsController.cs": _EXT_CTRL,
    "Util/ProcessExtensions.cs": '''using System.Diagnostics;

namespace App.Util
{
    public static class ProcessExtensions
    {
        public static string RunAsCommand(this string arg)
        {
            var psi = new ProcessStartInfo("/usr/bin/tool");
            psi.ArgumentList.Add("--");
            psi.ArgumentList.Add(arg);
            var p = Process.Start(psi);
            return p.Id.ToString();
        }
    }
}
''',
})

# 8 -- ProcessStartInfo.Arguments (one string) vs ArgumentList
_PS_CTRL = _api("Convert", "using App.Media;\n", "Converter", "_svc.ToPng(q)")
case("processstartinfo_arguments_property", {
    "Web/ConvertController.cs": _PS_CTRL,
    "Media/Converter.cs": '''using System.Diagnostics;

namespace App.Media
{
    public class Converter
    {
        public string ToPng(string file)
        {
            var psi = new ProcessStartInfo
            {
                FileName = "convert",
                Arguments = file + " out.png",  // frame-expect: CWE-78
                UseShellExecute = false,
            };
            using var p = Process.Start(psi);
            p.WaitForExit();
            return "out.png";
        }
    }
}
''',
}, {
    "Web/ConvertController.cs": _PS_CTRL,
    "Media/Converter.cs": '''using System.Diagnostics;

namespace App.Media
{
    public class Converter
    {
        public string ToPng(string file)
        {
            var psi = new ProcessStartInfo
            {
                FileName = "convert",
                UseShellExecute = false,
            };
            psi.ArgumentList.Add("--");
            psi.ArgumentList.Add(file);
            psi.ArgumentList.Add("out.png");
            using var p = Process.Start(psi);
            p.WaitForExit();
            return "out.png";
        }
    }
}
''',
})

# 9 -- Path.Combine traversal vs GetFileName
_FILE_CTRL = _api("Files", "using App.Storage;\n", "FileStore", "_svc.Read(q)")
case("path_combine_getfilename", {
    "Web/FilesController.cs": _FILE_CTRL,
    "Storage/FileStore.cs": '''using System.IO;

namespace App.Storage
{
    public class FileStore
    {
        private const string Root = "/srv/files";

        public string Read(string name)
        {
            var full = Path.Combine(Root, name);
            return File.ReadAllText(full);  // frame-expect: CWE-22
        }
    }
}
''',
}, {
    "Web/FilesController.cs": _FILE_CTRL,
    "Storage/FileStore.cs": '''using System.IO;

namespace App.Storage
{
    public class FileStore
    {
        private const string Root = "/srv/files";

        public string Read(string name)
        {
            var full = Path.Combine(Root, Path.GetFileName(name));
            return File.ReadAllText(full);
        }
    }
}
''',
})

# 10 -- XmlDocument / XmlTextReader with DTD processing
_XML_CTRL = '''using App.Xml;
using Microsoft.AspNetCore.Mvc;

namespace App.Web
{
    [ApiController]
    [Route("api/[controller]")]
    public class ImportController : ControllerBase
    {
        [HttpPost]
        public IActionResult Post([FromBody] string xml)
        {
            return Ok(XmlImporter.RootName(xml));
        }
    }
}
'''
case("xml_reader_dtd_processing", {
    "Web/ImportController.cs": _XML_CTRL,
    "Xml/XmlImporter.cs": '''using System.IO;
using System.Xml;

namespace App.Xml
{
    public static class XmlImporter
    {
        public static string RootName(string xml)
        {
            var settings = new XmlReaderSettings { DtdProcessing = DtdProcessing.Parse, XmlResolver = new XmlUrlResolver() };
            using var reader = XmlReader.Create(new StringReader(xml), settings);  // frame-expect: CWE-611
            var doc = new XmlDocument();  // frame-expect: CWE-611
            doc.Load(reader);
            return doc.DocumentElement.Name;
        }
    }
}
''',
}, {
    "Web/ImportController.cs": _XML_CTRL,
    "Xml/XmlImporter.cs": '''using System.IO;
using System.Xml;

namespace App.Xml
{
    public static class XmlImporter
    {
        public static string RootName(string xml)
        {
            var settings = new XmlReaderSettings { DtdProcessing = DtdProcessing.Prohibit, XmlResolver = null };
            using var reader = XmlReader.Create(new StringReader(xml), settings);
            var doc = new XmlDocument();
            doc.Load(reader);
            return doc.DocumentElement.Name;
        }
    }
}
''',
})

# 11 -- Json.NET TypeNameHandling
_JSON_CTRL = _api("Messages", "using App.Messaging;\n", "MessageReader", "_svc.Read(q)", params="[FromBody] string payload".replace("[FromBody] string payload", "[FromQuery] string q"))
case("jsonnet_typenamehandling_all", {
    "Web/MessagesController.cs": _JSON_CTRL,
    "Messaging/MessageReader.cs": '''using Newtonsoft.Json;

namespace App.Messaging
{
    public class MessageReader
    {
        public object Read(string json)
        {
            var settings = new JsonSerializerSettings { TypeNameHandling = TypeNameHandling.All };  // frame-expect: CWE-502
            return JsonConvert.DeserializeObject(json, settings);
        }
    }
}
''',
}, {
    "Web/MessagesController.cs": _JSON_CTRL,
    "Messaging/MessageReader.cs": '''using Newtonsoft.Json;

namespace App.Messaging
{
    public class MessageReader
    {
        public object Read(string json)
        {
            var settings = new JsonSerializerSettings { TypeNameHandling = TypeNameHandling.None };
            return JsonConvert.DeserializeObject(json, settings);
        }
    }
}
''',
})

# 12 -- BinaryFormatter on request bytes
_BF_CTRL = '''using App.Messaging;
using Microsoft.AspNetCore.Mvc;

namespace App.Web
{
    [ApiController]
    [Route("api/[controller]")]
    public class SessionController : ControllerBase
    {
        [HttpPost]
        public IActionResult Post()
        {
            return Ok(SessionCodec.Load(Request.Body));
        }
    }
}
'''
case("binaryformatter_codec", {
    "Web/SessionController.cs": _BF_CTRL,
    "Messaging/SessionCodec.cs": '''using System.IO;
using System.Runtime.Serialization.Formatters.Binary;

namespace App.Messaging
{
    public static class SessionCodec
    {
        public static object Load(Stream body)
        {
            var formatter = new BinaryFormatter();  // frame-expect: CWE-502
            return formatter.Deserialize(body);
        }
    }
}
''',
}, {
    "Web/SessionController.cs": _BF_CTRL,
    "Messaging/SessionCodec.cs": '''using System.IO;
using System.Text.Json;

namespace App.Messaging
{
    public static class SessionCodec
    {
        public static object Load(Stream body)
        {
            return JsonSerializer.Deserialize<System.Collections.Generic.Dictionary<string, string>>(body);
        }
    }
}
''',
})

# 13 -- HttpClient SSRF helper with a host allow-list
_SSRF_CTRL = _api("Proxy", "using App.Net;\n", "Fetcher", "_svc.GetAsync(q).Result")
case("httpclient_fetch_helper", {
    "Web/ProxyController.cs": _SSRF_CTRL,
    "Net/Fetcher.cs": '''using System.Net.Http;
using System.Threading.Tasks;

namespace App.Net
{
    public class Fetcher
    {
        private static readonly HttpClient Client = new HttpClient();

        public async Task<string> GetAsync(string url)
        {
            return await Client.GetStringAsync(url);  // frame-expect: CWE-918
        }
    }
}
''',
}, {
    "Web/ProxyController.cs": _SSRF_CTRL,
    "Net/Fetcher.cs": '''using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Threading.Tasks;

namespace App.Net
{
    public class Fetcher
    {
        private static readonly HttpClient Client = new HttpClient();
        private static readonly HashSet<string> Allowed = new HashSet<string> { "api.acme.com", "cdn.acme.com" };

        public async Task<string> GetAsync(string url)
        {
            var uri = new Uri(url);
            if (!Allowed.Contains(uri.Host)) throw new ArgumentException("host not allowed");
            return await Client.GetStringAsync(uri);
        }
    }
}
''',
})

# 14 -- open redirect with Url.IsLocalUrl
_LOGIN = '''using Microsoft.AspNetCore.Mvc;

namespace App.Web
{
    public class AccountController : Controller
    {
        [HttpPost]
        public IActionResult Login(string returnUrl)
        {
%s
        }
    }
}
'''
case("redirect_url_islocalurl", {
    "Web/AccountController.cs": _LOGIN % '            return Redirect(returnUrl);  // frame-expect: CWE-601',
}, {
    "Web/AccountController.cs": _LOGIN % '''            if (Url.IsLocalUrl(returnUrl))
            {
                return Redirect(returnUrl);
            }
            return RedirectToAction("Index", "Home");''',
})

# 15 -- partial class split over two files, the sink in the second part
_PARTIAL_CTRL = _api("Audit", "using App.Services;\n", "AuditService", "_svc.Search(q)")
gap("partial_class_second_file", {
    "Web/AuditController.cs": _PARTIAL_CTRL,
    "Services/AuditService.cs": '''namespace App.Services
{
    public partial class AuditService
    {
        public string Search(string actor)
        {
            return Query(actor.Trim());
        }
    }
}
''',
    "Services/AuditService.Sql.cs": '''using System.Data.SqlClient;

namespace App.Services
{
    public partial class AuditService
    {
        private readonly SqlConnection _db;

        public AuditService(SqlConnection db)
        {
            _db = db;
        }

        private string Query(string actor)
        {
            var cmd = new SqlCommand("SELECT Action FROM Audit WHERE Actor = '" + actor + "'", _db);  // frame-expect: CWE-89
            return cmd.ExecuteScalar()?.ToString();
        }
    }
}
''',
}, {
    "Web/AuditController.cs": _PARTIAL_CTRL,
    "Services/AuditService.cs": '''namespace App.Services
{
    public partial class AuditService
    {
        public string Search(string actor)
        {
            return Query(actor.Trim());
        }
    }
}
''',
    "Services/AuditService.Sql.cs": '''using System.Data.SqlClient;

namespace App.Services
{
    public partial class AuditService
    {
        private readonly SqlConnection _db;

        public AuditService(SqlConnection db)
        {
            _db = db;
        }

        private string Query(string actor)
        {
            var cmd = new SqlCommand("SELECT Action FROM Audit WHERE Actor = @actor", _db);
            cmd.Parameters.AddWithValue("@actor", actor);
            return cmd.ExecuteScalar()?.ToString();
        }
    }
}
''',
})

# 16 -- using alias for the repository namespace
_ALIAS_CTRL = '''using Microsoft.AspNetCore.Mvc;
using Repo = App.Persistence.Customers;

namespace App.Web
{
    [ApiController]
    [Route("api/[controller]")]
    public class CustomersController : ControllerBase
    {
        private readonly Repo.CustomerRepository _repo;

        public CustomersController(Repo.CustomerRepository repo)
        {
            _repo = repo;
        }

        [HttpGet]
        public IActionResult Get([FromQuery] string city)
        {
            return Ok(_repo.InCity(city));
        }
    }
}
'''
case("using_alias_namespace", {
    "Web/CustomersController.cs": _ALIAS_CTRL,
    "Persistence/CustomerRepository.cs": '''using System.Data.SqlClient;

namespace App.Persistence.Customers
{
    public class CustomerRepository
    {
        private readonly SqlConnection _db;

        public CustomerRepository(SqlConnection db)
        {
            _db = db;
        }

        public string InCity(string city)
        {
            var cmd = new SqlCommand($"SELECT Name FROM Customers WHERE City = '{city}'", _db);  // frame-expect: CWE-89
            return cmd.ExecuteScalar()?.ToString();
        }
    }
}
''',
}, {
    "Web/CustomersController.cs": _ALIAS_CTRL,
    "Persistence/CustomerRepository.cs": '''using System.Data.SqlClient;

namespace App.Persistence.Customers
{
    public class CustomerRepository
    {
        private readonly SqlConnection _db;

        public CustomerRepository(SqlConnection db)
        {
            _db = db;
        }

        public string InCity(string city)
        {
            var cmd = new SqlCommand("SELECT Name FROM Customers WHERE City = @city", _db);
            cmd.Parameters.AddWithValue("@city", city);
            return cmd.ExecuteScalar()?.ToString();
        }
    }
}
''',
})

# 17 -- static class with const SQL fragments, request data appended
_CONST_CTRL = _api("Reports", "using App.Reporting;\n", "ReportBuilder", "_svc.ByRegion(q)")
case("static_class_const_sql_fragments", {
    "Web/ReportsController.cs": _CONST_CTRL,
    "Reporting/SqlFragments.cs": '''namespace App.Reporting
{
    public static class SqlFragments
    {
        public const string Select = "SELECT Region, SUM(Amount) FROM Sales ";
        public const string Group = " GROUP BY Region";
    }
}
''',
    "Reporting/ReportBuilder.cs": '''using System.Data.SqlClient;

namespace App.Reporting
{
    public class ReportBuilder
    {
        private readonly SqlConnection _db;

        public ReportBuilder(SqlConnection db)
        {
            _db = db;
        }

        public string ByRegion(string region)
        {
            var sql = SqlFragments.Select + "WHERE Region = '" + region + "'" + SqlFragments.Group;
            var cmd = new SqlCommand(sql, _db);  // frame-expect: CWE-89
            return cmd.ExecuteScalar()?.ToString();
        }
    }
}
''',
}, {
    "Web/ReportsController.cs": _CONST_CTRL,
    "Reporting/SqlFragments.cs": '''namespace App.Reporting
{
    public static class SqlFragments
    {
        public const string Select = "SELECT Region, SUM(Amount) FROM Sales ";
        public const string Group = " GROUP BY Region";
    }
}
''',
    "Reporting/ReportBuilder.cs": '''using System.Data.SqlClient;

namespace App.Reporting
{
    public class ReportBuilder
    {
        private readonly SqlConnection _db;

        public ReportBuilder(SqlConnection db)
        {
            _db = db;
        }

        public string ByRegion(string region)
        {
            var sql = SqlFragments.Select + "WHERE Region = @region" + SqlFragments.Group;
            var cmd = new SqlCommand(sql, _db);
            cmd.Parameters.AddWithValue("@region", region);
            return cmd.ExecuteScalar()?.ToString();
        }
    }
}
''',
})

# 18 -- async/await chain over three files
_ASYNC_CTRL = '''using System.Threading.Tasks;
using App.Services;
using Microsoft.AspNetCore.Mvc;

namespace App.Web
{
    [ApiController]
    [Route("api/[controller]")]
    public class InvoicesController : ControllerBase
    {
        private readonly InvoiceService _svc;

        public InvoicesController(InvoiceService svc)
        {
            _svc = svc;
        }

        [HttpGet]
        public async Task<IActionResult> Get([FromQuery] string number)
        {
            return Ok(await _svc.LoadAsync(number));
        }
    }
}
'''
_ASYNC_SVC = '''using System.Threading.Tasks;
using App.Data;

namespace App.Services
{
    public class InvoiceService
    {
        private readonly InvoiceRepository _repo;

        public InvoiceService(InvoiceRepository repo)
        {
            _repo = repo;
        }

        public async Task<string> LoadAsync(string number)
        {
            var found = await _repo.FindAsync(number.ToUpperInvariant());
            return found ?? "none";
        }
    }
}
'''
case("async_await_chain", {
    "Web/InvoicesController.cs": _ASYNC_CTRL,
    "Services/InvoiceService.cs": _ASYNC_SVC,
    "Data/InvoiceRepository.cs": '''using System.Data.SqlClient;
using System.Threading.Tasks;

namespace App.Data
{
    public class InvoiceRepository
    {
        private readonly SqlConnection _db;

        public InvoiceRepository(SqlConnection db)
        {
            _db = db;
        }

        public async Task<string> FindAsync(string number)
        {
            using var cmd = new SqlCommand("SELECT Customer FROM Invoices WHERE Number = '" + number + "'", _db);  // frame-expect: CWE-89
            var result = await cmd.ExecuteScalarAsync();
            return result?.ToString();
        }
    }
}
''',
}, {
    "Web/InvoicesController.cs": _ASYNC_CTRL,
    "Services/InvoiceService.cs": _ASYNC_SVC,
    "Data/InvoiceRepository.cs": '''using System.Data.SqlClient;
using System.Threading.Tasks;

namespace App.Data
{
    public class InvoiceRepository
    {
        private readonly SqlConnection _db;

        public InvoiceRepository(SqlConnection db)
        {
            _db = db;
        }

        public async Task<string> FindAsync(string number)
        {
            using var cmd = new SqlCommand("SELECT Customer FROM Invoices WHERE Number = @number", _db);
            cmd.Parameters.AddWithValue("@number", number);
            var result = await cmd.ExecuteScalarAsync();
            return result?.ToString();
        }
    }
}
''',
})

# 19 -- inherited helper: the action calls a protected method of its abstract base controller (other file)
_BASE_CTRL_CS = '''using System.Data.SqlClient;
using Microsoft.AspNetCore.Mvc;

namespace App.Web
{
    public abstract class ApiControllerBase : ControllerBase
    {
        protected readonly SqlConnection Db;

        protected ApiControllerBase(SqlConnection db)
        {
            Db = db;
        }

        protected string Lookup(string table, string key)
        {
%s
            return cmd.ExecuteScalar()?.ToString();
        }
    }
}
'''
_NOTES_CTRL = '''using System.Data.SqlClient;
using Microsoft.AspNetCore.Mvc;

namespace App.Web
{
    [ApiController]
    [Route("api/[controller]")]
    public class NotesController : ApiControllerBase
    {
        public NotesController(SqlConnection db) : base(db)
        {
        }

        [HttpGet]
        public IActionResult Get([FromQuery] string key)
        {
            return Ok(Lookup("Notes", key));
        }
    }
}
'''
case("inherited_base_controller_helper", {
    "Web/ApiControllerBase.cs": _BASE_CTRL_CS % '            var cmd = new SqlCommand("SELECT Body FROM " + table + " WHERE Id = \'" + key + "\'", Db);  // frame-expect: CWE-89',
    "Web/NotesController.cs": _NOTES_CTRL,
}, {
    "Web/ApiControllerBase.cs": _BASE_CTRL_CS % '''            if (table != "Notes" && table != "Tags") throw new System.ArgumentException(table);
            var cmd = new SqlCommand("SELECT Body FROM " + table + " WHERE Id = @id", Db);
            cmd.Parameters.AddWithValue("@id", key);''',
    "Web/NotesController.cs": _NOTES_CTRL,
})

# 20 -- [FromQuery] model class; the property getter carries the request value
_MODEL_CTRL = '''using App.Data;
using Microsoft.AspNetCore.Mvc;

namespace App.Web
{
    public class UserFilter
    {
        public string Name { get; set; }
        public int Page { get; set; }
    }

    [ApiController]
    [Route("api/[controller]")]
    public class UsersController : ControllerBase
    {
        private readonly UserQueries _queries;

        public UsersController(UserQueries queries)
        {
            _queries = queries;
        }

        [HttpGet]
        public IActionResult Get([FromQuery] UserFilter filter)
        {
            return Ok(_queries.ByName(filter.Name));
        }
    }
}
'''
case("fromquery_model_property", {
    "Web/UsersController.cs": _MODEL_CTRL,
    "Data/UserQueries.cs": '''using System.Data.SqlClient;

namespace App.Data
{
    public class UserQueries
    {
        private readonly SqlConnection _db;

        public UserQueries(SqlConnection db)
        {
            _db = db;
        }

        public string ByName(string name)
        {
            using (var cmd = new SqlCommand("SELECT Email FROM Users WHERE Name LIKE '" + name + "%'", _db))  // frame-expect: CWE-89
            {
                return cmd.ExecuteScalar()?.ToString();
            }
        }
    }
}
''',
}, {
    "Web/UsersController.cs": _MODEL_CTRL,
    "Data/UserQueries.cs": '''using System.Data.SqlClient;

namespace App.Data
{
    public class UserQueries
    {
        private readonly SqlConnection _db;

        public UserQueries(SqlConnection db)
        {
            _db = db;
        }

        public string ByName(string name)
        {
            using (var cmd = new SqlCommand("SELECT Email FROM Users WHERE Name LIKE @name", _db))
            {
                cmd.Parameters.AddWithValue("@name", name + "%");
                return cmd.ExecuteScalar()?.ToString();
            }
        }
    }
}
''',
})

# 21 -- try / catch / finally around the sink
_TRY_CTRL = _api("Archive", "using App.Tools;\n", "Archiver", "_svc.Pack(q)")
case("try_catch_finally_around_sink", {
    "Web/ArchiveController.cs": _TRY_CTRL,
    "Tools/Archiver.cs": '''using System;
using System.Diagnostics;

namespace App.Tools
{
    public class Archiver
    {
        public string Pack(string dir)
        {
            try
            {
                var p = Process.Start("tar", "czf out.tgz " + dir);  // frame-expect: CWE-78
                p.WaitForExit();
                return "ok";
            }
            catch (Exception ex)
            {
                return "failed: " + ex.Message;
            }
            finally
            {
                GC.Collect();
            }
        }
    }
}
''',
}, {
    "Web/ArchiveController.cs": _TRY_CTRL,
    "Tools/Archiver.cs": '''using System;
using System.Diagnostics;

namespace App.Tools
{
    public class Archiver
    {
        public string Pack(string dir)
        {
            try
            {
                var psi = new ProcessStartInfo("tar");
                psi.ArgumentList.Add("czf");
                psi.ArgumentList.Add("out.tgz");
                psi.ArgumentList.Add("--");
                psi.ArgumentList.Add(dir);
                var p = Process.Start(psi);
                p.WaitForExit();
                return "ok";
            }
            catch (Exception ex)
            {
                return "failed: " + ex.Message;
            }
            finally
            {
                GC.Collect();
            }
        }
    }
}
''',
})

# 22 -- LDAP filter
_LDAP_CTRL = _api("Directory", "using App.Ldap;\n", "DirectoryClient", "_svc.FindUser(q)")
case("directorysearcher_filter", {
    "Web/DirectoryController.cs": _LDAP_CTRL,
    "Ldap/DirectoryClient.cs": '''using System.DirectoryServices;

namespace App.Ldap
{
    public class DirectoryClient
    {
        public string FindUser(string uid)
        {
            var searcher = new DirectorySearcher(new DirectoryEntry("LDAP://acme.local"));
            searcher.Filter = "(uid=" + uid + ")";  // frame-expect: CWE-90
            var found = searcher.FindOne();
            return found?.Path;
        }
    }
}
''',
}, {
    "Web/DirectoryController.cs": _LDAP_CTRL,
    "Ldap/DirectoryClient.cs": '''using System.DirectoryServices;
using System.Text.RegularExpressions;

namespace App.Ldap
{
    public class DirectoryClient
    {
        public string FindUser(string uid)
        {
            if (!Regex.IsMatch(uid, "^[a-z0-9]{1,16}$")) return null;
            var searcher = new DirectorySearcher(new DirectoryEntry("LDAP://acme.local"));
            searcher.Filter = "(uid=" + uid + ")";
            var found = searcher.FindOne();
            return found?.Path;
        }
    }
}
''',
})

# 23 -- XPath
_XP_CTRL = _api("Catalog", "using App.Xml;\n", "CatalogReader", "_svc.PriceOf(q)")
case("xpath_selectsinglenode", {
    "Web/CatalogController.cs": _XP_CTRL,
    "Xml/CatalogReader.cs": '''using System.Xml;

namespace App.Xml
{
    public class CatalogReader
    {
        private readonly XmlDocument _doc;

        public CatalogReader(XmlDocument doc)
        {
            _doc = doc;
        }

        public string PriceOf(string sku)
        {
            var node = _doc.SelectSingleNode("//item[@sku='" + sku + "']/price");  // frame-expect: CWE-643
            return node?.InnerText;
        }
    }
}
''',
}, {
    "Web/CatalogController.cs": _XP_CTRL,
    "Xml/CatalogReader.cs": '''using System.Xml;

namespace App.Xml
{
    public class CatalogReader
    {
        private readonly XmlDocument _doc;

        public CatalogReader(XmlDocument doc)
        {
            _doc = doc;
        }

        public string PriceOf(string sku)
        {
            if (!System.Text.RegularExpressions.Regex.IsMatch(sku, "^[A-Z0-9-]{1,16}$")) return null;
            var node = _doc.SelectSingleNode("//item[@sku='" + sku + "']/price");
            return node?.InnerText;
        }
    }
}
''',
})

# 24 -- lambda: Task.Run captures the request value
_TASK_CTRL = _api("Jobs", "using App.Jobs;\n", "JobRunner", "_svc.Start(q)")
case("task_run_lambda_captures_value", {
    "Web/JobsController.cs": _TASK_CTRL,
    "Jobs/JobRunner.cs": '''using System.Diagnostics;
using System.Threading.Tasks;

namespace App.Jobs
{
    public class JobRunner
    {
        public string Start(string script)
        {
            Task.Run(() =>
            {
                Process.Start("/bin/sh", "-c " + script);  // frame-expect: CWE-78
            });
            return "started";
        }
    }
}
''',
}, {
    "Web/JobsController.cs": _TASK_CTRL,
    "Jobs/JobRunner.cs": '''using System.Diagnostics;
using System.Threading.Tasks;

namespace App.Jobs
{
    public class JobRunner
    {
        public string Start(string script)
        {
            Task.Run(() =>
            {
                var psi = new ProcessStartInfo("/usr/local/bin/run-job");
                psi.ArgumentList.Add(script);
                Process.Start(psi);
            });
            return "started";
        }
    }
}
''',
})

# 25 -- LINQ / string.Join over a list of request values built into SQL
_LINQ_CTRL = _api("Batch", "using App.Data;\n", "BatchRepository", "_svc.DeleteMany(q.Split(','))")
case("linq_join_ids_into_sql", {
    "Web/BatchController.cs": _LINQ_CTRL,
    "Data/BatchRepository.cs": '''using System.Data.SqlClient;
using System.Linq;

namespace App.Data
{
    public class BatchRepository
    {
        private readonly SqlConnection _db;

        public BatchRepository(SqlConnection db)
        {
            _db = db;
        }

        public int DeleteMany(string[] ids)
        {
            var list = string.Join(",", ids.Select(i => i.Trim()));
            var cmd = new SqlCommand("DELETE FROM Items WHERE Id IN (" + list + ")", _db);  // frame-expect: CWE-89
            return cmd.ExecuteNonQuery();
        }
    }
}
''',
}, {
    "Web/BatchController.cs": _LINQ_CTRL,
    "Data/BatchRepository.cs": '''using System.Data.SqlClient;
using System.Linq;

namespace App.Data
{
    public class BatchRepository
    {
        private readonly SqlConnection _db;

        public BatchRepository(SqlConnection db)
        {
            _db = db;
        }

        public int DeleteMany(string[] ids)
        {
            var deleted = 0;
            foreach (var id in ids.Select(i => i.Trim()))
            {
                var cmd = new SqlCommand("DELETE FROM Items WHERE Id = @id", _db);
                cmd.Parameters.AddWithValue("@id", id);
                deleted += cmd.ExecuteNonQuery();
            }
            return deleted;
        }
    }
}
''',
})

# 26 -- DI registration in Startup, interface with one implementation, ExecuteSqlRaw
_DI_CTRL = '''using App.Core;
using Microsoft.AspNetCore.Mvc;

namespace App.Web
{
    [ApiController]
    [Route("api/[controller]")]
    public class TagsController : ControllerBase
    {
        private readonly ITagService _tags;

        public TagsController(ITagService tags)
        {
            _tags = tags;
        }

        [HttpDelete]
        public IActionResult Delete([FromQuery] string name)
        {
            _tags.Remove(name);
            return NoContent();
        }
    }
}
'''
_DI_STARTUP = '''using App.Core;
using Microsoft.Extensions.DependencyInjection;

namespace App
{
    public class Startup
    {
        public void ConfigureServices(IServiceCollection services)
        {
            services.AddScoped<ITagService, TagService>();
            services.AddControllers();
        }
    }
}
'''
_DI_IFACE = '''namespace App.Core
{
    public interface ITagService
    {
        void Remove(string name);
    }
}
'''
case("di_registration_executesqlraw", {
    "Web/TagsController.cs": _DI_CTRL,
    "Startup.cs": _DI_STARTUP,
    "Core/ITagService.cs": _DI_IFACE,
    "Core/TagService.cs": '''using Microsoft.EntityFrameworkCore;

namespace App.Core
{
    public class TagService : ITagService
    {
        private readonly AppDbContext _ctx;

        public TagService(AppDbContext ctx)
        {
            _ctx = ctx;
        }

        public void Remove(string name)
        {
            _ctx.Database.ExecuteSqlRaw("DELETE FROM Tags WHERE Name = '" + name + "'");  // frame-expect: CWE-89
        }
    }
}
''',
}, {
    "Web/TagsController.cs": _DI_CTRL,
    "Startup.cs": _DI_STARTUP,
    "Core/ITagService.cs": _DI_IFACE,
    "Core/TagService.cs": '''using Microsoft.EntityFrameworkCore;

namespace App.Core
{
    public class TagService : ITagService
    {
        private readonly AppDbContext _ctx;

        public TagService(AppDbContext ctx)
        {
            _ctx = ctx;
        }

        public void Remove(string name)
        {
            _ctx.Database.ExecuteSqlInterpolated($"DELETE FROM Tags WHERE Name = {name}");
        }
    }
}
''',
})

# 27 -- generic base service with a type constraint
_GBASE_CTRL = _api("Sensors", "using App.Core;\n", "SensorService", "_svc.Latest(q)")
_GBASE = '''namespace App.Core
{
    public interface IEntity
    {
        string Table { get; }
    }

    public class Sensor : IEntity
    {
        public string Table => "Sensors";
    }

    public abstract class ReadingService<T> where T : IEntity, new()
    {
        protected abstract string Fetch(string table, string id);

        public string Latest(string id)
        {
            return Fetch(new T().Table, id);
        }
    }
}
'''
case("generic_base_service_constraint", {
    "Web/SensorsController.cs": _GBASE_CTRL,
    "Core/ReadingService.cs": _GBASE,
    "Core/SensorService.cs": '''using System.Data.SqlClient;

namespace App.Core
{
    public class SensorService : ReadingService<Sensor>
    {
        private readonly SqlConnection _db;

        public SensorService(SqlConnection db)
        {
            _db = db;
        }

        protected override string Fetch(string table, string id)
        {
            var cmd = new SqlCommand("SELECT TOP 1 Value FROM " + table + " WHERE Sensor = '" + id + "'", _db);  // frame-expect: CWE-89
            return cmd.ExecuteScalar()?.ToString();
        }
    }
}
''',
}, {
    "Web/SensorsController.cs": _GBASE_CTRL,
    "Core/ReadingService.cs": _GBASE,
    "Core/SensorService.cs": '''using System.Data.SqlClient;

namespace App.Core
{
    public class SensorService : ReadingService<Sensor>
    {
        private readonly SqlConnection _db;

        public SensorService(SqlConnection db)
        {
            _db = db;
        }

        protected override string Fetch(string table, string id)
        {
            var cmd = new SqlCommand("SELECT TOP 1 Value FROM " + table + " WHERE Sensor = @id", _db);
            cmd.Parameters.AddWithValue("@id", id);
            return cmd.ExecuteScalar()?.ToString();
        }
    }
}
''',
})

# 28 -- ReDoS: user-supplied pattern
_RX_CTRL = _api("Grep", "using App.Text;\n", "Searcher", "_svc.Matches(q)")
case("regex_from_request_pattern", {
    "Web/GrepController.cs": _RX_CTRL,
    "Text/Searcher.cs": '''using System.Text.RegularExpressions;

namespace App.Text
{
    public class Searcher
    {
        private const string Corpus = "alpha beta gamma";

        public bool Matches(string pattern)
        {
            return new Regex(pattern).IsMatch(Corpus);  // frame-expect: CWE-1333
        }
    }
}
''',
}, {
    "Web/GrepController.cs": _RX_CTRL,
    "Text/Searcher.cs": '''using System;
using System.Text.RegularExpressions;

namespace App.Text
{
    public class Searcher
    {
        private const string Corpus = "alpha beta gamma";

        public bool Matches(string pattern)
        {
            return new Regex(Regex.Escape(pattern), RegexOptions.None, TimeSpan.FromMilliseconds(50)).IsMatch(Corpus);
        }
    }
}
''',
})

# Known gaps -------------------------------------------------------------------------
gap("two_implementations_behind_interface", {
    "Web/TagsController.cs": _DI_CTRL,
    "Startup.cs": _DI_STARTUP,
    "Core/ITagService.cs": _DI_IFACE,
    "Core/TagService.cs": '''using Microsoft.EntityFrameworkCore;

namespace App.Core
{
    public class TagService : ITagService
    {
        private readonly AppDbContext _ctx;

        public TagService(AppDbContext ctx)
        {
            _ctx = ctx;
        }

        public void Remove(string name)
        {
            _ctx.Database.ExecuteSqlRaw("DELETE FROM Tags WHERE Name = '" + name + "'");  // frame-expect: CWE-89
        }
    }
}
''',
    "Core/AuditedTagService.cs": '''namespace App.Core
{
    public class AuditedTagService : ITagService
    {
        public void Remove(string name)
        {
        }
    }
}
''',
}, None)

gap("constructor_stores_request_value_in_field", {
    "Web/RunController.cs": _api("Run", "using App.Jobs;\n", "Job", "new Job(q).Go()", attrs="[HttpGet]").replace(
        "private readonly Job _svc;\n\n        public RunController(Job svc)\n        {\n            _svc = svc;\n        }\n", ""),
    "Jobs/Job.cs": '''using System.Diagnostics;

namespace App.Jobs
{
    public class Job
    {
        private readonly string _target;

        public Job(string target)
        {
            _target = target;
        }

        public string Go()
        {
            var p = Process.Start("backup", _target);  // frame-expect: CWE-78
            return p.Id.ToString();
        }
    }
}
''',
}, None)
