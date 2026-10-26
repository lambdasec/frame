using System;
using System.DirectoryServices;
using System.Diagnostics;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace Ops.Controllers
{
    [ApiController]
    [Route("tools")]
    public class ToolsController : ControllerBase
    {
        private static readonly string[] AllowedHosts = { "api.example.com", "status.example.com" };
        private readonly HttpClient _http;

        public ToolsController(HttpClient http)
        {
            _http = http;
        }

        [HttpGet("fetch")]
        public async Task<IActionResult> Fetch([FromQuery] string url)
        {
            if (!Uri.TryCreate(url, UriKind.Absolute, out var uri) || !AllowedHosts.Contains(uri.Host))
            {
                return BadRequest();
            }
            var body = await _http.GetStringAsync(uri);
            return Content(body, "text/plain");
        }

        [HttpGet("webclient")]
        public IActionResult Proxy([FromQuery] string target)
        {
            using var client = new WebClient();
            var data = client.DownloadString("https://api.example.com/v1/" + Uri.EscapeDataString(target));
            return Ok(data);
        }

        [HttpGet("webrequest")]
        public IActionResult Probe([FromQuery] string address)
        {
            var request = WebRequest.Create("https://status.example.com/ping");
            using var response = request.GetResponse();
            return Ok(((HttpWebResponse)response).StatusCode);
        }

        [HttpGet("log")]
        public async Task<IActionResult> Log([FromQuery] string name)
        {
            var text = await System.IO.File.ReadAllTextAsync("/var/log/ops/" + Path.GetFileName(name));
            return Ok(text);
        }

        [HttpGet("grep")]
        public IActionResult Grep([FromQuery] string pattern, [FromQuery] string text)
        {
            var hit = Regex.IsMatch(text, Regex.Escape(pattern));
            return Ok(hit);
        }

        [HttpGet("people")]
        public IActionResult People([FromQuery] string uid)
        {
            using var searcher = new DirectorySearcher(new DirectoryEntry("LDAP://corp.example.com"));
            searcher.Filter = "(&(objectClass=person)(uid=" + System.Web.Security.AntiXss.AntiXssEncoder.LdapFilterEncode(uid) + "))";
            var result = searcher.FindOne();
            return Ok(result?.Path);
        }

        [HttpGet("lookup")]
        public IActionResult Lookup([FromQuery] string host)
        {
            if (!IPAddress.TryParse(host, out var ip))
            {
                return BadRequest();
            }
            var info = new ProcessStartInfo { FileName = "nslookup", RedirectStandardOutput = true };
            info.ArgumentList.Add(ip.ToString());
            using var proc = Process.Start(info);
            return Ok(proc.StandardOutput.ReadToEnd());
        }

        [HttpPost("upload")]
        public async Task<IActionResult> Upload(IFormFile file)
        {
            var target = Path.Combine("/srv/uploads", Path.GetFileName(file.FileName));
            using var stream = System.IO.File.OpenWrite(target);
            await file.CopyToAsync(stream);
            return Ok();
        }

        [HttpPost("unzip")]
        public IActionResult Unzip([FromQuery] string archive)
        {
            var path = Path.Combine("/srv/staging", Path.GetFileName(archive));
            ZipFile.ExtractToDirectory(path, "/srv/imports");
            return Ok();
        }
    }
}
