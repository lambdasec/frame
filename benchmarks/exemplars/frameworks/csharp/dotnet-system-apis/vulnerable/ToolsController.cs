using System;
using System.DirectoryServices;
using System.Diagnostics;
using System.IO;
using System.IO.Compression;
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
        private readonly HttpClient _http;

        public ToolsController(HttpClient http)
        {
            _http = http;
        }

        [HttpGet("fetch")]
        public async Task<IActionResult> Fetch([FromQuery] string url)
        {
            var body = await _http.GetStringAsync(url); // frame-expect: CWE-918
            return Content(body, "text/plain");
        }

        [HttpGet("webclient")]
        public IActionResult Proxy([FromQuery] string target)
        {
            using var client = new WebClient();
            var data = client.DownloadString(target); // frame-expect: CWE-918
            return Ok(data);
        }

        [HttpGet("webrequest")]
        public IActionResult Probe([FromQuery] string address)
        {
            var request = WebRequest.Create(address); // frame-expect: CWE-918
            using var response = request.GetResponse();
            return Ok(((HttpWebResponse)response).StatusCode);
        }

        [HttpGet("log")]
        public async Task<IActionResult> Log([FromQuery] string name)
        {
            var text = await System.IO.File.ReadAllTextAsync("/var/log/ops/" + name); // frame-expect: CWE-22
            return Ok(text);
        }

        [HttpGet("grep")]
        public IActionResult Grep([FromQuery] string pattern, [FromQuery] string text)
        {
            var hit = Regex.IsMatch(text, pattern); // frame-expect: CWE-1333
            return Ok(hit);
        }

        [HttpGet("people")]
        public IActionResult People([FromQuery] string uid)
        {
            using var searcher = new DirectorySearcher(new DirectoryEntry("LDAP://corp.example.com"));
            searcher.Filter = "(&(objectClass=person)(uid=" + uid + "))"; // frame-expect: CWE-90
            var result = searcher.FindOne();
            return Ok(result?.Path);
        }

        [HttpGet("lookup")]
        public IActionResult Lookup([FromQuery] string host)
        {
            var info = new ProcessStartInfo { FileName = "nslookup", Arguments = host, RedirectStandardOutput = true }; // frame-expect: CWE-78
            using var proc = Process.Start(info);
            return Ok(proc.StandardOutput.ReadToEnd());
        }

        [HttpPost("upload")]
        public async Task<IActionResult> Upload(IFormFile file)
        {
            var target = Path.Combine("/srv/uploads", file.FileName);
            using var stream = System.IO.File.OpenWrite(target); // frame-expect: CWE-22
            await file.CopyToAsync(stream);
            return Ok();
        }

        [HttpPost("unzip")]
        public IActionResult Unzip([FromQuery] string archive)
        {
            ZipFile.ExtractToDirectory(archive, "/srv/imports"); // frame-expect: CWE-22
            return Ok();
        }
    }
}
