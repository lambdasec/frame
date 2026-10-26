using System.Data.SqlClient;
using System.IO;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.Extensions.Configuration;

namespace Portal.Pages
{
    public class SearchModel : PageModel
    {
        private readonly IConfiguration _config;

        [BindProperty(SupportsGet = true)]
        public string Term { get; set; }

        [BindProperty]
        public string ReturnUrl { get; set; }

        public SearchModel(IConfiguration config)
        {
            _config = config;
        }

        public void OnGet()
        {
            using var conn = new SqlConnection(_config.GetConnectionString("Default"));
            conn.Open();
            var cmd = new SqlCommand("SELECT Title FROM Articles WHERE Title LIKE '%" + Term + "%'", conn); // frame-expect: CWE-89
            using var reader = cmd.ExecuteReader();
        }

        public IActionResult OnPostLogin()
        {
            return Redirect(ReturnUrl); // frame-expect: CWE-601
        }

        public IActionResult OnGetExport(string file)
        {
            var bytes = System.IO.File.ReadAllBytes(Path.Combine("exports", file)); // frame-expect: CWE-22
            return File(bytes, "application/octet-stream");
        }

        public IActionResult OnGetPreview(string html)
        {
            return Content("<div>" + html + "</div>", "text/html"); // frame-expect: CWE-79
        }
    }
}
