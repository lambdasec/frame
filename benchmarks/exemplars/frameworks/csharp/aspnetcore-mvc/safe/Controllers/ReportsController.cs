using System;
using System.IO;
using System.Linq;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Shop.Data;

namespace Shop.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class ReportsController : ControllerBase
    {
        private readonly ShopContext _db;
        private readonly string _reportDir = "/var/shop/reports";

        public ReportsController(ShopContext db)
        {
            _db = db;
        }

        [HttpGet("search")]
        public IActionResult Search([FromQuery] string term)
        {
            var rows = _db.Orders.FromSqlInterpolated($"SELECT * FROM Orders WHERE Customer LIKE {"%" + term + "%"}").ToList();
            return Ok(rows);
        }

        [HttpGet("by-status/{status}")]
        public IActionResult ByStatus(string status)
        {
            var rows = _db.Orders.FromSqlInterpolated($"SELECT * FROM Orders WHERE Status = {status}").ToList();
            return Ok(rows);
        }

        [HttpPost("purge")]
        public IActionResult Purge([FromBody] string customer)
        {
            _db.Database.ExecuteSqlInterpolated($"DELETE FROM Orders WHERE Customer = {customer}");
            return NoContent();
        }

        [HttpGet("download")]
        public IActionResult Download([FromQuery] string name)
        {
            var path = Path.GetFullPath(Path.Combine(_reportDir, Path.GetFileName(name)));
            return PhysicalFile(path, "application/pdf");
        }

        [HttpGet("preview")]
        public IActionResult Preview([FromQuery] string title)
        {
            return Content("<h1>" + System.Net.WebUtility.HtmlEncode(title) + "</h1>", "text/html");
        }

        [HttpGet("go")]
        public IActionResult Go([FromQuery] string returnUrl)
        {
            if (Url.IsLocalUrl(returnUrl))
            {
                return Redirect(returnUrl);
            }
            return RedirectToAction("Index", "Home");
        }

        [HttpGet("lookup")]
        public IActionResult Lookup()
        {
            var sku = HttpContext.Request.Query["sku"].ToString();
            var rows = _db.Orders.FromSqlRaw("SELECT * FROM Orders WHERE Sku = {0}", sku).ToList();
            return Ok(rows);
        }
    }
}
