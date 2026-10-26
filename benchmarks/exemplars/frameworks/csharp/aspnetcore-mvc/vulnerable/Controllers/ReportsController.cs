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
            var sql = "SELECT * FROM Orders WHERE Customer LIKE '%" + term + "%'";
            var rows = _db.Orders.FromSqlRaw(sql).ToList(); // frame-expect: CWE-89
            return Ok(rows);
        }

        [HttpGet("by-status/{status}")]
        public IActionResult ByStatus(string status)
        {
            var rows = _db.Orders.FromSqlRaw($"SELECT * FROM Orders WHERE Status = '{status}'").ToList(); // frame-expect: CWE-89
            return Ok(rows);
        }

        [HttpPost("purge")]
        public IActionResult Purge([FromBody] string customer)
        {
            _db.Database.ExecuteSqlRaw("DELETE FROM Orders WHERE Customer = '" + customer + "'"); // frame-expect: CWE-89
            return NoContent();
        }

        [HttpGet("download")]
        public IActionResult Download([FromQuery] string name)
        {
            var path = Path.Combine(_reportDir, name);
            return PhysicalFile(path, "application/pdf"); // frame-expect: CWE-22
        }

        [HttpGet("preview")]
        public IActionResult Preview([FromQuery] string title)
        {
            return Content("<h1>" + title + "</h1>", "text/html"); // frame-expect: CWE-79
        }

        [HttpGet("go")]
        public IActionResult Go([FromQuery] string returnUrl)
        {
            return Redirect(returnUrl); // frame-expect: CWE-601
        }

        [HttpGet("lookup")]
        public IActionResult Lookup()
        {
            var sku = HttpContext.Request.Query["sku"].ToString();
            var rows = _db.Orders.FromSqlRaw("SELECT * FROM Orders WHERE Sku = '" + sku + "'").ToList(); // frame-expect: CWE-89
            return Ok(rows);
        }
    }
}
