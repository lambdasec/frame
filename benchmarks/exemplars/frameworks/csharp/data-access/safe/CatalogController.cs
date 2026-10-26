using System.Collections.Generic;
using System.Data;
using System.Linq;
using Dapper;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Npgsql;

namespace Catalog.Controllers
{
    [ApiController]
    [Route("catalog")]
    public class CatalogController : ControllerBase
    {
        private readonly IDbConnection _db;
        private readonly CatalogContext _ctx;

        public CatalogController(IDbConnection db, CatalogContext ctx)
        {
            _db = db;
            _ctx = ctx;
        }

        [HttpGet("dapper")]
        public IActionResult ByName([FromQuery] string name)
        {
            var rows = _db.Query<Product>("SELECT * FROM Products WHERE Name = @name", new { name }).ToList();
            return Ok(rows);
        }

        [HttpGet("dapper-interp")]
        public IActionResult ByCategory([FromQuery] string category)
        {
            var row = _db.QueryFirstOrDefault<Product>("SELECT * FROM Products WHERE Category = @category", new { category });
            return Ok(row);
        }

        [HttpDelete("dapper")]
        public IActionResult Remove([FromQuery] string sku)
        {
            _db.Execute("DELETE FROM Products WHERE Sku = @sku", new { sku });
            return NoContent();
        }

        [HttpGet("ef")]
        public IActionResult Ef([FromQuery] string brand)
        {
            var rows = _ctx.Products.FromSqlRaw("SELECT * FROM Products WHERE Brand = {0}", brand).ToList();
            return Ok(rows);
        }

        [HttpGet("ef-interp")]
        public IActionResult EfInterp([FromQuery] string brand)
        {
            var rows = _ctx.Products.FromSqlInterpolated($"SELECT * FROM Products WHERE Brand = {brand}").ToList();
            return Ok(rows);
        }

        [HttpGet("ef-raw")]
        public IActionResult EfRaw([FromQuery] string model)
        {
            var rows = _ctx.Database.SqlQuery<Product>($"SELECT * FROM Products WHERE Model = {model}").ToList();
            return Ok(rows);
        }

        [HttpGet("npgsql")]
        public IActionResult Pg([FromQuery] string tag)
        {
            using var conn = new NpgsqlConnection("Host=db;Database=catalog");
            conn.Open();
            using var cmd = new NpgsqlCommand("SELECT * FROM tags WHERE tag = @tag", conn);
            cmd.Parameters.AddWithValue("tag", tag);
            using var reader = cmd.ExecuteReader();
            return Ok(reader.HasRows);
        }
    }
}
