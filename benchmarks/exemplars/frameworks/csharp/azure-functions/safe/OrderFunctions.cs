using System.Data.SqlClient;
using System.IO;
using System.Net;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Azure.WebJobs;
using Microsoft.Azure.WebJobs.Extensions.Http;
using Microsoft.Extensions.Logging;

namespace Orders.Functions
{
    public class OrderFunctions
    {
        private const string ConnectionString = "Server=tcp:orders.database.windows.net;Database=orders";

        [FunctionName("GetOrders")]
        public async Task<IActionResult> GetOrders(
            [HttpTrigger(AuthorizationLevel.Function, "get", Route = null)] HttpRequest req,
            ILogger log)
        {
            string customer = req.Query["customer"];
            using var conn = new SqlConnection(ConnectionString);
            await conn.OpenAsync();
            var cmd = new SqlCommand("SELECT * FROM Orders WHERE Customer = @customer", conn);
            cmd.Parameters.AddWithValue("@customer", customer);
            var reader = await cmd.ExecuteReaderAsync();
            return new OkObjectResult(reader.HasRows);
        }

        [FunctionName("Receipt")]
        public async Task<IActionResult> Receipt(
            [HttpTrigger(AuthorizationLevel.Anonymous, "get", Route = "receipt/{name}")] HttpRequest req,
            string name,
            ILogger log)
        {
            var text = File.ReadAllText("/home/site/receipts/" + Path.GetFileName(name));
            return new ContentResult { Content = text, ContentType = "text/plain" };
        }

        [FunctionName("Greeting")]
        public static IActionResult Greeting(
            [HttpTrigger(AuthorizationLevel.Anonymous, "get")] HttpRequest req)
        {
            string who = req.Query["name"];
            return new ContentResult { Content = "<h1>Hello " + WebUtility.HtmlEncode(who) + "</h1>", ContentType = "text/html" };
        }

        [FunctionName("Bounce")]
        public static IActionResult Bounce(
            [HttpTrigger(AuthorizationLevel.Anonymous, "get")] HttpRequest req)
        {
            string target = req.Query["to"];
            if (!target.StartsWith("/") || target.StartsWith("//"))
            {
                return new BadRequestResult();
            }
            return new LocalRedirectResult(target);
        }
    }
}
