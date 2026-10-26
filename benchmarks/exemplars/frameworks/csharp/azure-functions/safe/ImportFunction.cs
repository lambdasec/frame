using System.Data.SqlClient;
using System.Net;
using System.Threading.Tasks;
using Microsoft.Azure.Functions.Worker;
using Microsoft.Azure.Functions.Worker.Http;

namespace Orders.Isolated
{
    public class ImportFunction
    {
        [Function("Import")]
        public async Task<HttpResponseData> Run(
            [HttpTrigger(AuthorizationLevel.Function, "post")] HttpRequestData req,
            FunctionContext context)
        {
            var body = await req.ReadAsStringAsync();
            using var conn = new SqlConnection("Server=tcp:orders.database.windows.net;Database=orders");
            conn.Open();
            var cmd = new SqlCommand("INSERT INTO Imports (Payload) VALUES (@payload)", conn);
            cmd.Parameters.AddWithValue("@payload", body);
            cmd.ExecuteNonQuery();
            return req.CreateResponse(HttpStatusCode.Accepted);
        }
    }
}
