using System.Data.SqlClient;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Routing;

namespace Shop.Endpoints
{
    public static class OrderEndpoints
    {
        public static void MapOrderEndpoints(this IEndpointRouteBuilder app)
        {
            var group = app.MapGroup("/orders").RequireAuthorization();
            group.MapGet("/", ListOrders);
            group.MapPost("/note", ([FromBody] NoteDto note, ILogger<NoteDto> logger) =>
            {
                var cmd = new SqlCommand("INSERT INTO Notes (Body) VALUES ('" + note.Body + "')"); // frame-expect: CWE-89
                cmd.ExecuteNonQuery();
                return Results.Created("/orders/note", note);
            });
        }

        private static IResult ListOrders(string customer, IOrderService orders)
        {
            var cmd = new SqlCommand("SELECT * FROM Orders WHERE Customer = '" + customer + "'"); // frame-expect: CWE-89
            return Results.Ok(cmd.ExecuteReader().HasRows);
        }
    }

    public record NoteDto(string Body);
}
