using System.Diagnostics;
using System.Data.SqlClient;
using System.Net;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;

var builder = WebApplication.CreateBuilder(args);
var app = builder.Build();
var connectionString = builder.Configuration.GetConnectionString("Default");

app.MapGet("/ping", (string host) =>
{
    var psi = new ProcessStartInfo("ping");
    psi.ArgumentList.Add("-c");
    psi.ArgumentList.Add("1");
    if (!System.Net.IPAddress.TryParse(host, out var ip))
    {
        return Results.BadRequest();
    }
    psi.ArgumentList.Add(ip.ToString());
    Process.Start(psi);
    return Results.Ok();
});

app.MapGet("/users", (string name) =>
{
    using var conn = new SqlConnection(connectionString);
    conn.Open();
    var cmd = new SqlCommand("SELECT * FROM Users WHERE Name = @name", conn);
    cmd.Parameters.AddWithValue("@name", name);
    var reader = cmd.ExecuteReader();
    return Results.Ok(reader.HasRows);
});

app.MapGet("/file", (string path) =>
{
    var text = System.IO.File.ReadAllText("/srv/data/" + System.IO.Path.GetFileName(path));
    return Results.Text(text);
});

app.MapPost("/notes", async (HttpRequest request) =>
{
    var title = request.Query["title"];
    var html = "<h2>" + WebUtility.HtmlEncode(title) + "</h2>";
    return Results.Content(html, "text/html");
});

app.MapGet("/out", (string next) =>
{
    if (!next.StartsWith("/") || next.StartsWith("//"))
    {
        return Results.BadRequest();
    }
    return Results.LocalRedirect(next);
});

app.Run();
