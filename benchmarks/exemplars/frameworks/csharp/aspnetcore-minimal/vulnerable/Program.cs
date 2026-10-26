using System.Diagnostics;
using System.Data.SqlClient;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;

var builder = WebApplication.CreateBuilder(args);
var app = builder.Build();
var connectionString = builder.Configuration.GetConnectionString("Default");

app.MapGet("/ping", (string host) =>
{
    var psi = new ProcessStartInfo("ping", "-c 1 " + host); // frame-expect: CWE-78
    Process.Start(psi);
    return Results.Ok();
});

app.MapGet("/users", (string name) =>
{
    using var conn = new SqlConnection(connectionString);
    conn.Open();
    var cmd = new SqlCommand("SELECT * FROM Users WHERE Name = '" + name + "'", conn); // frame-expect: CWE-89
    var reader = cmd.ExecuteReader();
    return Results.Ok(reader.HasRows);
});

app.MapGet("/file", (string path) =>
{
    var text = System.IO.File.ReadAllText("/srv/data/" + path); // frame-expect: CWE-22
    return Results.Text(text);
});

app.MapPost("/notes", async (HttpRequest request) =>
{
    var title = request.Query["title"];
    var html = "<h2>" + title + "</h2>";
    return Results.Content(html, "text/html"); // frame-expect: CWE-79
});

app.MapGet("/out", (string next) => Results.Redirect(next)); // frame-expect: CWE-601

app.Run();
