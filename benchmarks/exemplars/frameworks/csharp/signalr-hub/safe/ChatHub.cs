using System;
using System.Data.SqlClient;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Threading.Tasks;
using Microsoft.AspNetCore.SignalR;
using Microsoft.Extensions.Configuration;

namespace Chat.Hubs
{
    public class ChatHub : Hub
    {
        private readonly IConfiguration _config;

        public ChatHub(IConfiguration config)
        {
            _config = config;
        }

        public override async Task OnConnectedAsync()
        {
            await Clients.Caller.SendAsync("welcome", Context.ConnectionId);
            await base.OnConnectedAsync();
        }

        public async Task SendMessage(string room, string text)
        {
            using var conn = new SqlConnection(_config.GetConnectionString("Chat"));
            conn.Open();
            var cmd = new SqlCommand("INSERT INTO Messages (Room, Body) VALUES (@room, @body)", conn);
            cmd.Parameters.AddWithValue("@room", room);
            cmd.Parameters.AddWithValue("@body", text);
            cmd.ExecuteNonQuery();
            await Clients.Group(room).SendAsync("message", text);
        }

        public async Task Upload(string fileName, byte[] data)
        {
            var target = Path.Combine("/var/chat/uploads", Path.GetFileName(fileName));
            await File.WriteAllBytesAsync(target, data);
        }

        public void Ping(string host)
        {
            if (!IPAddress.TryParse(host, out var ip))
            {
                return;
            }
            var psi = new ProcessStartInfo("ping");
            psi.ArgumentList.Add(ip.ToString());
            Process.Start(psi);
        }
    }
}
