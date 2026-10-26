using System;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;

namespace Portal
{
    public class Startup
    {
        public void ConfigureServices(IServiceCollection services)
        {
            services.AddCors(options =>
            {
                options.AddPolicy("partners", policy => policy.WithOrigins("https://partner.example.com").AllowAnyHeader().WithMethods("GET"));
            });
            services.AddHttpClient("partner");
        }

        public void Configure(IApplicationBuilder app)
        {
            app.Use(async (context, next) =>
            {
                context.Response.Cookies.Append("session", Guid.NewGuid().ToString(), new CookieOptions { HttpOnly = true, Secure = true, SameSite = SameSiteMode.Strict });
                await next();
            });
        }

        public static string HashPassword(string password)
        {
            var salt = RandomNumberGenerator.GetBytes(16);
            var hash = Rfc2898DeriveBytes.Pbkdf2(password, salt, 600000, HashAlgorithmName.SHA256, 32);
            return Convert.ToBase64String(salt) + ":" + Convert.ToBase64String(hash);
        }

        public static byte[] Encrypt(byte[] data, byte[] key)
        {
            using var aes = Aes.Create();
            aes.Key = key;
            return aes.CreateEncryptor().TransformFinalBlock(data, 0, data.Length);
        }
    }
}
