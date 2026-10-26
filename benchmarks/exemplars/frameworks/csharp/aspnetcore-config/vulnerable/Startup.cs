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
                options.AddPolicy("open", policy => policy.AllowAnyOrigin().AllowAnyHeader().AllowAnyMethod()); // frame-expect: CWE-942
            });
            services.AddHttpClient("partner").ConfigurePrimaryHttpMessageHandler(() => new HttpClientHandler
            {
                ServerCertificateCustomValidationCallback = (message, cert, chain, errors) => true // frame-expect: CWE-295
            });
        }

        public void Configure(IApplicationBuilder app)
        {
            app.Use(async (context, next) =>
            {
                context.Response.Cookies.Append("session", Guid.NewGuid().ToString(), new CookieOptions { HttpOnly = false, Secure = false }); // frame-expect: CWE-1004, CWE-614
                await next();
            });
        }

        public static string HashPassword(string password)
        {
            using var md5 = MD5.Create(); // frame-expect: CWE-328
            return Convert.ToHexString(md5.ComputeHash(Encoding.UTF8.GetBytes(password)));
        }

        public static byte[] Encrypt(byte[] data, byte[] key)
        {
            using var des = DES.Create(); // frame-expect: CWE-327
            des.Key = key;
            return des.CreateEncryptor().TransformFinalBlock(data, 0, data.Length);
        }
    }
}
