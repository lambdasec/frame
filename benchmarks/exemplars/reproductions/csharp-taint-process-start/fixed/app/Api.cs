using System.Collections.Generic;
using System.Diagnostics;
using Microsoft.AspNetCore.Mvc;

namespace app {
    [ApiController]
    public class Api : ControllerBase {
        static readonly HashSet<string> Allowed = new HashSet<string> { "example.com", "example.org" };

        [HttpGet("ping")]
        public void Ping([FromQuery] string host) {
            if (!Allowed.Contains(host)) {
                return;                                // fixed: attacker data never reaches the process
            }
            Process.Start("ping", "-c 1 " + host);
        }
    }
}
