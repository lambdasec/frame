using System.Diagnostics;
using Microsoft.AspNetCore.Mvc;

namespace app {
    [ApiController]
    public class Api : ControllerBase {
        [HttpGet("ping")]
        public void Ping([FromQuery] string host) {
            Process.Start("ping", "-c 1 " + host);   // CWE-78: the request's host reaches a process
        }
    }
}
