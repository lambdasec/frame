using System;

// Stand-ins for the ASP.NET Core MVC types the controller uses, so the case
// builds as a plain test project with no web framework package.
namespace Microsoft.AspNetCore.Mvc {
    public abstract class ControllerBase { }

    [AttributeUsage(AttributeTargets.Class)]
    public sealed class ApiControllerAttribute : Attribute { }

    [AttributeUsage(AttributeTargets.Method)]
    public sealed class HttpGetAttribute : Attribute {
        public HttpGetAttribute(string template) { }
    }

    [AttributeUsage(AttributeTargets.Parameter)]
    public sealed class FromQueryAttribute : Attribute { }
}
