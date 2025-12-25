"""
Library specifications for C# (.NET) programs.

This module defines ProcSpec for common C#/.NET APIs including:
- ASP.NET Core (web framework)
- Entity Framework (ORM)
- System.IO (file operations)
- System.Diagnostics (process execution)
- System.Net (networking)
- System.Data (ADO.NET)
"""

from typing import Dict
from frame.sil.procedure import ProcSpec


def _source(kind: str, desc: str = "") -> ProcSpec:
    """Create a taint source spec"""
    return ProcSpec(is_source=kind, description=desc)


def _sink(kind: str, args: list = None, desc: str = "") -> ProcSpec:
    """Create a taint sink spec"""
    return ProcSpec(is_sink=kind, sink_args=args or [0], description=desc)


def _sanitizer(kinds: list, desc: str = "") -> ProcSpec:
    """Create a sanitizer spec"""
    return ProcSpec(is_sanitizer=kinds, description=desc)


def _propagator(args: list, desc: str = "") -> ProcSpec:
    """Create a taint propagator spec"""
    return ProcSpec(taint_propagates=args, description=desc)


# =============================================================================
# ASP.NET Core - Taint Sources
# =============================================================================

ASPNET_SOURCE_SPECS = {
    # Request data (taint sources)
    "Request.Query": _source("user", "ASP.NET request query string"),
    "Request.Form": _source("user", "ASP.NET request form data"),
    "Request.Headers": _source("user", "ASP.NET request headers"),
    "Request.Cookies": _source("user", "ASP.NET request cookies"),
    "Request.Body": _source("user", "ASP.NET request body"),
    "Request.Path": _source("user", "ASP.NET request path"),
    "Request.QueryString": _source("user", "ASP.NET query string"),

    # Controller action parameters
    "[FromQuery]": _source("user", "ASP.NET FromQuery parameter"),
    "[FromBody]": _source("user", "ASP.NET FromBody parameter"),
    "[FromForm]": _source("user", "ASP.NET FromForm parameter"),
    "[FromHeader]": _source("user", "ASP.NET FromHeader parameter"),
    "[FromRoute]": _source("user", "ASP.NET FromRoute parameter"),

    # HttpContext
    "HttpContext.Request": _source("user", "HttpContext request"),
    "HttpContext.User": _source("user", "HttpContext user claims"),

    # MVC
    "ModelState": _propagator([0], "ASP.NET model state"),
    "ViewData": _propagator([0], "ASP.NET view data"),
    "TempData": _propagator([0], "ASP.NET temp data"),
}

# =============================================================================
# ASP.NET Core - Response Sinks
# =============================================================================

ASPNET_SINK_SPECS = {
    # Response (XSS sinks)
    "Response.WriteAsync": _sink("html", [0], "ASP.NET Response.WriteAsync (XSS)"),
    "Response.Write": _sink("html", [0], "ASP.NET Response.Write (XSS)"),
    "Content": _sink("html", [0], "ASP.NET Content() response (XSS)"),

    # Redirect (open redirect)
    "Redirect": _sink("redirect", [0], "ASP.NET Redirect (open redirect)"),
    "RedirectToAction": _sink("redirect", [0], "ASP.NET RedirectToAction"),
    "LocalRedirect": _propagator([0], "ASP.NET LocalRedirect (safe)"),

    # View (XSS if not using Razor encoding)
    "View": _propagator([0], "ASP.NET View()"),
    "PartialView": _propagator([0], "ASP.NET PartialView()"),
    "Html.Raw": _sink("html", [0], "ASP.NET Html.Raw (XSS)"),
}

# =============================================================================
# Entity Framework (ORM)
# =============================================================================

EF_SPECS = {
    # Raw SQL (SQL injection)
    "FromSqlRaw": _sink("sql", [0], "EF FromSqlRaw (SQL injection)"),
    "ExecuteSqlRaw": _sink("sql", [0], "EF ExecuteSqlRaw (SQL injection)"),
    "ExecuteSqlRawAsync": _sink("sql", [0], "EF ExecuteSqlRawAsync (SQL injection)"),

    # Interpolated SQL (safer but still track)
    "FromSqlInterpolated": _propagator([0], "EF FromSqlInterpolated (parameterized)"),
    "ExecuteSqlInterpolated": _propagator([0], "EF ExecuteSqlInterpolated (parameterized)"),

    # LINQ (generally safe)
    "Where": _propagator([0], "EF LINQ Where"),
    "Select": _propagator([0], "EF LINQ Select"),
    "FirstOrDefault": _propagator([0], "EF LINQ FirstOrDefault"),
    "SingleOrDefault": _propagator([0], "EF LINQ SingleOrDefault"),
    "ToList": _propagator([0], "EF LINQ ToList"),
    "ToListAsync": _propagator([0], "EF LINQ ToListAsync"),
}

# =============================================================================
# ADO.NET (Database)
# =============================================================================

ADONET_SPECS = {
    # Command (SQL injection)
    "SqlCommand": _sink("sql", [0], "SqlCommand (SQL injection)"),
    "ExecuteReader": _sink("sql", [0], "ExecuteReader (SQL injection)"),
    "ExecuteNonQuery": _sink("sql", [0], "ExecuteNonQuery (SQL injection)"),
    "ExecuteScalar": _sink("sql", [0], "ExecuteScalar (SQL injection)"),
    "ExecuteReaderAsync": _sink("sql", [0], "ExecuteReaderAsync (SQL injection)"),
    "ExecuteNonQueryAsync": _sink("sql", [0], "ExecuteNonQueryAsync (SQL injection)"),

    # Command text assignment
    "CommandText": _sink("sql", [0], "CommandText assignment (SQL injection)"),

    # Parameters (sanitizers)
    "Parameters.Add": _sanitizer(["sql"], "SqlParameter.Add (parameterized)"),
    "Parameters.AddWithValue": _sanitizer(["sql"], "AddWithValue (parameterized)"),
    "SqlParameter": _sanitizer(["sql"], "SqlParameter (parameterized)"),
}

# =============================================================================
# System.IO (File Operations)
# =============================================================================

IO_SPECS = {
    # File operations (path traversal)
    "File.ReadAllText": _sink("path", [0], "File.ReadAllText (path traversal)"),
    "File.ReadAllTextAsync": _sink("path", [0], "File.ReadAllTextAsync (path traversal)"),
    "File.ReadAllBytes": _sink("path", [0], "File.ReadAllBytes (path traversal)"),
    "File.ReadAllLines": _sink("path", [0], "File.ReadAllLines (path traversal)"),
    "File.WriteAllText": _sink("path", [0], "File.WriteAllText (path traversal)"),
    "File.WriteAllTextAsync": _sink("path", [0], "File.WriteAllTextAsync (path traversal)"),
    "File.WriteAllBytes": _sink("path", [0], "File.WriteAllBytes (path traversal)"),
    "File.Delete": _sink("path", [0], "File.Delete (path traversal)"),
    "File.Copy": _sink("path", [0, 1], "File.Copy (path traversal)"),
    "File.Move": _sink("path", [0, 1], "File.Move (path traversal)"),
    "File.Exists": _sink("path", [0], "File.Exists (path traversal)"),
    "File.Open": _sink("path", [0], "File.Open (path traversal)"),
    "File.Create": _sink("path", [0], "File.Create (path traversal)"),

    # FileStream
    "FileStream": _sink("path", [0], "FileStream (path traversal)"),
    "StreamReader": _sink("path", [0], "StreamReader (path traversal)"),
    "StreamWriter": _sink("path", [0], "StreamWriter (path traversal)"),

    # Directory
    "Directory.GetFiles": _sink("path", [0], "Directory.GetFiles (path traversal)"),
    "Directory.GetDirectories": _sink("path", [0], "Directory.GetDirectories (path traversal)"),
    "Directory.Delete": _sink("path", [0], "Directory.Delete (path traversal)"),
    "Directory.CreateDirectory": _sink("path", [0], "Directory.CreateDirectory (path traversal)"),

    # Path
    "Path.Combine": _propagator([0, 1], "Path.Combine"),
    "Path.GetFullPath": _propagator([0], "Path.GetFullPath"),
}

# =============================================================================
# System.Diagnostics (Process Execution)
# =============================================================================

PROCESS_SPECS = {
    # Process (command injection)
    "Process.Start": _sink("command", [0], "Process.Start (command injection)"),
    "ProcessStartInfo": _sink("command", [0], "ProcessStartInfo (command injection)"),
    "ProcessStartInfo.FileName": _sink("command", [0], "ProcessStartInfo.FileName (command injection)"),
    "ProcessStartInfo.Arguments": _sink("command", [0], "ProcessStartInfo.Arguments (command injection)"),

    # Shell execution
    "cmd.exe": _sink("command", [0], "cmd.exe execution"),
    "/bin/bash": _sink("command", [0], "bash execution"),
}

# =============================================================================
# System.Net (HTTP Client - SSRF)
# =============================================================================

HTTP_SPECS = {
    # HttpClient (SSRF)
    "HttpClient.GetAsync": _sink("ssrf", [0], "HttpClient.GetAsync (SSRF)"),
    "HttpClient.PostAsync": _sink("ssrf", [0], "HttpClient.PostAsync (SSRF)"),
    "HttpClient.PutAsync": _sink("ssrf", [0], "HttpClient.PutAsync (SSRF)"),
    "HttpClient.DeleteAsync": _sink("ssrf", [0], "HttpClient.DeleteAsync (SSRF)"),
    "HttpClient.SendAsync": _sink("ssrf", [0], "HttpClient.SendAsync (SSRF)"),
    "HttpClient.GetStringAsync": _sink("ssrf", [0], "HttpClient.GetStringAsync (SSRF)"),

    # WebClient (legacy)
    "WebClient.DownloadString": _sink("ssrf", [0], "WebClient.DownloadString (SSRF)"),
    "WebClient.DownloadData": _sink("ssrf", [0], "WebClient.DownloadData (SSRF)"),
    "WebClient.DownloadFile": _sink("ssrf", [0], "WebClient.DownloadFile (SSRF)"),
    "WebClient.UploadString": _sink("ssrf", [0], "WebClient.UploadString (SSRF)"),

    # HttpWebRequest (legacy)
    "WebRequest.Create": _sink("ssrf", [0], "WebRequest.Create (SSRF)"),
    "HttpWebRequest": _sink("ssrf", [0], "HttpWebRequest (SSRF)"),

    # RestSharp
    "RestClient": _sink("ssrf", [0], "RestClient (SSRF)"),
    "RestRequest": _propagator([0], "RestRequest"),
}

# =============================================================================
# XML Processing (XXE)
# =============================================================================

XML_SPECS = {
    # XmlDocument (XXE)
    "XmlDocument.LoadXml": _sink("xxe", [0], "XmlDocument.LoadXml (XXE)"),
    "XmlDocument.Load": _sink("xxe", [0], "XmlDocument.Load (XXE)"),

    # XmlReader (safer by default in .NET 4.5.2+)
    "XmlReader.Create": _propagator([0], "XmlReader.Create"),
    "XmlTextReader": _sink("xxe", [0], "XmlTextReader (XXE - legacy)"),

    # XSLT
    "XslCompiledTransform.Load": _sink("xxe", [0], "XslCompiledTransform.Load (XXE)"),
    "XslCompiledTransform.Transform": _sink("xxe", [0, 1], "XslCompiledTransform.Transform (XXE)"),

    # XPath
    "SelectSingleNode": _sink("xpath", [0], "SelectSingleNode (XPath injection)"),
    "SelectNodes": _sink("xpath", [0], "SelectNodes (XPath injection)"),
    "XPathNavigator.Evaluate": _sink("xpath", [0], "XPathNavigator.Evaluate (XPath injection)"),
}

# =============================================================================
# Serialization (Deserialization)
# =============================================================================

SERIALIZATION_SPECS = {
    # BinaryFormatter (unsafe)
    "BinaryFormatter.Deserialize": _sink("deserialize", [0], "BinaryFormatter.Deserialize (unsafe)"),

    # JavaScriptSerializer
    "JavaScriptSerializer.Deserialize": _sink("deserialize", [0], "JavaScriptSerializer.Deserialize (unsafe)"),

    # Json.NET
    "JsonConvert.DeserializeObject": _propagator([0], "JsonConvert.DeserializeObject"),
    "JsonSerializer.Deserialize": _propagator([0], "JsonSerializer.Deserialize"),

    # DataContractSerializer
    "DataContractSerializer.ReadObject": _sink("deserialize", [0], "DataContractSerializer.ReadObject"),

    # XmlSerializer
    "XmlSerializer.Deserialize": _sink("deserialize", [0], "XmlSerializer.Deserialize"),
}

# =============================================================================
# LDAP
# =============================================================================

LDAP_SPECS = {
    # DirectorySearcher (LDAP injection)
    "DirectorySearcher.Filter": _sink("ldap", [0], "DirectorySearcher.Filter (LDAP injection)"),
    "DirectorySearcher.FindAll": _sink("ldap", [0], "DirectorySearcher.FindAll (LDAP injection)"),
    "DirectorySearcher.FindOne": _sink("ldap", [0], "DirectorySearcher.FindOne (LDAP injection)"),
}

# =============================================================================
# Regex (ReDoS)
# =============================================================================

REGEX_SPECS = {
    # Regex (ReDoS)
    "Regex": _sink("regex", [0], "Regex (potential ReDoS)"),
    "Regex.Match": _sink("regex", [0], "Regex.Match (potential ReDoS)"),
    "Regex.Replace": _sink("regex", [0], "Regex.Replace (potential ReDoS)"),
    "Regex.IsMatch": _sink("regex", [0], "Regex.IsMatch (potential ReDoS)"),
}

# =============================================================================
# Logging (Log Injection)
# =============================================================================

LOGGING_SPECS = {
    # ILogger
    "logger.LogInformation": _sink("log", [0], "ILogger.LogInformation (log injection)"),
    "logger.LogWarning": _sink("log", [0], "ILogger.LogWarning (log injection)"),
    "logger.LogError": _sink("log", [0], "ILogger.LogError (log injection)"),
    "logger.LogDebug": _sink("log", [0], "ILogger.LogDebug (log injection)"),
    "logger.LogCritical": _sink("log", [0], "ILogger.LogCritical (log injection)"),

    # NLog
    "Logger.Info": _sink("log", [0], "NLog Info (log injection)"),
    "Logger.Warn": _sink("log", [0], "NLog Warn (log injection)"),
    "Logger.Error": _sink("log", [0], "NLog Error (log injection)"),

    # Serilog
    "Log.Information": _sink("log", [0], "Serilog Information (log injection)"),
    "Log.Warning": _sink("log", [0], "Serilog Warning (log injection)"),
    "Log.Error": _sink("log", [0], "Serilog Error (log injection)"),
}

# =============================================================================
# Cryptography
# =============================================================================

CRYPTO_SPECS = {
    # Weak algorithms
    "MD5.Create": _propagator([0], "MD5.Create (weak hash)"),
    "SHA1.Create": _propagator([0], "SHA1.Create (weak hash)"),
    "DES.Create": _propagator([0], "DES.Create (weak encryption)"),
    "TripleDES.Create": _propagator([0], "TripleDES.Create (deprecated)"),

    # Strong algorithms
    "SHA256.Create": _propagator([0], "SHA256.Create"),
    "SHA512.Create": _propagator([0], "SHA512.Create"),
    "Aes.Create": _propagator([0], "Aes.Create"),

    # Random (weak)
    "Random": _propagator([0], "Random (not cryptographically secure)"),
    "RandomNumberGenerator.Create": _propagator([0], "RandomNumberGenerator (secure)"),
}

# =============================================================================
# String Operations
# =============================================================================

STRING_SPECS = {
    # String manipulation (propagators)
    "String.Concat": _propagator([0, 1], "String.Concat"),
    "String.Format": _propagator([0, 1], "String.Format"),
    "String.Join": _propagator([0, 1], "String.Join"),
    "String.Replace": _propagator([0], "String.Replace"),
    "String.Substring": _propagator([0], "String.Substring"),
    "String.ToLower": _propagator([0], "String.ToLower"),
    "String.ToUpper": _propagator([0], "String.ToUpper"),
    "String.Trim": _propagator([0], "String.Trim"),

    # StringBuilder
    "StringBuilder.Append": _propagator([0], "StringBuilder.Append"),
    "StringBuilder.AppendFormat": _propagator([0, 1], "StringBuilder.AppendFormat"),
    "StringBuilder.Insert": _propagator([1], "StringBuilder.Insert"),
    "StringBuilder.ToString": _propagator([0], "StringBuilder.ToString"),

    # Interpolation
    "$\"": _propagator([0], "String interpolation"),
}

# =============================================================================
# Sanitizers
# =============================================================================

SANITIZER_SPECS = {
    # HTML encoding
    "HtmlEncoder.Encode": _sanitizer(["html"], "HtmlEncoder.Encode"),
    "WebUtility.HtmlEncode": _sanitizer(["html"], "WebUtility.HtmlEncode"),
    "HttpUtility.HtmlEncode": _sanitizer(["html"], "HttpUtility.HtmlEncode"),

    # URL encoding
    "WebUtility.UrlEncode": _sanitizer(["url"], "WebUtility.UrlEncode"),
    "HttpUtility.UrlEncode": _sanitizer(["url"], "HttpUtility.UrlEncode"),
    "Uri.EscapeDataString": _sanitizer(["url"], "Uri.EscapeDataString"),

    # JavaScript encoding
    "JavaScriptEncoder.Encode": _sanitizer(["html", "xss"], "JavaScriptEncoder.Encode"),

    # Path sanitization
    "Path.GetFileName": _sanitizer(["path"], "Path.GetFileName (extracts filename only)"),
}

# =============================================================================
# Combined C# Specs
# =============================================================================

CSHARP_SPECS: Dict[str, ProcSpec] = {}
CSHARP_SPECS.update(ASPNET_SOURCE_SPECS)
CSHARP_SPECS.update(ASPNET_SINK_SPECS)
CSHARP_SPECS.update(EF_SPECS)
CSHARP_SPECS.update(ADONET_SPECS)
CSHARP_SPECS.update(IO_SPECS)
CSHARP_SPECS.update(PROCESS_SPECS)
CSHARP_SPECS.update(HTTP_SPECS)
CSHARP_SPECS.update(XML_SPECS)
CSHARP_SPECS.update(SERIALIZATION_SPECS)
CSHARP_SPECS.update(LDAP_SPECS)
CSHARP_SPECS.update(REGEX_SPECS)
CSHARP_SPECS.update(LOGGING_SPECS)
CSHARP_SPECS.update(CRYPTO_SPECS)
CSHARP_SPECS.update(STRING_SPECS)
CSHARP_SPECS.update(SANITIZER_SPECS)
