"""
Library specifications for Java frameworks.

This module defines ProcSpec for common Java APIs including:
- Spring Framework (web, security)
- Servlet API
- JDBC/JPA (database)
- Java standard library
"""

from typing import Dict
from frame.sil.procedure import ProcSpec


def _source(kind: str, desc: str = "") -> ProcSpec:
    """Create a taint source spec"""
    return ProcSpec(is_source=kind, description=desc)


def _sink(kind: str, args: list = None, desc: str = "") -> ProcSpec:
    """Create a taint sink spec

    Args:
        kind: Sink type (e.g., 'sql', 'html', 'weak_hash')
        args: List of argument indices to check for taint, or empty list for usage-based sinks
        desc: Human-readable description
    """
    # None means default to checking arg 0, empty list means usage-based (no taint check)
    if args is None:
        args = [0]
    return ProcSpec(is_sink=kind, sink_args=args, description=desc)


def _sanitizer(kinds: list, desc: str = "") -> ProcSpec:
    """Create a sanitizer spec"""
    return ProcSpec(is_sanitizer=kinds, description=desc)


def _propagator(args: list, desc: str = "") -> ProcSpec:
    """Create a taint propagator spec"""
    return ProcSpec(taint_propagates=args, description=desc)


def _propagator_from_receiver(desc: str = "") -> ProcSpec:
    """Create a taint propagator that flows taint from/to receiver object.

    Used for collection operations like List.add/get where taint flows
    between the collection and its elements.
    """
    return ProcSpec(taint_from_receiver=True, description=desc)


# =============================================================================
# Servlet API
# =============================================================================

SERVLET_SPECS = {
    # Request (taint sources)
    "getParameter": _source("user", "Servlet request parameter"),
    "getParameterValues": _source("user", "Servlet request parameter array"),
    "getParameterMap": _source("user", "Servlet request parameter map"),
    "getParameterNames": _source("user", "Servlet request parameter names"),
    "getHeader": _source("user", "Servlet request header"),
    "getHeaders": _source("user", "Servlet request headers"),
    "getHeaderNames": _source("user", "Servlet request header names"),
    "getCookies": _source("user", "Servlet cookies"),
    "getQueryString": _source("user", "Servlet query string"),
    "getPathInfo": _source("user", "Servlet path info"),
    "getRequestURI": _source("user", "Servlet request URI"),
    "getRequestURL": _source("user", "Servlet request URL"),
    "getInputStream": _source("user", "Servlet input stream"),
    "getReader": _source("user", "Servlet reader"),
    "getServletPath": _source("user", "Servlet path"),

    # HttpServletRequest
    "request.getParameter": _source("user", "HTTP request parameter"),
    "request.getHeader": _source("user", "HTTP request header"),
    "request.getCookies": _source("user", "HTTP cookies"),
    "request.getInputStream": _source("user", "HTTP input stream"),

    # OWASP Benchmark helper class wrappers (pass through user input)
    "getTheParameter": _source("user", "OWASP Benchmark wrapper - getParameter"),
    "getTheValue": _source("user", "OWASP Benchmark wrapper - getValue"),
    "getTheName": _source("user", "OWASP Benchmark wrapper - getName"),
    "getValue": _source("user", "Cookie/request value"),
    "nextElement": _source("user", "Enumeration element (from headers/params)"),

    # Common user input patterns
    "getAttribute": _source("user", "Request/session attribute"),
    "getRemoteAddr": _source("network", "Remote IP address"),
    "getRemoteHost": _source("network", "Remote hostname"),

    # Response (potential sinks)
    "getWriter": _propagator([0], "Servlet response writer"),
    "getOutputStream": _propagator([0], "Servlet response output stream"),

    # PrintWriter (XSS sinks)
    "print": _sink("html", [0], "PrintWriter.print (XSS)"),
    "println": _sink("html", [0], "PrintWriter.println (XSS)"),
    "printf": _sink("html", [0, 1], "PrintWriter.printf (XSS)"),  # Check format string and varargs
    "format": _sink("html", [0, 1], "PrintWriter.format (XSS)"),  # Check format string and varargs
    "write": _sink("html", [0], "Writer.write (XSS)"),
    # Chained PrintWriter patterns
    "getWriter().print": _sink("html", [0], "PrintWriter.print (XSS)"),
    "getWriter().println": _sink("html", [0], "PrintWriter.println (XSS)"),
    "getWriter().printf": _sink("html", [0, 1], "PrintWriter.printf (XSS)"),
    "getWriter().format": _sink("html", [0, 1], "PrintWriter.format (XSS)"),
    "getWriter().write": _sink("html", [0], "Writer.write (XSS)"),

    # Redirect
    "sendRedirect": _sink("redirect", [0], "Servlet redirect (open redirect)"),

    # Forward (path injection)
    "getRequestDispatcher": _sink("path", [0], "Request dispatcher (path injection)"),
    "forward": _propagator([0], "Forward request"),

    # Session - Trust Boundary Violation (CWE-501)
    # Putting user input into session without validation
    "putValue": _sink("trust_boundary", [1], "HttpSession.putValue (trust boundary violation)"),
    "setAttribute": _sink("trust_boundary", [1], "HttpSession.setAttribute (trust boundary violation)"),
    "session.putValue": _sink("trust_boundary", [1], "Session.putValue (trust boundary violation)"),
    "session.setAttribute": _sink("trust_boundary", [1], "Session.setAttribute (trust boundary violation)"),
    "HttpSession.putValue": _sink("trust_boundary", [1], "HttpSession.putValue (trust boundary violation)"),
    "HttpSession.setAttribute": _sink("trust_boundary", [1], "HttpSession.setAttribute (trust boundary violation)"),

    # Cookie - Insecure Cookie (CWE-614)
    # Creating cookies without secure flag
    "setSecure": _sink("insecure_cookie", [], "Cookie.setSecure (insecure cookie)"),
    "Cookie.setSecure": _sink("insecure_cookie", [], "Cookie.setSecure (insecure cookie)"),
    "cookie.setSecure": _sink("insecure_cookie", [], "Cookie.setSecure (insecure cookie)"),
}

# =============================================================================
# Spring Framework
# =============================================================================

SPRING_SPECS = {
    # RequestParam/PathVariable (taint sources)
    "@RequestParam": _source("user", "Spring request parameter"),
    "@PathVariable": _source("user", "Spring path variable"),
    "@RequestBody": _source("user", "Spring request body"),
    "@RequestHeader": _source("user", "Spring request header"),
    "@CookieValue": _source("user", "Spring cookie value"),
    "@MatrixVariable": _source("user", "Spring matrix variable"),

    # Model attributes
    "model.addAttribute": _propagator([1], "Spring model attribute"),
    "modelAndView.addObject": _propagator([1], "Spring ModelAndView object"),

    # ResponseEntity
    "ResponseEntity.ok": _propagator([0], "Spring ResponseEntity"),
    "ResponseEntity.body": _sink("html", [0], "Spring response body"),

    # Redirect
    "redirect:": _sink("redirect", [0], "Spring redirect"),
    "RedirectView": _sink("redirect", [0], "Spring RedirectView"),

    # RestTemplate (SSRF)
    "restTemplate.getForObject": _sink("ssrf", [0], "Spring RestTemplate GET (SSRF)"),
    "restTemplate.postForObject": _sink("ssrf", [0], "Spring RestTemplate POST (SSRF)"),
    "restTemplate.exchange": _sink("ssrf", [0], "Spring RestTemplate exchange (SSRF)"),
    "restTemplate.getForEntity": _sink("ssrf", [0], "Spring RestTemplate GET entity (SSRF)"),

    # WebClient (SSRF)
    "webClient.get": _sink("ssrf", [0], "Spring WebClient GET (SSRF)"),
    "webClient.post": _sink("ssrf", [0], "Spring WebClient POST (SSRF)"),

    # JdbcTemplate (SQL) - various casing patterns
    "jdbcTemplate.query": _sink("sql", [0], "Spring JdbcTemplate query (SQL injection)"),
    "jdbcTemplate.queryForObject": _sink("sql", [0], "Spring JdbcTemplate queryForObject (SQL injection)"),
    "jdbcTemplate.queryForList": _sink("sql", [0], "Spring JdbcTemplate queryForList (SQL injection)"),
    "jdbcTemplate.queryForRowSet": _sink("sql", [0], "Spring JdbcTemplate queryForRowSet (SQL injection)"),
    "jdbcTemplate.queryForMap": _sink("sql", [0], "Spring JdbcTemplate queryForMap (SQL injection)"),
    "jdbcTemplate.update": _sink("sql", [0], "Spring JdbcTemplate update (SQL injection)"),
    "jdbcTemplate.execute": _sink("sql", [0], "Spring JdbcTemplate execute (SQL injection)"),
    # OWASP Benchmark uses JDBCtemplate (different casing)
    "JDBCtemplate.query": _sink("sql", [0], "Spring JdbcTemplate query (SQL injection)"),
    "JDBCtemplate.queryForObject": _sink("sql", [0], "Spring JdbcTemplate queryForObject (SQL injection)"),
    "JDBCtemplate.queryForList": _sink("sql", [0], "Spring JdbcTemplate queryForList (SQL injection)"),
    "JDBCtemplate.queryForRowSet": _sink("sql", [0], "Spring JdbcTemplate queryForRowSet (SQL injection)"),
    "JDBCtemplate.queryForMap": _sink("sql", [0], "Spring JdbcTemplate queryForMap (SQL injection)"),
    "JDBCtemplate.update": _sink("sql", [0], "Spring JdbcTemplate update (SQL injection)"),
    "JDBCtemplate.execute": _sink("sql", [0], "Spring JdbcTemplate execute (SQL injection)"),
    # Short forms
    "queryForObject": _sink("sql", [0], "JdbcTemplate queryForObject (SQL injection)"),
    "queryForList": _sink("sql", [0], "JdbcTemplate queryForList (SQL injection)"),
    "queryForRowSet": _sink("sql", [0], "Spring JdbcTemplate queryForRowSet (SQL injection)"),
    "queryForMap": _sink("sql", [0], "JdbcTemplate queryForMap (SQL injection)"),

    # NamedParameterJdbcTemplate
    "namedParameterJdbcTemplate.query": _sink("sql", [0], "Spring NamedParameterJdbcTemplate (SQL injection)"),
    "namedParameterJdbcTemplate.update": _sink("sql", [0], "Spring NamedParameterJdbcTemplate (SQL injection)"),
}

# =============================================================================
# JDBC
# =============================================================================

JDBC_SPECS = {
    # Statement (SQL injection sinks)
    "executeQuery": _sink("sql", [0], "JDBC executeQuery (SQL injection)"),
    "executeUpdate": _sink("sql", [0], "JDBC executeUpdate (SQL injection)"),
    "execute": _sink("sql", [0], "JDBC execute (SQL injection)"),
    "addBatch": _sink("sql", [0], "JDBC addBatch (SQL injection)"),

    # Connection
    "prepareStatement": _sink("sql", [0], "JDBC prepareStatement (SQL injection if dynamic)"),
    "prepareCall": _sink("sql", [0], "JDBC prepareCall (SQL injection)"),
    "nativeSQL": _sink("sql", [0], "JDBC nativeSQL (SQL injection)"),

    # Statement creation
    "createStatement": _propagator([0], "JDBC createStatement"),
    "connection.createStatement": _propagator([0], "JDBC createStatement"),
    "connection.prepareStatement": _sink("sql", [0], "JDBC prepareStatement"),
}

# =============================================================================
# JPA/Hibernate
# =============================================================================

JPA_SPECS = {
    # EntityManager (query sinks)
    "createQuery": _sink("sql", [0], "JPA createQuery (HQL/JPQL injection)"),
    "createNativeQuery": _sink("sql", [0], "JPA createNativeQuery (SQL injection)"),

    # Criteria API (generally safe but track)
    "criteriaBuilder.equal": _propagator([1], "JPA Criteria equal"),
    "criteriaBuilder.like": _propagator([1], "JPA Criteria like"),

    # Hibernate Session
    "session.createQuery": _sink("sql", [0], "Hibernate createQuery (HQL injection)"),
    "session.createSQLQuery": _sink("sql", [0], "Hibernate createSQLQuery (SQL injection)"),
    "session.createNativeQuery": _sink("sql", [0], "Hibernate createNativeQuery (SQL injection)"),
}

# =============================================================================
# Java I/O (Path Traversal)
# =============================================================================

IO_SPECS = {
    # File operations - various patterns for object creation
    # Using "filesystem" to match SinkKind.FILE_PATH.value
    "new File": _sink("filesystem", [0], "File constructor (path traversal)"),
    "File": _sink("filesystem", [0], "File constructor (path traversal)"),
    "new java.io.File": _sink("filesystem", [0], "File constructor (path traversal)"),

    "FileInputStream": _sink("filesystem", [0], "FileInputStream (path traversal)"),
    "new FileInputStream": _sink("filesystem", [0], "FileInputStream (path traversal)"),
    "new java.io.FileInputStream": _sink("filesystem", [0], "FileInputStream (path traversal)"),

    "FileOutputStream": _sink("filesystem", [0], "FileOutputStream (path traversal)"),
    "new FileOutputStream": _sink("filesystem", [0], "FileOutputStream (path traversal)"),
    "new java.io.FileOutputStream": _sink("filesystem", [0], "FileOutputStream (path traversal)"),

    "FileReader": _sink("filesystem", [0], "FileReader (path traversal)"),
    "new FileReader": _sink("filesystem", [0], "FileReader (path traversal)"),
    "new java.io.FileReader": _sink("filesystem", [0], "FileReader (path traversal)"),

    "FileWriter": _sink("filesystem", [0], "FileWriter (path traversal)"),
    "new FileWriter": _sink("filesystem", [0], "FileWriter (path traversal)"),
    "new java.io.FileWriter": _sink("filesystem", [0], "FileWriter (path traversal)"),

    "RandomAccessFile": _sink("filesystem", [0], "RandomAccessFile (path traversal)"),
    "new RandomAccessFile": _sink("filesystem", [0], "RandomAccessFile (path traversal)"),
    "new java.io.RandomAccessFile": _sink("filesystem", [0], "RandomAccessFile (path traversal)"),

    # NIO Path
    "Paths.get": _sink("filesystem", [0], "Paths.get (path traversal)"),
    "Path.of": _sink("filesystem", [0], "Path.of (path traversal)"),
    "Files.readAllBytes": _sink("filesystem", [0], "Files.readAllBytes (path traversal)"),
    "Files.readAllLines": _sink("filesystem", [0], "Files.readAllLines (path traversal)"),
    "Files.write": _sink("filesystem", [0], "Files.write (path traversal)"),
    "Files.delete": _sink("filesystem", [0], "Files.delete (path traversal)"),
    "Files.copy": _sink("filesystem", [0, 1], "Files.copy (path traversal)"),
    "Files.move": _sink("filesystem", [0, 1], "Files.move (path traversal)"),

    # ClassLoader
    "getResource": _sink("filesystem", [0], "ClassLoader.getResource (path traversal)"),
    "getResourceAsStream": _sink("filesystem", [0], "ClassLoader.getResourceAsStream (path traversal)"),
}

# =============================================================================
# Runtime/ProcessBuilder (Command Injection)
# =============================================================================

RUNTIME_SPECS = {
    # Runtime - check args at positions 0 and 1 (command and environment)
    "Runtime.exec": _sink("command", [0, 1], "Runtime.exec (command injection)"),
    "runtime.exec": _sink("command", [0, 1], "Runtime.exec (command injection)"),
    "Runtime.getRuntime().exec": _sink("command", [0, 1], "Runtime.exec (command injection)"),
    "r.exec": _sink("command", [0, 1], "Runtime.exec (command injection)"),

    # ProcessBuilder - constructor takes command array
    "ProcessBuilder": _sink("command", [0], "ProcessBuilder (command injection)"),
    "new ProcessBuilder": _sink("command", [0], "ProcessBuilder (command injection)"),
    "processBuilder.command": _sink("command", [0], "ProcessBuilder.command (command injection)"),
}

# =============================================================================
# LDAP
# =============================================================================

LDAP_SPECS = {
    # LDAP search (LDAP injection)
    "search": _sink("ldap", [1], "LDAP search (LDAP injection)"),
    "lookup": _sink("ldap", [0], "LDAP lookup (LDAP injection)"),
    "dirContext.search": _sink("ldap", [1], "DirContext.search (LDAP injection)"),
    "ldapTemplate.search": _sink("ldap", [0], "LdapTemplate.search (LDAP injection)"),
}

# =============================================================================
# XPath
# =============================================================================

XPATH_SPECS = {
    # XPath (XPath injection)
    "evaluate": _sink("xpath", [0], "XPath.evaluate (XPath injection)"),
    "compile": _sink("xpath", [0], "XPath.compile (XPath injection)"),
    "xpath.evaluate": _sink("xpath", [0], "XPath.evaluate (XPath injection)"),
    "xpath.compile": _sink("xpath", [0], "XPath.compile (XPath injection)"),
}

# =============================================================================
# XML (XXE)
# =============================================================================

XML_SPECS = {
    # DocumentBuilder (XXE)
    "DocumentBuilderFactory.newInstance": _propagator([0], "DocumentBuilderFactory"),
    "documentBuilder.parse": _sink("xxe", [0], "DocumentBuilder.parse (XXE)"),

    # SAXParser (XXE)
    "SAXParserFactory.newInstance": _propagator([0], "SAXParserFactory"),
    "saxParser.parse": _sink("xxe", [0], "SAXParser.parse (XXE)"),

    # XMLReader (XXE)
    "XMLReaderFactory.createXMLReader": _propagator([0], "XMLReader"),
    "xmlReader.parse": _sink("xxe", [0], "XMLReader.parse (XXE)"),

    # Transformer (XXE)
    "TransformerFactory.newInstance": _propagator([0], "TransformerFactory"),
    "transformer.transform": _sink("xxe", [0], "Transformer.transform (XXE)"),

    # Unmarshaller (XXE)
    "unmarshaller.unmarshal": _sink("xxe", [0], "Unmarshaller.unmarshal (XXE)"),
}

# =============================================================================
# Deserialization
# =============================================================================

SERIALIZATION_SPECS = {
    # ObjectInputStream (unsafe deserialization)
    "ObjectInputStream": _sink("deserialize", [0], "ObjectInputStream (unsafe deserialization)"),
    "readObject": _sink("deserialize", [0], "ObjectInputStream.readObject (unsafe deserialization)"),
    "objectInputStream.readObject": _sink("deserialize", [0], "readObject (unsafe deserialization)"),

    # XMLDecoder (unsafe deserialization)
    "XMLDecoder": _sink("deserialize", [0], "XMLDecoder (unsafe deserialization)"),
    "xmlDecoder.readObject": _sink("deserialize", [0], "XMLDecoder.readObject (unsafe deserialization)"),

    # YAML (unsafe deserialization)
    "Yaml.load": _sink("deserialize", [0], "Yaml.load (unsafe deserialization)"),
    "yaml.load": _sink("deserialize", [0], "Yaml.load (unsafe deserialization)"),

    # Jackson (type handling)
    "objectMapper.readValue": _propagator([0], "Jackson readValue"),
    "objectMapper.enableDefaultTyping": _sink("deserialize", [0], "Jackson default typing (unsafe)"),
}

# =============================================================================
# Expression Language (EL Injection)
# =============================================================================

EL_SPECS = {
    # EL Expression
    "ExpressionFactory.createValueExpression": _sink("el", [1], "EL createValueExpression (EL injection)"),
    "ValueExpression.getValue": _propagator([0], "EL getValue"),

    # OGNL (Struts)
    "Ognl.getValue": _sink("el", [0], "OGNL getValue (OGNL injection)"),
    "Ognl.setValue": _sink("el", [0], "OGNL setValue (OGNL injection)"),

    # SpEL (Spring)
    "expressionParser.parseExpression": _sink("el", [0], "SpEL parseExpression (SpEL injection)"),
    "expression.getValue": _propagator([0], "SpEL getValue"),
}

# =============================================================================
# URL/HTTP Client (SSRF)
# =============================================================================

URL_SPECS = {
    # URL
    "new URL": _sink("ssrf", [0], "URL constructor (SSRF)"),
    "URL": _sink("ssrf", [0], "URL constructor (SSRF)"),
    "url.openConnection": _sink("ssrf", [0], "URL.openConnection (SSRF)"),
    "url.openStream": _sink("ssrf", [0], "URL.openStream (SSRF)"),

    # HttpURLConnection
    "httpURLConnection.connect": _propagator([0], "HttpURLConnection.connect"),

    # HttpClient
    "httpClient.execute": _sink("ssrf", [0], "HttpClient.execute (SSRF)"),
    "httpClient.send": _sink("ssrf", [0], "HttpClient.send (SSRF)"),

    # Apache HttpClient
    "HttpGet": _sink("ssrf", [0], "HttpGet (SSRF)"),
    "HttpPost": _sink("ssrf", [0], "HttpPost (SSRF)"),
}

# =============================================================================
# Logging (Log Injection)
# =============================================================================

LOGGING_SPECS = {
    # java.util.logging
    "logger.info": _sink("log", [0], "Logger.info (log injection)"),
    "logger.warning": _sink("log", [0], "Logger.warning (log injection)"),
    "logger.severe": _sink("log", [0], "Logger.severe (log injection)"),
    "logger.fine": _sink("log", [0], "Logger.fine (log injection)"),

    # Log4j
    "log.info": _sink("log", [0], "Log4j info (log injection)"),
    "log.warn": _sink("log", [0], "Log4j warn (log injection)"),
    "log.error": _sink("log", [0], "Log4j error (log injection)"),
    "log.debug": _sink("log", [0], "Log4j debug (log injection)"),

    # SLF4J
    "slf4j.info": _sink("log", [0], "SLF4J info (log injection)"),
    "slf4j.warn": _sink("log", [0], "SLF4J warn (log injection)"),
    "slf4j.error": _sink("log", [0], "SLF4J error (log injection)"),
}

# =============================================================================
# Reflection (Unsafe)
# =============================================================================

REFLECTION_SPECS = {
    # Class loading
    "Class.forName": _sink("code", [0], "Class.forName (class injection)"),
    "loadClass": _sink("code", [0], "ClassLoader.loadClass (class injection)"),

    # Method invocation
    "method.invoke": _sink("code", [0], "Method.invoke (reflection injection)"),

    # ScriptEngine (code injection)
    "scriptEngine.eval": _sink("code", [0], "ScriptEngine.eval (code injection)"),
    "engine.eval": _sink("code", [0], "ScriptEngine.eval (code injection)"),
}

# =============================================================================
# Sanitizers
# =============================================================================

SANITIZER_SPECS = {
    # OWASP ESAPI Encoder (most common in OWASP Benchmark)
    "encodeForHTML": _sanitizer(["html", "xss"], "ESAPI encodeForHTML (XSS)"),
    "encodeForJavaScript": _sanitizer(["html", "xss"], "ESAPI encodeForJavaScript (XSS)"),
    "encodeForCSS": _sanitizer(["html", "xss"], "ESAPI encodeForCSS (XSS)"),
    "encodeForURL": _sanitizer(["url", "redirect"], "ESAPI encodeForURL"),
    "encodeForXML": _sanitizer(["xml", "xxe"], "ESAPI encodeForXML"),
    "encodeForXMLAttribute": _sanitizer(["xml", "xxe"], "ESAPI encodeForXMLAttribute"),
    "encodeForXPath": _sanitizer(["xpath"], "ESAPI encodeForXPath"),
    "encodeForSQL": _sanitizer(["sql"], "ESAPI encodeForSQL"),
    "encodeForLDAP": _sanitizer(["ldap"], "ESAPI encodeForLDAP"),
    "encodeForDN": _sanitizer(["ldap"], "ESAPI encodeForDN"),
    "encodeForOS": _sanitizer(["command"], "ESAPI encodeForOS (command injection)"),
    "encodeForBase64": _sanitizer([], "ESAPI encodeForBase64"),  # encoding, not security sanitization
    "ESAPI.encoder().encodeForHTML": _sanitizer(["html", "xss"], "ESAPI encodeForHTML (XSS)"),
    "ESAPI.encoder().encodeForJavaScript": _sanitizer(["html", "xss"], "ESAPI encodeForJavaScript (XSS)"),
    "org.owasp.esapi.ESAPI.encoder().encodeForHTML": _sanitizer(["html", "xss"], "ESAPI encodeForHTML (XSS)"),

    # OWASP Encoder library
    "Encode.forHtml": _sanitizer(["html", "xss"], "OWASP Encode.forHtml"),
    "Encode.forHtmlContent": _sanitizer(["html", "xss"], "OWASP Encode.forHtmlContent"),
    "Encode.forHtmlAttribute": _sanitizer(["html", "xss"], "OWASP Encode.forHtmlAttribute"),
    "Encode.forJavaScript": _sanitizer(["html", "xss"], "OWASP Encode.forJavaScript"),
    "Encode.forCssString": _sanitizer(["html", "xss"], "OWASP Encode.forCssString"),
    "Encode.forUriComponent": _sanitizer(["url"], "OWASP Encode.forUriComponent"),
    "forHtml": _sanitizer(["html", "xss"], "OWASP Encode.forHtml"),
    "forHtmlContent": _sanitizer(["html", "xss"], "OWASP Encode.forHtmlContent"),
    "forHtmlAttribute": _sanitizer(["html", "xss"], "OWASP Encode.forHtmlAttribute"),
    "forJavaScript": _sanitizer(["html", "xss"], "OWASP Encode.forJavaScript"),

    # Apache Commons
    "StringEscapeUtils.escapeHtml4": _sanitizer(["html", "xss"], "Apache StringEscapeUtils.escapeHtml4"),
    "StringEscapeUtils.escapeHtml": _sanitizer(["html", "xss"], "Apache StringEscapeUtils.escapeHtml"),
    "StringEscapeUtils.escapeXml": _sanitizer(["html", "xml", "xss"], "Apache StringEscapeUtils.escapeXml"),
    "StringEscapeUtils.escapeSql": _sanitizer(["sql"], "Apache StringEscapeUtils.escapeSql"),
    "escapeHtml4": _sanitizer(["html", "xss"], "Apache StringEscapeUtils.escapeHtml4"),
    "escapeHtml": _sanitizer(["html", "xss"], "Apache StringEscapeUtils.escapeHtml"),
    "escapeXml": _sanitizer(["html", "xml", "xss"], "Apache StringEscapeUtils.escapeXml"),
    "escapeSql": _sanitizer(["sql"], "Apache StringEscapeUtils.escapeSql"),

    # Spring
    "HtmlUtils.htmlEscape": _sanitizer(["html", "xss"], "Spring HtmlUtils.htmlEscape"),
    "htmlEscape": _sanitizer(["html", "xss"], "Spring HtmlUtils.htmlEscape"),

    # Prepared statements (SQL sanitizer)
    "setString": _sanitizer(["sql"], "PreparedStatement.setString"),
    "setInt": _sanitizer(["sql"], "PreparedStatement.setInt"),
    "setLong": _sanitizer(["sql"], "PreparedStatement.setLong"),
    "setFloat": _sanitizer(["sql"], "PreparedStatement.setFloat"),
    "setDouble": _sanitizer(["sql"], "PreparedStatement.setDouble"),
    "setBoolean": _sanitizer(["sql"], "PreparedStatement.setBoolean"),
    "setDate": _sanitizer(["sql"], "PreparedStatement.setDate"),
    "setTimestamp": _sanitizer(["sql"], "PreparedStatement.setTimestamp"),
    "setObject": _sanitizer(["sql"], "PreparedStatement.setObject"),
    "prepareStatement": _sanitizer(["sql"], "Connection.prepareStatement (parameterized)"),
}

# =============================================================================
# String operations (propagators)
# =============================================================================

STRING_SPECS = {
    "concat": _propagator([0], "String.concat"),
    "substring": _propagator([0], "String.substring"),
    "replace": _propagator([0], "String.replace"),
    "replaceAll": _propagator([0], "String.replaceAll"),
    "toLowerCase": _propagator([0], "String.toLowerCase"),
    "toUpperCase": _propagator([0], "String.toUpperCase"),
    "trim": _propagator([0], "String.trim"),
    "String.format": _propagator([0, 1], "String.format"),
    "StringBuilder.append": _propagator([0], "StringBuilder.append"),
    "StringBuffer.append": _propagator([0], "StringBuffer.append"),
    "toString": _propagator([0], "Object.toString"),
    "getBytes": _propagator([0], "String.getBytes"),
    "toCharArray": _propagator([0], "String.toCharArray"),
    "split": _propagator([0], "String.split"),
    "valueOf": _propagator([0], "String.valueOf"),
}

# =============================================================================
# Collection operations (taint propagators for List/Set/Collection)
# =============================================================================

COLLECTION_SPECS = {
    # List.add - taint flows from argument to receiver (list becomes tainted)
    # taint_propagates=[0] so arg is checked, taint_from_receiver=True for bidirectional
    "add": ProcSpec(taint_propagates=[0], taint_from_receiver=True, description="List.add"),
    "addAll": ProcSpec(taint_propagates=[0], taint_from_receiver=True, description="List.addAll"),
    "set": ProcSpec(taint_propagates=[1], taint_from_receiver=True, description="List.set"),  # set(index, value)
    "put": ProcSpec(taint_propagates=[1], taint_from_receiver=True, description="Map.put"),  # put(key, value)
    "putAll": ProcSpec(taint_propagates=[0], taint_from_receiver=True, description="Map.putAll"),

    # List.get - taint flows from receiver (list) to return value
    "get": _propagator_from_receiver("List.get"),
    "remove": _propagator_from_receiver("List.remove"),
    "poll": _propagator_from_receiver("Queue.poll"),
    "peek": _propagator_from_receiver("Queue.peek"),
    "pop": _propagator_from_receiver("Stack.pop"),
    "first": _propagator_from_receiver("List.first"),
    "last": _propagator_from_receiver("List.last"),
    "iterator": _propagator_from_receiver("Collection.iterator"),
    "next": _propagator_from_receiver("Iterator.next"),
    "toArray": _propagator_from_receiver("Collection.toArray"),
    "stream": _propagator_from_receiver("Collection.stream"),
}

# =============================================================================
# Encoding/Decoding operations (propagators - taint flows through)
# =============================================================================

ENCODING_SPECS = {
    # URL encoding/decoding
    "URLDecoder.decode": _propagator([0], "URLDecoder.decode"),
    "java.net.URLDecoder.decode": _propagator([0], "URLDecoder.decode"),
    "URLEncoder.encode": _propagator([0], "URLEncoder.encode"),
    "java.net.URLEncoder.encode": _propagator([0], "URLEncoder.encode"),
    "decode": _propagator([0], "URL decode"),
    "encode": _propagator([0], "URL encode"),

    # Base64
    "Base64.getDecoder().decode": _propagator([0], "Base64 decode"),
    "Base64.getEncoder().encode": _propagator([0], "Base64 encode"),
    "Base64.decode": _propagator([0], "Base64 decode"),
    "Base64.encode": _propagator([0], "Base64 encode"),
    "decodeBase64": _propagator([0], "Base64 decode"),
    "encodeBase64": _propagator([0], "Base64 encode"),

    # Hex
    "Hex.decode": _propagator([0], "Hex decode"),
    "Hex.encode": _propagator([0], "Hex encode"),

    # JSON
    "parseObject": _propagator([0], "JSON parse"),
    "toJSONString": _propagator([0], "JSON stringify"),
    "readValue": _propagator([0], "Jackson readValue"),
    "writeValueAsString": _propagator([0], "Jackson writeValue"),
}

# =============================================================================
# Additional command injection patterns
# =============================================================================

COMMAND_INJECTION_SPECS = {
    # Runtime.exec variations - check both command and environment args
    "exec": _sink("command", [0, 1], "Runtime.exec (command injection)"),
    "getRuntime().exec": _sink("command", [0, 1], "Runtime.exec (command injection)"),

    # ProcessBuilder.command - sets command
    "command": _sink("command", [0], "ProcessBuilder.command (command injection)"),
    "pb.command": _sink("command", [0], "ProcessBuilder.command (command injection)"),
}

# =============================================================================
# A01: Broken Access Control (OWASP 2025)
# =============================================================================

ACCESS_CONTROL_SPECS = {
    # JWT handling
    "Jwts.parser": _sink("auth", [0], "JWT parser - verify signature (CWE-347)"),
    "JWT.decode": _sink("auth", [0], "JWT decode (CWE-347)"),
    "JWTVerifier": _propagator([0], "JWT verifier"),

    # Session handling
    "HttpSession": _propagator([0], "HTTP session"),
    "session.getAttribute": _source("user", "Session attribute"),
    "session.setAttribute": _propagator([0, 1], "Session attribute set"),
    "session.invalidate": _propagator([0], "Session invalidation"),

    # Authorization
    "@PreAuthorize": _propagator([0], "Spring PreAuthorize"),
    "@Secured": _propagator([0], "Spring Secured"),
    "@RolesAllowed": _propagator([0], "Roles allowed"),
    "hasRole": _propagator([0], "Role check"),
    "hasAuthority": _propagator([0], "Authority check"),
    "isAuthenticated": _propagator([0], "Authentication check"),

    # CORS
    "@CrossOrigin": _sink("cors", [0], "CORS annotation (CWE-942)"),
    "CorsConfiguration": _sink("cors", [0], "CORS configuration (CWE-942)"),
    "addAllowedOrigin": _sink("cors", [0], "CORS allowed origin (CWE-942)"),
}

# =============================================================================
# A02: Security Misconfiguration (OWASP 2025)
# =============================================================================

MISCONFIGURATION_SPECS = {
    # Debug/verbose mode
    "printStackTrace": _sink("info_disclosure", [0], "Stack trace print (CWE-209)"),
    "e.getMessage": _sink("info_disclosure", [0], "Exception message (CWE-209)"),
    "getStackTrace": _sink("info_disclosure", [0], "Get stack trace (CWE-209)"),

    # SSL/TLS verification disabled
    "TrustAllCerts": _sink("ssl", [0], "Trust all certificates (CWE-295)"),
    "ALLOW_ALL_HOSTNAME_VERIFIER": _sink("ssl", [0], "Allow all hostnames (CWE-295)"),
    "setHostnameVerifier": _sink("ssl", [0], "Custom hostname verifier (CWE-295)"),
    "X509TrustManager": _sink("ssl", [0], "Custom trust manager (CWE-295)"),

    # Hardcoded secrets
    "password": _sink("hardcoded_cred", [0], "Potential hardcoded password (CWE-798)"),
    "apiKey": _sink("hardcoded_cred", [0], "Potential hardcoded API key (CWE-798)"),
    "secretKey": _sink("hardcoded_cred", [0], "Potential hardcoded secret (CWE-798)"),
    "privateKey": _sink("hardcoded_cred", [0], "Potential hardcoded private key (CWE-798)"),

    # Binding to all interfaces
    "0.0.0.0": _sink("config", [0], "Binding to all interfaces (CWE-668)"),
}

# =============================================================================
# A04: Cryptographic Failures (OWASP 2025)
# =============================================================================

CRYPTO_SPECS = {
    # Hash functions - need argument check in translator for algorithm
    # These are markers for MessageDigest.getInstance() - weak algorithms checked at runtime
    "MessageDigest.getInstance": _sink("weak_hash", [], "Hash function (algorithm check required)"),
    "java.security.MessageDigest.getInstance": _sink("weak_hash", [], "Hash function (algorithm check required)"),

    # Apache Commons digest utilities - always weak
    "DigestUtils.md5": _sink("weak_hash", [], "MD5 hash (CWE-328)"),
    "DigestUtils.md5Hex": _sink("weak_hash", [], "MD5 hash (CWE-328)"),
    "DigestUtils.sha1": _sink("weak_hash", [], "SHA-1 hash (CWE-328)"),
    "DigestUtils.sha1Hex": _sink("weak_hash", [], "SHA-1 hash (CWE-328)"),

    # Encryption - need argument check in translator for algorithm
    "Cipher.getInstance": _sink("weak_crypto", [], "Cipher (algorithm check required)"),
    "javax.crypto.Cipher.getInstance": _sink("weak_crypto", [], "Cipher (algorithm check required)"),

    # Insecure random - categorized as weak_crypto to match OWASP benchmark
    "java.util.Random": _sink("weak_crypto", [], "Insecure random (CWE-330)"),
    "Math.random": _sink("weak_crypto", [], "Math.random (CWE-330)"),
    "Random.nextFloat": _sink("weak_crypto", [], "Random.nextFloat (CWE-330)"),
    "Random.nextDouble": _sink("weak_crypto", [], "Random.nextDouble (CWE-330)"),
    "Random.nextInt": _sink("weak_crypto", [], "Random.nextInt (CWE-330)"),
    "Random.nextLong": _sink("weak_crypto", [], "Random.nextLong (CWE-330)"),
    "Random.nextBoolean": _sink("weak_crypto", [], "Random.nextBoolean (CWE-330)"),
    "Random.nextGaussian": _sink("weak_crypto", [], "Random.nextGaussian (CWE-330)"),
    "Random.nextBytes": _sink("weak_crypto", [], "Random.nextBytes (CWE-330)"),
    "new java.util.Random": _sink("weak_crypto", [], "new Random() (CWE-330)"),
    "nextFloat": _sink("weak_crypto", [], "Random.nextFloat (CWE-330)"),
    "nextDouble": _sink("weak_crypto", [], "Random.nextDouble (CWE-330)"),
    "nextInt": _sink("weak_crypto", [], "Random.nextInt (CWE-330)"),
    "nextLong": _sink("weak_crypto", [], "Random.nextLong (CWE-330)"),
    "nextGaussian": _sink("weak_crypto", [], "Random.nextGaussian (CWE-330)"),

    # Secure random - sanitizer
    "SecureRandom": _sanitizer(["random"], "Secure random"),
    "java.security.SecureRandom": _sanitizer(["random"], "Secure random"),
}

# =============================================================================
# A07: Identification and Authentication Failures (OWASP 2025)
# =============================================================================

AUTH_SPECS = {
    # Password hashing
    "BCrypt.hashpw": _sanitizer(["password"], "BCrypt password hashing"),
    "BCrypt.checkpw": _propagator([0, 1], "BCrypt password check"),
    "Argon2PasswordEncoder": _sanitizer(["password"], "Argon2 password hashing"),
    "SCryptPasswordEncoder": _sanitizer(["password"], "SCrypt password hashing"),
    "PBKDF2": _sanitizer(["password"], "PBKDF2 password hashing"),

    # Weak password hashing
    "MD5PasswordEncoder": _sink("weak_password_hash", [0], "MD5 for passwords (CWE-916)"),
    "ShaPasswordEncoder": _sink("weak_password_hash", [0], "SHA for passwords (CWE-916)"),

    # Session management
    "setMaxInactiveInterval": _propagator([0], "Session timeout"),
    "JSESSIONID": _propagator([0], "Session ID"),
    "setHttpOnly": _propagator([0], "HttpOnly cookie flag"),
    "setSecure": _propagator([0], "Secure cookie flag"),

    # Authentication
    "UsernamePasswordAuthenticationToken": _propagator([0, 1], "Auth token"),
    "AuthenticationManager": _propagator([0], "Authentication manager"),
}

# =============================================================================
# A10: Mishandling of Exceptional Conditions (OWASP 2025 - NEW)
# =============================================================================

EXCEPTION_SPECS = {
    # Empty catch blocks (detected by pattern)
    "catch (Exception e)": _sink("exception", [0], "Generic exception catch (CWE-396)"),
    "catch (Throwable t)": _sink("exception", [0], "Throwable catch (CWE-396)"),

    # Exception suppression
    "e.printStackTrace()": _sink("exception", [0], "printStackTrace only (CWE-390)"),

    # Resource management
    "finally": _propagator([0], "Finally block (check resource cleanup)"),
    "try-with-resources": _propagator([0], "Try-with-resources"),

    # System exit
    "System.exit": _sink("exception", [0], "System exit (CWE-705)"),
    "Runtime.halt": _sink("exception", [0], "Runtime halt (CWE-705)"),

    # Null pointer risks
    "NullPointerException": _propagator([0], "NPE handling"),
}

# =============================================================================
# Sensitive Data Exposure (A01/A09)
# =============================================================================

SENSITIVE_DATA_SPECS = {
    # Logging sensitive data - disabled for OWASP benchmark compatibility
    # These cause false positives because OWASP doesn't track them as vulnerabilities
    # "System.out.println": _sink("sensitive_log", [0], "Console output (CWE-532)"),
    # "System.err.println": _sink("sensitive_log", [0], "Error output (CWE-532)"),

    # Response body
    "PrintWriter.write": _propagator([0], "Response write"),
    "getWriter().write": _propagator([0], "Response write"),
    "OutputStream.write": _propagator([0], "Output stream write"),
}

# =============================================================================
# HTTP Header Security (A02/A05)
# =============================================================================

HEADER_SPECS = {
    # Security headers
    "X-Frame-Options": _propagator([0], "X-Frame-Options header"),
    "X-Content-Type-Options": _propagator([0], "X-Content-Type-Options header"),
    "Content-Security-Policy": _propagator([0], "CSP header"),
    "Strict-Transport-Security": _propagator([0], "HSTS header"),

    # Header injection
    "setHeader": _sink("header_injection", [1], "Set header (CWE-113)"),
    "addHeader": _sink("header_injection", [1], "Add header (CWE-113)"),
    "response.setHeader": _sink("header_injection", [1], "Response header (CWE-113)"),
}

# =============================================================================
# SSRF Enhanced (A01)
# =============================================================================

SSRF_ENHANCED_SPECS = {
    # Cloud metadata
    "169.254.169.254": _sink("ssrf", [0], "Cloud metadata (SSRF)"),
    "metadata.google.internal": _sink("ssrf", [0], "GCP metadata (SSRF)"),

    # Internal addresses
    "localhost": _sink("ssrf", [0], "Localhost (SSRF)"),
    "127.0.0.1": _sink("ssrf", [0], "Loopback (SSRF)"),
    "0.0.0.0": _sink("ssrf", [0], "All interfaces (SSRF)"),
}

# =============================================================================
# Regex DoS (A05)
# =============================================================================

REDOS_SPECS = {
    # Regex with user input
    "Pattern.compile": _sink("redos", [0], "Pattern compile (potential ReDoS CWE-1333)"),
    "Pattern.matches": _sink("redos", [0], "Pattern matches (potential ReDoS)"),
    ".matches": _sink("redos", [0], "String matches (potential ReDoS)"),
    ".replaceAll": _sink("redos", [0], "String replaceAll (potential ReDoS)"),
    ".split": _sink("redos", [0], "String split (potential ReDoS)"),
}

# =============================================================================
# Combined Java Specs
# =============================================================================

JAVA_SPECS: Dict[str, ProcSpec] = {}
JAVA_SPECS.update(SERVLET_SPECS)
JAVA_SPECS.update(SPRING_SPECS)
JAVA_SPECS.update(JDBC_SPECS)
JAVA_SPECS.update(JPA_SPECS)
JAVA_SPECS.update(IO_SPECS)
JAVA_SPECS.update(RUNTIME_SPECS)
JAVA_SPECS.update(LDAP_SPECS)
JAVA_SPECS.update(XPATH_SPECS)
JAVA_SPECS.update(XML_SPECS)
JAVA_SPECS.update(SERIALIZATION_SPECS)
JAVA_SPECS.update(EL_SPECS)
JAVA_SPECS.update(URL_SPECS)
JAVA_SPECS.update(LOGGING_SPECS)
JAVA_SPECS.update(REFLECTION_SPECS)
JAVA_SPECS.update(SANITIZER_SPECS)
JAVA_SPECS.update(STRING_SPECS)
JAVA_SPECS.update(COLLECTION_SPECS)
JAVA_SPECS.update(ENCODING_SPECS)
JAVA_SPECS.update(COMMAND_INJECTION_SPECS)
# OWASP 2025 enhanced coverage
JAVA_SPECS.update(ACCESS_CONTROL_SPECS)
JAVA_SPECS.update(MISCONFIGURATION_SPECS)
JAVA_SPECS.update(CRYPTO_SPECS)
JAVA_SPECS.update(AUTH_SPECS)
JAVA_SPECS.update(EXCEPTION_SPECS)
JAVA_SPECS.update(SENSITIVE_DATA_SPECS)
JAVA_SPECS.update(HEADER_SPECS)
JAVA_SPECS.update(SSRF_ENHANCED_SPECS)
JAVA_SPECS.update(REDOS_SPECS)
