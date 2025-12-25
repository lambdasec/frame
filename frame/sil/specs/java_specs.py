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
    """Create a taint sink spec"""
    return ProcSpec(is_sink=kind, sink_args=args or [0], description=desc)


def _sanitizer(kinds: list, desc: str = "") -> ProcSpec:
    """Create a sanitizer spec"""
    return ProcSpec(is_sanitizer=kinds, description=desc)


def _propagator(args: list, desc: str = "") -> ProcSpec:
    """Create a taint propagator spec"""
    return ProcSpec(taint_propagates=args, description=desc)


# =============================================================================
# Servlet API
# =============================================================================

SERVLET_SPECS = {
    # Request (taint sources)
    "getParameter": _source("user", "Servlet request parameter"),
    "getParameterValues": _source("user", "Servlet request parameter array"),
    "getParameterMap": _source("user", "Servlet request parameter map"),
    "getHeader": _source("user", "Servlet request header"),
    "getHeaders": _source("user", "Servlet request headers"),
    "getCookies": _source("user", "Servlet cookies"),
    "getQueryString": _source("user", "Servlet query string"),
    "getPathInfo": _source("user", "Servlet path info"),
    "getRequestURI": _source("user", "Servlet request URI"),
    "getRequestURL": _source("user", "Servlet request URL"),
    "getInputStream": _source("user", "Servlet input stream"),
    "getReader": _source("user", "Servlet reader"),

    # HttpServletRequest
    "request.getParameter": _source("user", "HTTP request parameter"),
    "request.getHeader": _source("user", "HTTP request header"),
    "request.getCookies": _source("user", "HTTP cookies"),
    "request.getInputStream": _source("user", "HTTP input stream"),

    # Response (potential sinks)
    "getWriter": _propagator([0], "Servlet response writer"),
    "getOutputStream": _propagator([0], "Servlet response output stream"),

    # PrintWriter (XSS sinks)
    "print": _sink("html", [0], "PrintWriter.print (XSS)"),
    "println": _sink("html", [0], "PrintWriter.println (XSS)"),
    "write": _sink("html", [0], "Writer.write (XSS)"),

    # Redirect
    "sendRedirect": _sink("redirect", [0], "Servlet redirect (open redirect)"),

    # Forward (path injection)
    "getRequestDispatcher": _sink("path", [0], "Request dispatcher (path injection)"),
    "forward": _propagator([0], "Forward request"),
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

    # JdbcTemplate (SQL)
    "jdbcTemplate.query": _sink("sql", [0], "Spring JdbcTemplate query (SQL injection)"),
    "jdbcTemplate.queryForObject": _sink("sql", [0], "Spring JdbcTemplate queryForObject (SQL injection)"),
    "jdbcTemplate.queryForList": _sink("sql", [0], "Spring JdbcTemplate queryForList (SQL injection)"),
    "jdbcTemplate.update": _sink("sql", [0], "Spring JdbcTemplate update (SQL injection)"),
    "jdbcTemplate.execute": _sink("sql", [0], "Spring JdbcTemplate execute (SQL injection)"),

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
    # File operations
    "new File": _sink("path", [0], "File constructor (path traversal)"),
    "File": _sink("path", [0], "File constructor (path traversal)"),
    "FileInputStream": _sink("path", [0], "FileInputStream (path traversal)"),
    "FileOutputStream": _sink("path", [0], "FileOutputStream (path traversal)"),
    "FileReader": _sink("path", [0], "FileReader (path traversal)"),
    "FileWriter": _sink("path", [0], "FileWriter (path traversal)"),
    "RandomAccessFile": _sink("path", [0], "RandomAccessFile (path traversal)"),

    # NIO Path
    "Paths.get": _sink("path", [0], "Paths.get (path traversal)"),
    "Path.of": _sink("path", [0], "Path.of (path traversal)"),
    "Files.readAllBytes": _sink("path", [0], "Files.readAllBytes (path traversal)"),
    "Files.readAllLines": _sink("path", [0], "Files.readAllLines (path traversal)"),
    "Files.write": _sink("path", [0], "Files.write (path traversal)"),
    "Files.delete": _sink("path", [0], "Files.delete (path traversal)"),
    "Files.copy": _sink("path", [0, 1], "Files.copy (path traversal)"),
    "Files.move": _sink("path", [0, 1], "Files.move (path traversal)"),

    # ClassLoader
    "getResource": _sink("path", [0], "ClassLoader.getResource (path traversal)"),
    "getResourceAsStream": _sink("path", [0], "ClassLoader.getResourceAsStream (path traversal)"),
}

# =============================================================================
# Runtime/ProcessBuilder (Command Injection)
# =============================================================================

RUNTIME_SPECS = {
    # Runtime
    "Runtime.exec": _sink("command", [0], "Runtime.exec (command injection)"),
    "runtime.exec": _sink("command", [0], "Runtime.exec (command injection)"),
    "Runtime.getRuntime().exec": _sink("command", [0], "Runtime.exec (command injection)"),

    # ProcessBuilder
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
    # OWASP Encoder
    "Encode.forHtml": _sanitizer(["html"], "OWASP Encode.forHtml"),
    "Encode.forHtmlContent": _sanitizer(["html"], "OWASP Encode.forHtmlContent"),
    "Encode.forHtmlAttribute": _sanitizer(["html"], "OWASP Encode.forHtmlAttribute"),
    "Encode.forJavaScript": _sanitizer(["html", "xss"], "OWASP Encode.forJavaScript"),
    "Encode.forCssString": _sanitizer(["html"], "OWASP Encode.forCssString"),
    "Encode.forUriComponent": _sanitizer(["url"], "OWASP Encode.forUriComponent"),

    # Apache Commons
    "StringEscapeUtils.escapeHtml4": _sanitizer(["html"], "Apache StringEscapeUtils.escapeHtml4"),
    "StringEscapeUtils.escapeXml": _sanitizer(["html", "xml"], "Apache StringEscapeUtils.escapeXml"),
    "StringEscapeUtils.escapeSql": _sanitizer(["sql"], "Apache StringEscapeUtils.escapeSql"),

    # Spring
    "HtmlUtils.htmlEscape": _sanitizer(["html"], "Spring HtmlUtils.htmlEscape"),

    # Prepared statements (SQL sanitizer)
    "setString": _sanitizer(["sql"], "PreparedStatement.setString"),
    "setInt": _sanitizer(["sql"], "PreparedStatement.setInt"),
    "setLong": _sanitizer(["sql"], "PreparedStatement.setLong"),
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
    "format": _propagator([0, 1], "String.format"),
    "StringBuilder.append": _propagator([0], "StringBuilder.append"),
    "StringBuffer.append": _propagator([0], "StringBuffer.append"),
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
