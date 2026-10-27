"""
Library specifications for Java (Spring, Servlet, JDBC/JPA, the JDK, ...), and the
type tables the Java frontend uses to match them.

The table itself is data: `data/java.toml` (one `[[spec]]` per call name, in lookup
order), loaded by `frame/sil/specs/tables.py`. Edit the TOML, then run the benchmark sweep.
"""

from typing import Dict

from frame.sil.procedure import ProcSpec
from frame.sil.specs.tables import load_table

JAVA_SPECS: Dict[str, ProcSpec] = load_table("java")


# Spec keys are written against the conventional variable name for a receiver
# (`documentBuilder.parse`, `jdbcTemplate.query`). The frontend knows each
# variable's declared type, so a call on `DocumentBuilder b` is looked up under
# the type's decapitalised name (`documentBuilder`) and under these aliases,
# whatever the variable is called. Only types whose decapitalised name is NOT
# the spec receiver need an entry.
JAVA_TYPE_RECEIVERS = {
    "HttpServletRequest": ("request",), "ServletRequest": ("request",),
    "HttpServletRequestWrapper": ("request",),
    "HttpServletResponse": ("response",), "ServletResponse": ("response",),
    "HttpSession": ("session",),
    "Session": ("session",), "StatelessSession": ("session",),
    "XPath": ("xpath",),
    "InitialDirContext": ("dirContext",), "LdapContext": ("dirContext",),
    "InitialLdapContext": ("dirContext",),
    "SpelExpressionParser": ("expressionParser",),
    "CloseableHttpClient": ("httpClient",),
    "HttpsURLConnection": ("httpURLConnection",),
    "Logger": ("log",),
}


# Documented return types of factory methods, so `var b = f.newDocumentBuilder()`
# has a type to match specs against (a `var` initialised by `new T(...)` needs
# no entry).
JAVA_FACTORY_RETURN_TYPES = {
    "newDocumentBuilder": "DocumentBuilder",
    "newSAXParser": "SAXParser",
    "getXMLReader": "XMLReader",
    "createXMLReader": "XMLReader",
    "newTransformer": "Transformer",
    "createUnmarshaller": "Unmarshaller",
    "newXPath": "XPath",
    "getEngineByName": "ScriptEngine",
    "getEngineByExtension": "ScriptEngine",
    "getRuntime": "Runtime",
    "openConnection": "URLConnection",
    "createDefault": "CloseableHttpClient",
}


# Declared return types of well-known APIs that are reached through a call CHAIN
# (`ActionContext.getContext().getParameters()`), keyed `OwnerType.method` (the owner is a class
# used as a qualifier, a variable's declared type, or an earlier link's result). They give the
# next link a receiver type, so it resolves to a canonical callee (framework packs match on it)
# instead of staying an unknown `$chain.method`.
JAVA_RETURN_TYPES = {
    # Struts 2
    "ActionContext.getContext": "com.opensymphony.xwork2.ActionContext",
    "ActionContext.getValueStack": "com.opensymphony.xwork2.util.ValueStack",
    "ServletActionContext.getRequest": "javax.servlet.http.HttpServletRequest",
    "ServletActionContext.getResponse": "javax.servlet.http.HttpServletResponse",
    "ServletActionContext.getServletContext": "javax.servlet.ServletContext",
    # JSF
    "FacesContext.getCurrentInstance": "javax.faces.context.FacesContext",
    "FacesContext.getExternalContext": "javax.faces.context.ExternalContext",
    "FacesContext.getApplication": "javax.faces.application.Application",
    "ExternalContext.getRequestParameterMap": "java.util.Map",
    "ExternalContext.getRequestHeaderMap": "java.util.Map",
    "ExternalContext.getRequestCookieMap": "java.util.Map",
    "ActionContext.getParameters": "java.util.Map",
    # JAX-RS
    "UriInfo.getQueryParameters": "javax.ws.rs.core.MultivaluedMap",
    "UriInfo.getPathParameters": "javax.ws.rs.core.MultivaluedMap",
    "HttpHeaders.getRequestHeaders": "javax.ws.rs.core.MultivaluedMap",
    # Micronaut
    "HttpRequest.getParameters": "io.micronaut.http.HttpParameters",
    "HttpRequest.getHeaders": "io.micronaut.http.HttpHeaders",
    "HttpRequest.getCookies": "io.micronaut.http.cookie.Cookies",
    # Vert.x
    "HttpServerRequest.params": "io.vertx.core.MultiMap",
    "HttpServerRequest.headers": "io.vertx.core.MultiMap",
    "RoutingContext.queryParams": "io.vertx.core.MultiMap",
    "RoutingContext.queryParam": "java.util.List",
    "Pool.query": "io.vertx.sqlclient.Query",
    "Pool.preparedQuery": "io.vertx.sqlclient.PreparedQuery",
    "PgPool.query": "io.vertx.sqlclient.Query",
    "PgPool.preparedQuery": "io.vertx.sqlclient.PreparedQuery",
    "SqlClient.query": "io.vertx.sqlclient.Query",
    "SqlClient.preparedQuery": "io.vertx.sqlclient.PreparedQuery",
    "SqlConnection.query": "io.vertx.sqlclient.Query",
    "SqlConnection.preparedQuery": "io.vertx.sqlclient.PreparedQuery",
    "RoutingContext.pathParams": "java.util.Map",
    "RoutingContext.body": "io.vertx.ext.web.RequestBody",
    "RoutingContext.request": "io.vertx.core.http.HttpServerRequest",
    "RoutingContext.response": "io.vertx.core.http.HttpServerResponse",
    "HttpServerResponse.putHeader": "io.vertx.core.http.HttpServerResponse",
    "HttpServerResponse.setStatusCode": "io.vertx.core.http.HttpServerResponse",
    "HttpServerResponse.setChunked": "io.vertx.core.http.HttpServerResponse",
    "HttpServerResponse.setStatusMessage": "io.vertx.core.http.HttpServerResponse",
    # Servlet / Spring
    "HttpServletRequest.getSession": "javax.servlet.http.HttpSession",
    "HttpServletRequest.getInputStream": "javax.servlet.ServletInputStream",
    "HttpServletRequest.getReader": "java.io.BufferedReader",
    "BufferedReader.lines": "java.util.stream.Stream",
    "RequestContextHolder.currentRequestAttributes": "org.springframework.web.context.request.ServletRequestAttributes",
    "ServletRequestAttributes.getRequest": "javax.servlet.http.HttpServletRequest",
    # JPA / Hibernate
    "EntityManager.createQuery": "javax.persistence.Query",
    "EntityManager.createNativeQuery": "javax.persistence.Query",
    "SessionFactory.getCurrentSession": "org.hibernate.Session",
    "SessionFactory.openSession": "org.hibernate.Session",
    "Session.createCriteria": "org.hibernate.Criteria",
    "Session.createQuery": "org.hibernate.query.Query",
    "Session.createSQLQuery": "org.hibernate.query.Query",
    "Session.createNativeQuery": "org.hibernate.query.Query",
    # Play
    "Http.Request.body": "play.mvc.Http.RequestBody",
    "Request.body": "play.mvc.Http.RequestBody",
    "RequestBody.asJson": "com.fasterxml.jackson.databind.JsonNode",
    "Http.RequestBody.asJson": "com.fasterxml.jackson.databind.JsonNode",
    "JsonNode.get": "com.fasterxml.jackson.databind.JsonNode",
    "JsonNode.path": "com.fasterxml.jackson.databind.JsonNode",
    # java.net.http
    "HttpRequest.newBuilder": "java.net.http.HttpRequest.Builder",
    # jOOQ
    "DSL.using": "org.jooq.DSLContext",
    # JDK
    "Runtime.getRuntime": "java.lang.Runtime",
}

# Lambdas passed to a framework's route / handler registration receive the framework's request
# objects, but are written without parameter types (`get("/x", (req, res) -> ...)`). Each row:
# (import prefixes of which the file must have one, regex over the registration call's text,
# the qualified parameter types in order). The frontend gives the lambda's parameters these types.
_HTTP_VERBS = r"get|post|put|delete|patch|head|options|trace|all|before|after|afterAfter|beforeMatched|afterMatched"
JAVA_LAMBDA_PARAMS = [
    (("spark.",), rf"(^|\.)({_HTTP_VERBS}|notFound|internalServerError|exception)$",
     ("spark.Request", "spark.Response")),
    (("io.javalin",), rf"(^|\.)({_HTTP_VERBS}|error|exception|sse)$", ("io.javalin.http.Context",)),
    (("io.jooby",), rf"(^|\.)({_HTTP_VERBS}|decorator)$", ("io.jooby.Context",)),
    (("io.vertx.ext.web",), r"\.(handler|blockingHandler|failureHandler)$", ("io.vertx.ext.web.RoutingContext",)),
    (("ratpack.",), rf"(^|\.)({_HTTP_VERBS}|path|prefix|handler|insert)$", ("ratpack.handling.Context",)),
    (("org.springframework.web.reactive.function.server",),
     r"(^|\.)(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS|route|andRoute|nest)$",
     ("org.springframework.web.reactive.function.server.ServerRequest",)),
]

# `javax.*` packages that moved to `jakarta.*` (Jakarta EE 9+): a file that imports from jakarta
# gets the jakarta spelling of the types above.
JAKARTA_MIGRATED = ("javax.servlet", "javax.faces", "javax.persistence", "javax.ws", "javax.el",
                    "javax.inject", "javax.enterprise", "javax.validation", "javax.websocket")


def type_spec_receivers(type_name: str) -> tuple:
    """Spec receiver names under which a call on a `type_name` value is looked
    up: the type itself, its decapitalised form (DocumentBuilder ->
    documentBuilder, SAXParser -> saxParser, URL -> url) and any alias."""
    upper = len(type_name) - len(type_name.lstrip("ABCDEFGHIJKLMNOPQRSTUVWXYZ"))
    if upper == len(type_name):
        decap = type_name.lower()
    elif upper > 1:
        decap = type_name[:upper - 1].lower() + type_name[upper - 1:]
    else:
        decap = type_name[:1].lower() + type_name[1:]
    return (type_name, decap) + JAVA_TYPE_RECEIVERS.get(type_name, ())


# Library verifier objects documented to accept every host; passing one where
# a verifier is expected is as permissive as `(host, session) -> true`.
PERMISSIVE_VERIFIERS = frozenset({
    "NoopHostnameVerifier", "NoopHostnameVerifier.INSTANCE",
    "AllowAllHostnameVerifier",
    "ALLOW_ALL_HOSTNAME_VERIFIER", "SSLSocketFactory.ALLOW_ALL_HOSTNAME_VERIFIER",
})
