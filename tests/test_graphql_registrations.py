"""GraphQL resolvers are the functions an application hands a server (`new ApolloServer({ resolvers })`,
`makeExecutableSchema`, ...), found by the value they are passed to, never by an object key
(`Query:`) or a variable's name (`resolvers`). The server's `context` function is an entry point
(its request), and what it returns is every resolver's third argument: the values (`ctx.db` a
pool) and the attacker data (`ctx.token` a header) of each field."""

import pytest

from frame.sil.scanner import FrameScanner

HEAD = """const { ApolloServer } = require('@apollo/server');
const { startStandaloneServer } = require('@apollo/server/standalone');
const mysql = require('mysql2/promise');
const pool = mysql.createPool({ host: 'db' });
"""


def _findings(code, name="server.js"):
    return sorted((v.line, v.cwe_id) for v in
                  FrameScanner(language="javascript", verify=False).scan(code, name).vulnerabilities)


def _dir(tmp_path, files):
    for name, text in files.items():
        (tmp_path / name).write_text(text)
    results = FrameScanner(verify=False).scan_directory(str(tmp_path), None)
    return sorted((r.filename.rsplit("/", 1)[-1], v.line, v.cwe_id) for r in results for v in r.vulnerabilities)


QUERY = "(parent, args) => pool.query(\"SELECT * FROM b WHERE a = '\" + args.author + \"'\")"


@pytest.mark.parametrize("decl", [
    "const server = new ApolloServer({ typeDefs: '', resolvers: { Query: { books: QUERY } } });",
    "const resolvers = { Query: { books: QUERY } };\nconst server = new ApolloServer({ typeDefs: '', resolvers });",
    "const r = { Query: { books: QUERY } };\nconst server = new ApolloServer({ typeDefs: '', resolvers: r });",
    "const a = { Query: { books: QUERY } };\nconst server = new ApolloServer({ typeDefs: '', resolvers: [a] });",
    "const a = { Query: { books: QUERY } };\nconst server = new ApolloServer({ typeDefs: '', resolvers: { ...a } });",
    "const server = new ApolloServer({ typeDefs: '', resolvers: { Query: { books: { resolve: QUERY } } } });",
])
def test_a_resolver_map_handed_to_the_server(decl):
    code = HEAD + decl.replace("QUERY", QUERY) + "\n"
    assert any(c == "CWE-89" for _, c in _findings(code))


@pytest.mark.parametrize("decl", [
    "const resolvers = { Query: { books: QUERY } };",                       # handed to nothing
    "const handlers = { Query: { books: QUERY } };\nregister(handlers);",   # not a GraphQL server
])
def test_an_object_shaped_like_a_resolver_map_is_not_one(decl):
    assert _findings(HEAD + decl.replace("QUERY", QUERY) + "\n") == []


def test_make_executable_schema_takes_resolvers():
    code = ("const { makeExecutableSchema } = require('@graphql-tools/schema');\n"
            "const { exec } = require('child_process');\n"
            "const schema = makeExecutableSchema({ typeDefs: '', resolvers: {\n"
            "  Mutation: { run: (_, { cmd }) => exec('x ' + cmd) },\n} });\n")
    assert _findings(code) == [(4, "CWE-78")]


def test_resolvers_from_another_module(tmp_path):
    found = _dir(tmp_path, {
        "resolvers.js": "const { exec } = require('child_process');\n"
                        "module.exports = { Mutation: { run: (_, args) => exec('x ' + args.cmd) } };\n",
        "unused.js": "const { exec } = require('child_process');\n"
                     "module.exports = { Mutation: { run: (_, args) => exec('x ' + args.cmd) } };\n",
        "server.js": "const { ApolloServer } = require('@apollo/server');\nconst resolvers = require('./resolvers');\n"
                     "const server = new ApolloServer({ typeDefs: '', resolvers });\n",
    })
    assert found == [("resolvers.js", 2, "CWE-78")]


CONTEXT = HEAD + """const resolvers = { Query: {
  byToken: (p, a, ctx) => ctx.db.query("SELECT * FROM s WHERE t = '" + ctx.token + "'"),
  byRole: (p, a, ctx) => ctx.db.query("SELECT * FROM s WHERE r = '" + ctx.role + "'"),
  mine: (p, a, { db, token }) => db.query("SELECT * FROM s WHERE t = '" + token + "'"),
} };
const server = new ApolloServer({ typeDefs: '', resolvers });
startStandaloneServer(server, { context: async ({ req }) => ({ db: pool, token: req.headers["x-tenant"], role: 'guest' }) });
"""


def test_the_context_function_returns_every_resolvers_third_argument():
    assert _findings(CONTEXT) == [(6, "CWE-89"), (8, "CWE-89")]


def test_apollo_3_context_option():
    code = CONTEXT.replace("const server = new ApolloServer({ typeDefs: '', resolvers });\n", "").replace(
        "startStandaloneServer(server, { context: async", "const server = new ApolloServer({ typeDefs: '', resolvers, context: async") \
        .replace("const { ApolloServer } = require('@apollo/server');", "const { ApolloServer } = require('apollo-server');")
    assert _findings(code) == [(6, "CWE-89"), (8, "CWE-89")]


def test_the_context_function_reads_the_request():
    code = HEAD + "const { exec } = require('child_process');\nconst server = new ApolloServer({ typeDefs: '', resolvers: {} });\n" \
                  "startStandaloneServer(server, { context: async ({ req }) => { exec('x ' + req.headers.host); return {}; } });\n"
    assert _findings(code) == [(7, "CWE-78")]


def test_a_context_of_another_server_does_not_reach_these_resolvers():
    code = CONTEXT.replace("startStandaloneServer(server,", "const other = new ApolloServer({ typeDefs: '', resolvers: {} });\n"
                                                            "startStandaloneServer(other,")
    assert [c for _, c in _findings(code)] == []
