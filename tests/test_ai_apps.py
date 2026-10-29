"""AI application security: model output as a source (OWASP LLM05), system instructions as a
prompt-injection sink (CWE-1427, OWASP LLM01), MCP tool arguments as model output. The framework
exemplars (benchmarks/exemplars/frameworks/*/llm-sdks, */mcp-servers) cover the packs end to
end; these pin the engine rules around them."""

import pytest

from frame.sil.packs.apply import bound_names
from frame.sil.scanner import FrameScanner


def findings(code, language="python", name="app"):
    r = FrameScanner(language=language).scan(code, name)
    return {(v.type.value, v.line, v.category) for v in r.vulnerabilities}


@pytest.mark.parametrize("param,names", [
    ("{ path }", ["path"]), ("{ path, depth = 2 }", ["path", "depth"]),
    ("{ opts: { depth }, ...rest }", ["depth", "rest"]), ("[a, b = 1]", ["a", "b"]),
    ("{ a: alias }", ["alias"]), ("req", ["req"])])
def test_names_a_destructuring_parameter_binds(param, names):
    assert bound_names(param) == names


def test_model_output_is_attacker_data_at_injection_sinks_not_at_logs():
    code = ("import logging, sqlite3\nfrom openai import OpenAI\nclient = OpenAI()\ndb = sqlite3.connect('x')\n\n"
            "def f(q):\n"
            "    out = client.chat.completions.create(model='m', messages=[]).choices[0].message.content\n"
            "    logging.info('model said %s', out)\n"
            "    db.execute(\"SELECT * FROM t WHERE name = '\" + out + \"'\")\n")
    got = findings(code)
    assert ("sql_injection", 9, "ai") in got
    assert not any(t in ("sensitive_data_logged", "log_injection") and line == 8 for t, line, _ in got)


def test_a_user_turn_is_not_prompt_injection():
    code = ("import anthropic\nfrom flask import Flask, request\napp = Flask(__name__)\nc = anthropic.Anthropic()\n\n"
            "@app.post('/c')\ndef chat():\n"
            "    m = c.messages.create(model='m', max_tokens=9, system='Be brief.',\n"
            "                          messages=[{'role': 'user', 'content': request.json['q']}])\n"
            "    return {'a': m.content[0].text}\n")
    assert not any(t == "prompt_injection" for t, _, _ in findings(code))


def test_a_js_name_declared_twice_is_not_bound_to_the_sdk():
    code = ("const OpenAI = require('openai');\nconst { execSync } = require('child_process');\n"
            "const client = new OpenAI();\n"
            "function other() { const client = makeOther(); execSync(client.chat.completions.create({}).x); }\n")
    assert not any(t == "command_injection" for t, _, _ in findings(code, "javascript", "a.js"))


def test_twilio_messages_create_is_not_a_model_call():
    code = ("const twilio = require('twilio');\nconst { execSync } = require('child_process');\n"
            "const client = twilio('sid', 'token');\n"
            "async function f() { const m = await client.messages.create({ body: 'hi', to: '+1', from: '+2' });\n"
            "  execSync(m.sid); }\n")
    assert not any(t == "command_injection" for t, _, _ in findings(code, "javascript", "t.js"))


PY_CHAT = '''from flask import Flask, request
from openai import OpenAI

app = Flask(__name__)
client = OpenAI()


@app.get("/a")
def a():
    tone = request.args.get("tone")
    messages = [{"role": "%s", "content": f"Answer in a {tone} tone."},
                {"role": "user", "content": request.args.get("q")}]
    return client.chat.completions.create(model="m", messages=messages).choices[0].message.content
'''


@pytest.mark.parametrize("role,expected", [("system", 1), ("developer", 1), ("user", 0), ("assistant", 0)])
def test_a_role_content_system_message_is_the_system_prompt(role, expected):
    """`{"role": "system", "content": x}` in a messages list (the OpenAI chat format), wherever the
    list is built: x is the system prompt. A user or assistant turn is not."""
    got = [line for t, line, _ in findings(PY_CHAT % role) if t == "prompt_injection"]
    assert got == [11] * expected


def test_a_role_that_is_not_a_literal_is_not_assumed_to_be_system():
    code = PY_CHAT.replace('"role": "%s"', '"role": request.args.get("role")')
    assert not any(t == "prompt_injection" for t, _, _ in findings(code))


def test_a_system_message_dict_outside_an_llm_app_is_not_a_finding():
    """No LLM SDK imported: the pack is not applied, so a role/content dict is only data."""
    code = (PY_CHAT % "system").replace("from openai import OpenAI\n", "").replace("client = OpenAI()\n", "client = None\n")
    assert not any(t == "prompt_injection" for t, _, _ in findings(code))


def test_a_system_message_object_in_javascript():
    code = '''const express = require("express");
const OpenAI = require("openai");
const app = express();
const client = new OpenAI();
app.get("/a", async (req, res) => {
  const r = await client.chat.completions.create({ model: "m", messages: [
    { role: "system", content: "Reply as " + req.query.persona },
    { role: "user", content: req.query.q }] });
  res.json({ ok: r.id });
});
'''
    assert [line for t, line, _ in findings(code, "javascript", "a.js") if t == "prompt_injection"] == [7]
    fixed = code.replace('"Reply as " + req.query.persona', '"Reply politely."')
    assert not any(t == "prompt_injection" for t, _, _ in findings(fixed, "javascript", "a.js"))


# -- indirect prompt injection: retrieved documents and MCP tool results (llm-context packs) -----

_RAG = ("import logging, sqlite3\nimport anthropic\nfrom langchain_chroma import Chroma\n"
        "c = anthropic.Anthropic()\nstore = Chroma()\ndb = sqlite3.connect('x')\n\n"
        "def f(q):\n    docs = store.similarity_search(q)\n    text = docs[0].page_content\n")


def test_a_retrieved_document_in_the_system_prompt_is_indirect_injection():
    code = _RAG + "    return c.messages.create(model='m', max_tokens=9, system='Notes: ' + text, messages=[])\n"
    assert ("prompt_injection", 11, "ai") in findings(code)


def test_a_retrieved_document_in_a_user_turn_or_a_log_is_not_reported():
    code = _RAG + ("    logging.info('retrieved %s', text)\n"
                   "    return c.messages.create(model='m', max_tokens=9, system='Answer from the notes.',\n"
                   "                             messages=[{'role': 'user', 'content': text + q}])\n")
    assert findings(code) == set()


def test_a_retrieved_document_is_attacker_data_at_injection_sinks():
    code = _RAG + "    db.execute(\"SELECT * FROM t WHERE tag = '\" + text + \"'\")\n"
    assert ("sql_injection", 11, "ai") in findings(code)


def test_without_a_retrieval_library_the_method_name_means_nothing():
    """The llm-context pack applies only to files importing LangChain or MCP."""
    code = ("import anthropic\nc = anthropic.Anthropic()\n\ndef f(index, q):\n"
            "    hits = index.similarity_search(q)\n"
            "    return c.messages.create(model='m', max_tokens=9, system='Notes: ' + hits[0], messages=[])\n")
    assert findings(code) == set()


def test_an_mcp_tool_result_is_attacker_data():
    code = ("import os\nfrom mcp import ClientSession\n\n"
            "async def f(session: ClientSession):\n"
            "    r = await session.call_tool('pick', {})\n"
            "    os.system('ls ' + r.content[0].text)\n")
    assert ("command_injection", 6, "ai") in findings(code)


@pytest.mark.parametrize("stmt", [
    "const s = new SystemMessage('Notes: ' + text); return llm.invoke([s]);",
    "return llm.invoke([new SystemMessage('Notes: ' + text), new HumanMessage(q)]);",
])
def test_js_a_retrieved_document_in_a_system_message(stmt):
    code = ("import { SystemMessage, HumanMessage } from '@langchain/core/messages';\n"
            "import { ChatOpenAI } from '@langchain/openai';\nconst llm = new ChatOpenAI();\n"
            "export async function f(store, q) {\n  const docs = await store.similaritySearch(q);\n"
            "  const text = docs[0].pageContent;\n  " + stmt + "\n}\n")
    assert ("prompt_injection", 7, "ai") in findings(code, "javascript", "app.mjs")
