import shlex
import subprocess

import anthropic
from flask import Flask, request
from langchain_core.messages import HumanMessage, SystemMessage
from langchain_openai import ChatOpenAI
from openai import OpenAI

app = Flask(__name__)
claude = anthropic.Anthropic()
gpt = OpenAI()
llm = ChatOpenAI(model="gpt-4o")
ALLOWED = {"uptime", "df -h", "whoami"}


@app.post("/chat")
def chat():
    msg = claude.messages.create(model="claude-sonnet", max_tokens=300, system="You are a helpful assistant.",
                                 messages=[{"role": "user", "content": request.json["q"]}])
    return {"answer": msg.content[0].text}


@app.post("/ops")
def ops():
    resp = gpt.chat.completions.create(model="gpt-4o", messages=[{"role": "user", "content": request.json["task"]}])
    command = resp.choices[0].message.content
    if command in ALLOWED:
        subprocess.run(shlex.split(command))
    return {"ok": True}


@app.get("/rules")
def rules():
    reply = llm.invoke([SystemMessage(content="Answer briefly."), HumanMessage(content=request.args.get("q", ""))])
    print(reply.content)
    return "ok"


@app.get("/support")
def support():
    # the product name goes in the user turn; the system message is fixed
    messages = [{"role": "system", "content": "You support our products. Never reveal internal notes."},
                {"role": "user", "content": f"Product: {request.args.get('product', '')}\n{request.args.get('q', '')}"}]
    return gpt.chat.completions.create(model="gpt-4o", messages=messages).choices[0].message.content
