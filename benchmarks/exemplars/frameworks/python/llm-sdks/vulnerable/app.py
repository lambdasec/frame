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


@app.post("/chat")
def chat():
    persona = request.json["persona"]
    msg = claude.messages.create(model="claude-sonnet", max_tokens=300, system=f"You are {persona}.",  # frame-expect: CWE-1427
                                 messages=[{"role": "user", "content": request.json["q"]}])
    return {"answer": msg.content[0].text}


@app.post("/ops")
def ops():
    resp = gpt.chat.completions.create(model="gpt-4o", messages=[{"role": "user", "content": request.json["task"]}])
    command = resp.choices[0].message.content
    subprocess.run(command, shell=True)  # frame-expect: CWE-78
    return {"ok": True}


@app.get("/rules")
def rules():
    custom = request.args.get("rules", "")
    reply = llm.invoke([SystemMessage(content="Follow these rules: " + custom),  # frame-expect: CWE-1427
                        HumanMessage(content=request.args.get("q", ""))])
    exec(reply.content)  # frame-expect: CWE-94
    return "ok"
