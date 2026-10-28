const { execSync } = require("child_process");
const express = require("express");
const OpenAI = require("openai");
const Anthropic = require("@anthropic-ai/sdk");

const app = express();
app.use(express.json());
const gpt = new OpenAI();
const claude = new Anthropic();

app.post("/chat", async (req, res) => {
  const msg = await claude.messages.create({ model: "claude-sonnet", max_tokens: 300, system: `You are ${req.body.persona}`, // frame-expect: CWE-1427
                                             messages: [{ role: "user", content: req.body.q }] });
  res.json({ answer: msg.content[0].text });
});

app.post("/ops", async (req, res) => {
  const resp = await gpt.chat.completions.create({ model: "gpt-4o", messages: [{ role: "user", content: req.body.task }] });
  execSync(resp.choices[0].message.content); // frame-expect: CWE-78
  res.json({ ok: true });
});
