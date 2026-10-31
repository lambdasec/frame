import Anthropic from "@anthropic-ai/sdk";
import { SystemMessage, HumanMessage } from "@langchain/core/messages";
import { ChatOpenAI } from "@langchain/openai";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { MemoryVectorStore } from "langchain/vectorstores/memory";
import { OpenAIEmbeddings } from "@langchain/openai";
import { exec } from "node:child_process";

const anthropic = new Anthropic();
const llm = new ChatOpenAI({ model: "gpt-4o-mini" });
const client = new Client({ name: "archiver", version: "1.0.0" });
const store = new MemoryVectorStore(new OpenAIEmbeddings());
const retriever = store.asRetriever();

export async function answer(question) {
  const docs = await store.similaritySearch(question, 4);
  const context = docs[0].pageContent;
  return anthropic.messages.create({   // frame-expect: CWE-1427
    model: "claude-sonnet-4-5",
    max_tokens: 512,
    system: "Answer using these support tickets:\n" + context,
    messages: [{ role: "user", content: question }],
  });
}

export async function summarize(question) {
  const docs = await retriever.invoke(question);
  const notes = docs[0].pageContent;
  return llm.invoke([new SystemMessage("You may use these notes: " + notes), new HumanMessage(question)]);   // frame-expect: CWE-1427
}

export async function archive() {
  const result = await client.callTool({ name: "pick_folder", arguments: { under: "/srv/exports" } });
  const folder = result.content[0].text;
  exec("tar czf /tmp/out.tgz " + folder);   // frame-expect: CWE-78
}
