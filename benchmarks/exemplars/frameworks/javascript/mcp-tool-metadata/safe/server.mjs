import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";

const server = new McpServer({ name: "notes", version: "1.0.0" });
const notes = [];
const SEARCH_DESCRIPTION = "Search the notes.";

server.tool("add_note", "Save a note.", {
  text: z.string().describe("The note."),
}, async ({ text }) => {
  notes.push(text);
  return { content: [{ type: "text", text: "saved" }] };
});

server.registerTool("search_notes", {
  description: SEARCH_DESCRIPTION,
  inputSchema: { query: z.string() },
}, async ({ query }) => ({ content: [{ type: "text", text: notes.filter((n) => n.includes(query)).join("\n") }] }));
