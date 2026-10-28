import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { execFileSync } from "child_process";

const server = new McpServer({ name: "ops", version: "1.0.0" });

server.tool("disk_usage", { path: z.string() }, async ({ path }) => {
  return { content: [{ type: "text", text: execFileSync("du", ["-sh", "--", path]).toString() }] };
});

server.registerTool("grep_logs", { inputSchema: { pattern: z.string() } }, async ({ pattern }) => {
  return { content: [{ type: "text", text: execFileSync("grep", ["--", pattern, "/var/log/app.log"]).toString() }] };
});
