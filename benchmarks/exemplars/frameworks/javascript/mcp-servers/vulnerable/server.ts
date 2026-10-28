import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { execSync } from "child_process";

const server = new McpServer({ name: "ops", version: "1.0.0" });

server.tool("disk_usage", { path: z.string() }, async ({ path }) => {
  return { content: [{ type: "text", text: execSync(`du -sh ${path}`).toString() }] }; // frame-expect: CWE-78
});

server.registerTool("grep_logs", { inputSchema: { pattern: z.string() } }, async ({ pattern }) => {
  return { content: [{ type: "text", text: execSync("grep " + pattern + " /var/log/app.log").toString() }] }; // frame-expect: CWE-78
});
