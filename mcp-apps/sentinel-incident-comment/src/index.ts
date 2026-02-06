/**
 * Entry point for the Sentinel Incident Comment MCP Server
 * 
 * Usage:
 *   SENTINEL_COMMENT_WEBHOOK_URL=<url> node dist/index.js --stdio
 *   SENTINEL_COMMENT_WEBHOOK_URL=<url> node dist/index.js --http
 */
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { createServer } from "./server.js";

async function main() {
  // Validate environment
  if (!process.env.SENTINEL_COMMENT_WEBHOOK_URL) {
    console.error("Warning: SENTINEL_COMMENT_WEBHOOK_URL environment variable is not set.");
    console.error("The server will start but the tool will fail until this is configured.");
  }

  const server = createServer();
  const transport = new StdioServerTransport();
  await server.connect(transport);
  console.error("Sentinel Incident Comment MCP Server running on stdio");
}

main().catch((error) => {
  console.error("Failed to start server:", error);
  process.exit(1);
});
