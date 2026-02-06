/**
 * MCP Server for Adding Comments to Microsoft Sentinel Incidents
 * 
 * This server provides a secure way to add comments to Sentinel incidents
 * via a Logic App webhook. The webhook URL is stored securely in an
 * environment variable.
 * 
 * Environment Variables:
 *   SENTINEL_COMMENT_WEBHOOK_URL - The Logic App webhook URL (required)
 */
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";

// Schema for the input parameters
const AddCommentInputSchema = z.object({
  incidentId: z.string().describe("The Microsoft Sentinel incident ID (e.g., '12345' or full ARM resource ID)"),
  message: z.string().describe("The comment message to add. Supports plain text or HTML formatting."),
});

// Schema for the output
const AddCommentOutputSchema = z.object({
  status: z.enum(["success", "error"]),
  message: z.string(),
  incidentId: z.string(),
  commentId: z.string().optional(),
  error: z.any().optional(),
});

export function createServer(): McpServer {
  const server = new McpServer({
    name: "Sentinel Incident Comment Server",
    version: "1.0.0",
  });

  // Register the add-comment tool
  server.tool(
    "add_comment_to_sentinel_incident",
    "Adds a comment to a Microsoft Sentinel incident. The comment can be plain text or HTML formatted. " +
    "Use this to document investigation findings, add notes, or communicate with other analysts working on the incident.",
    AddCommentInputSchema.shape,
    async ({ incidentId, message }) => {
      const webhookUrl = process.env.SENTINEL_COMMENT_WEBHOOK_URL;

      if (!webhookUrl) {
        return {
          content: [
            {
              type: "text",
              text: JSON.stringify({
                status: "error",
                message: "SENTINEL_COMMENT_WEBHOOK_URL environment variable is not set",
                incidentId,
              }, null, 2),
            },
          ],
          isError: true,
        };
      }

      try {
        const response = await fetch(webhookUrl, {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
          },
          body: JSON.stringify({
            incidentId,
            message,
          }),
        });

        const responseText = await response.text();
        let responseData: any;

        try {
          responseData = JSON.parse(responseText);
        } catch {
          responseData = { rawResponse: responseText };
        }

        if (response.ok) {
          return {
            content: [
              {
                type: "text",
                text: `✅ Comment added to incident ${incidentId}\n\n${JSON.stringify(responseData, null, 2)}`,
              },
            ],
          };
        } else {
          return {
            content: [
              {
                type: "text",
                text: `❌ Failed to add comment to incident ${incidentId}\n\nStatus: ${response.status} ${response.statusText}\n\n${JSON.stringify(responseData, null, 2)}`,
              },
            ],
            isError: true,
          };
        }
      } catch (error) {
        const errorMessage = error instanceof Error ? error.message : String(error);
        return {
          content: [
            {
              type: "text",
              text: `❌ Error calling Logic App webhook: ${errorMessage}`,
            },
          ],
          isError: true,
        };
      }
    }
  );

  return server;
}
