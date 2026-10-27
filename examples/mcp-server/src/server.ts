// A remote MCP server (Streamable HTTP, stateless) protected by IAMKit.
//
// IAMKit is the OAuth 2.1 authorization server: the server publishes its
// protected resource metadata (RFC 9728), accepts only access tokens issued
// for its URL (RFC 8707 aud) and asks for more scope with a 403
// insufficient_scope challenge when a tool needs it. Scopes are the IAMKit
// permissions of the resource: notes:read and notes:write.
import express from "express";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { createKeySet } from "@iamkit/node";
import { createResourceServer, resourceClaimsOf, ResourceError, type ResourceClaims } from "@iamkit/node/resource-server";
import { z } from "zod";
import { scopesFor } from "./scopes.js";

const env = (name: string, fallback?: string) => {
  const value = process.env[name] ?? fallback;
  if (!value) throw new Error(`${name} is required`);
  return value;
};

const issuer = env("IAMKIT_ISSUER");
const resourceUrl = env("MCP_RESOURCE_URL", "http://localhost:3333/mcp");
const port = Number(env("PORT", "3333"));

const rs = createResourceServer({
  issuer,
  resource: resourceUrl,
  environmentId: env("IAMKIT_ENVIRONMENT_ID"),
  // The scopes a client asks for first (the protected resource's
  // default_scopes): notes:write comes later, by step-up.
  scopesSupported: ["notes:read"],
  resourceName: "IAMKit notes (example MCP server)",
  // Where this server reaches IAMKit's keys, when it differs from the issuer.
  keys: process.env.IAMKIT_JWKS_URL ? createKeySet({ jwksUrl: process.env.IAMKIT_JWKS_URL }) : undefined,
});

// Notes per organization: what a user sees follows the token's tenant.
const notes = new Map<string, { by: string; text: string; at: string }[]>();

function mcpServer(claims: ResourceClaims): McpServer {
  const server = new McpServer({ name: "iamkit-notes", version: "0.1.0" });
  server.registerTool(
    "list_notes",
    { description: "List the notes of your organization (scope notes:read)" },
    async () => {
      const list = notes.get(claims.organizationId) ?? [];
      const text = list.length ? list.map((n) => `- ${n.text} (${n.by}, ${n.at})`).join("\n") : "No notes yet.";
      return { content: [{ type: "text", text }] };
    },
  );
  server.registerTool(
    "add_note",
    { description: "Add a note to your organization (scope notes:write)", inputSchema: { text: z.string().min(1).max(500) } },
    async ({ text }) => {
      const list = notes.get(claims.organizationId) ?? [];
      list.push({ by: claims.sub, text, at: new Date().toISOString() });
      notes.set(claims.organizationId, list);
      return { content: [{ type: "text", text: `Added. ${list.length} note(s) now.` }] };
    },
  );
  server.registerTool(
    "whoami",
    { description: "Show the token's subject, organization and scopes" },
    async () => ({
      content: [{ type: "text", text: JSON.stringify({ user: claims.sub, organization: claims.organizationId, client: claims.oauthClientId, scopes: claims.scopes }, null, 2) }],
    }),
  );
  return server;
}

const app = express();
// RFC 9728 metadata at /.well-known/oauth-protected-resource/mcp and the root.
app.use(rs.metadataHandler());
app.get("/health", (_req, res) => {
  res.json({ ok: true });
});

app.post("/mcp", rs.protect(), express.json({ limit: "1mb" }), async (req, res) => {
  const claims = resourceClaimsOf(req)!;
  // Step-up: a tool needing more scope answers 403 insufficient_scope; the
  // client authorizes again with the scope of the challenge.
  try {
    rs.require(claims, ...scopesFor(req.body));
  } catch (error) {
    if (error instanceof ResourceError) {
      rs.deny(res, error);
      return;
    }
    throw error;
  }
  const server = mcpServer(claims);
  const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined });
  res.on("close", () => {
    void transport.close();
    void server.close();
  });
  await server.connect(transport);
  await transport.handleRequest(req, res, req.body);
});

// Stateless server: no GET stream, no session to delete.
app.all("/mcp", rs.protect(), (_req, res) => {
  res.status(405).set("Allow", "POST").json({ jsonrpc: "2.0", error: { code: -32000, message: "Method not allowed" }, id: null });
});

app.listen(port, "127.0.0.1", () => {
  console.log(`MCP server ${rs.resource} (metadata ${rs.metadataUrl}) on http://127.0.0.1:${port}`);
});
