// The scope each tool needs, and the scopes a JSON-RPC request needs
// beyond a valid token (checked before the MCP transport runs, so a
// missing one answers 403 insufficient_scope and the client steps up).

export const toolScopes: Record<string, string> = {
  list_notes: "notes:read",
  add_note: "notes:write",
};

/** The scopes a JSON-RPC message (or batch) needs. */
export function scopesFor(body: unknown): string[] {
  const messages = Array.isArray(body) ? body : [body];
  const out = new Set<string>();
  for (const m of messages) {
    const msg = m as { method?: unknown; params?: { name?: unknown } } | null;
    const name = msg?.method === "tools/call" ? msg.params?.name : undefined;
    if (typeof name === "string" && Object.hasOwn(toolScopes, name)) {
      out.add(toolScopes[name]!);
    }
  }
  return [...out];
}
