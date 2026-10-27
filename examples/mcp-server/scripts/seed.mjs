// Seeds a disposable IAMKit for the example MCP server through the
// management API and prints the fixture JSON.
// Usage: IAMKIT_URL=… MGMT=… MCP_RESOURCE_URL=… node scripts/seed.mjs > fixture.json
const base = process.env.IAMKIT_URL.replace(/\/$/, "");
const key = process.env.MGMT;
const resourceUrl = process.env.MCP_RESOURCE_URL;

async function call(method, path, body) {
  const res = await fetch(`${base}/management/v1${path}`, {
    method,
    headers: { "X-API-Key": key, "Content-Type": "application/json" },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const text = await res.text();
  if (!res.ok) throw new Error(`${method} ${path}: ${res.status} ${text}`);
  return text && res.headers.get("content-type")?.includes("json") ? JSON.parse(text) : undefined;
}
const id = (r) => r.id ?? r.client_id;

const password = "Mcp-example-password-2026!";
const project = id(await call("POST", "/projects", { name: "MCP example" }));
const environment = id(await call("POST", `/projects/${project}/environments`, { name: "Development" }));
const E = `/environments/${environment}`;
const organization = id(await call("POST", `${E}/organizations`, { name: "Acme" }));

// The MCP server is a resource whose audience is its URL, with one
// permission per scope, registered as a protected resource of the
// application its clients belong to.
const application = id(await call("POST", `${E}/applications`, { name: "Notes MCP" }));
const resource = id(
  await call("POST", `${E}/resources`, { name: "Notes MCP server", prefix: "notes", audience: resourceUrl, permissions: ["notes:read", "notes:write"] }),
);
await call("POST", `${E}/application-resources`, { application_id: application, resource_id: resource });
const protectedResource = id(
  await call("POST", `${E}/protected-resources`, { application_id: application, resource_id: resource, name: "Notes", default_scopes: ["notes:read"] }),
);

// Pre-registered public clients (phase a has no dynamic registration):
// MCP Inspector's default callback and a fixed Claude Code callback port.
const client = async (name, redirects) =>
  id(
    await call("POST", `${E}/oauth-clients`, {
      name,
      application_id: application,
      resource_id: resource,
      redirect_uris: redirects,
      public: true,
      hosted_login: true,
    }),
  );
const inspectorClientId = await client("MCP Inspector", ["http://127.0.0.1:6276/oauth/callback", "http://localhost:6274/oauth/callback"]);
const claudeClientId = await client("Claude Code", ["http://localhost:19876/callback", "http://127.0.0.1:19876/callback"]);

async function user(name, email, permissions) {
  const u = id(await call("POST", `${E}/users`, { name, email, password }));
  await call("POST", `${E}/memberships`, { organization_id: organization, user_id: u });
  await call("PUT", `${E}/grants`, { organization_id: organization, user_id: u, resource_id: resource, permissions });
  return u;
}
const reader = await user("Riley Reader", "reader@mcp.example", ["notes:read"]);
const writer = await user("Wren Writer", "writer@mcp.example", ["notes:read", "notes:write"]);

process.stdout.write(
  JSON.stringify(
    {
      environment,
      organization,
      application,
      resource,
      protectedResource,
      inspectorClientId,
      claudeClientId,
      reader,
      writer,
      email: "reader@mcp.example",
      writerEmail: "writer@mcp.example",
      password,
    },
    null,
    2,
  ),
);
