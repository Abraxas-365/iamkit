// Seeds a disposable IAMKit for the parity journeys through the
// management API, then prints the fixture JSON (ids, users, the OAuth
// client). Usage: IAMKIT_URL=… MGMT=… APP_URL=… node e2e/seed.mjs > fixture.json
const base = process.env.IAMKIT_URL.replace(/\/$/, "");
const key = process.env.MGMT;
const app = process.env.APP_URL.replace(/\/$/, "");

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

const password = "Parity-password-2026!";
const project = id(await call("POST", "/projects", { name: "Custom UI parity" }));
const environment = id(await call("POST", `/projects/${project}/environments`, { name: "Parity" }));
const E = `/environments/${environment}`;

const organization = id(await call("POST", `${E}/organizations`, { name: "Acme" }));
const secure = id(await call("POST", `${E}/organizations`, { name: "Secure" }));
await call("PATCH", `${E}/organizations/${secure}`, { mfa_required: true });

const application = id(await call("POST", `${E}/applications`, { name: "Invoices", redirect_uris: [`${app}/callback`] }));
const resource = id(
  await call("POST", `${E}/resources`, { name: "Invoices API", prefix: "invoices", audience: "https://api.parity.example", permissions: ["invoices:read"] }),
);
await call("POST", `${E}/application-resources`, { application_id: application, resource_id: resource });
const reader = id(await call("POST", `${E}/roles`, { name: "reader", resource_id: resource, permissions: ["invoices:read"] }));
const customers = id(await call("POST", `${E}/organizations/${organization}/groups`, { name: "Customers" }));
await call("POST", `${E}/group-role-assignments`, { role_id: reader, organization_id: organization, group_id: customers });

const client = await call("POST", `${E}/oauth-clients`, {
  application_id: application,
  resource_id: resource,
  redirect_uris: [`${app}/callback`],
  public: true,
  allowed_origins: [app],
});
const clientId = id(client);

// Sign-up into Acme's Customers group; every first-factor method on.
await call("PUT", `${E}/sign-in-policy`, {
  allow_password: true,
  allow_email_code: true,
  allow_social: true,
  allow_password_reset: true,
  allow_signup: true,
  signup_organization_id: organization,
  signup_group_id: customers,
});

// The client's own wording, served with the ticket (hosted texts).
await call("PUT", `${E}/login-settings/clients/${clientId}/texts/en`, { texts: { "hosted.title.sign_in": "Sign in to Invoices" } });

async function user(name, email, organizations) {
  // otp_enabled: emailed sign-in codes are opt-in per user.
  const u = id(await call("POST", `${E}/users`, { name, email, password, otp_enabled: true }));
  for (const o of organizations) {
    await call("POST", `${E}/memberships`, { organization_id: o, user_id: u });
    await call("PUT", `${E}/grants`, { organization_id: o, user_id: u, resource_id: resource, permissions: ["invoices:read"] });
  }
  return { id: u, email };
}

const fixture = {
  environment,
  organization,
  secure,
  application,
  resource,
  clientId,
  password,
  alice: await user("Alice", "alice@parity.example", [organization]),
  reset: await user("Riley", "riley@parity.example", [organization]),
  coder: await user("Casey", "casey@parity.example", [organization]),
  mfa: await user("Morgan", "morgan@parity.example", [secure]),
};
const invited = await call("POST", `${E}/organizations/${organization}/invitations`, { email: "ivy@parity.example" });
fixture.invitation = { token: invited.token, email: "ivy@parity.example" };
process.stdout.write(JSON.stringify(fixture, null, 2));
