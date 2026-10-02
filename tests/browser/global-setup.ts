// A disposable IAMKit for the browser journeys, started once per run:
//   - PostgreSQL and Mailpit (real SMTP) in testcontainers,
//   - IAMKit built from this checkout with the console embedded,
//   - a TLS proxy in this process (the issuer, __Host- and Secure cookies
//     need HTTPS), and a loopback receiver for action targets and webhooks.
// The stack is seeded through the management API; tests read the fixture
// from .stack/fixture.json. Set IAMKIT_BROWSER_BINARY to reuse a built
// binary (it must embed the console).
import { execFileSync, spawn, type ChildProcess } from "node:child_process";
import { createHash, randomBytes } from "node:crypto";
import { createWriteStream, cpSync, existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { createServer as createHTTP, request, type Server } from "node:http";
import { createServer as createHTTPS } from "node:https";
import type { AddressInfo } from "node:net";
import path from "node:path";
import { PostgreSqlContainer } from "@testcontainers/postgresql";
import { GenericContainer, Wait } from "testcontainers";
import type { Fixture } from "./fixture.js";

const here = import.meta.dirname;
const root = path.resolve(here, "../..");
const stack = path.join(here, ".stack");

const listen = (server: Server, port = 0) =>
  new Promise<number>((resolve) => server.listen(port, "127.0.0.1", () => resolve((server.address() as AddressInfo).port)));

async function freePort(): Promise<number> {
  const s = createHTTP();
  const port = await listen(s);
  await new Promise((r) => s.close(r));
  return port;
}

/** build compiles the console into the binary, leaving the tracked placeholders alone. */
function build(): string {
  if (process.env.IAMKIT_BROWSER_BINARY) return path.resolve(process.env.IAMKIT_BROWSER_BINARY);
  const frontend = path.join(root, "frontend");
  if (!existsSync(path.join(frontend, "node_modules"))) execFileSync("npm", ["ci"], { cwd: frontend, stdio: "inherit" });
  execFileSync("npm", ["run", "build"], { cwd: frontend, stdio: "inherit" });
  const dist = path.join(root, "internal/console/dist");
  for (const old of ["assets", "index.html", "favicon.svg"]) rmSync(path.join(dist, old), { recursive: true, force: true });
  cpSync(path.join(frontend, "dist"), dist, { recursive: true });
  const binary = path.join(stack, "iamkit");
  execFileSync("go", ["build", "-o", binary, "./cmd/iamkit"], { cwd: root, stdio: "inherit", env: { ...process.env, GOWORK: "off" } });
  return binary;
}

/** receiver answers action targets (deny users whose email starts with
 * "blocked") and records webhook deliveries. */
function receiver() {
  const calls: unknown[] = [];
  const hooks: unknown[] = [];
  const server = createHTTP((req, res) => {
    let body = "";
    req.on("data", (c) => (body += c));
    req.on("end", () => {
      if (req.method === "GET") {
        res.writeHead(200, { "content-type": "application/json" }).end(JSON.stringify(req.url === "/hooks" ? hooks : calls));
        return;
      }
      const parsed = body ? JSON.parse(body) : {};
      if (req.url === "/hook") {
        hooks.push({ headers: req.headers, body: parsed });
        res.writeHead(204).end();
        return;
      }
      calls.push(parsed);
      const email: string = parsed?.user?.email ?? "";
      const answer = email.startsWith("blocked") ? { deny: true, message: "Blocked by the browser-test action." } : {};
      res.writeHead(200, { "content-type": "application/json" }).end(JSON.stringify(answer));
    });
  });
  return server;
}

/** proxy terminates TLS for IAMKit at https://localhost:<port>. */
function proxy(upstream: number, cert: Buffer, key: Buffer) {
  return createHTTPS({ cert, key }, (req, res) => {
    const out = request({ host: "127.0.0.1", port: upstream, method: req.method, path: req.url, headers: req.headers }, (back) => {
      res.writeHead(back.statusCode ?? 502, back.headers);
      back.pipe(res);
    });
    out.on("error", () => res.writeHead(502).end());
    req.pipe(out);
  }) as unknown as Server;
}

async function waitFor(url: string, what: string, child: ChildProcess) {
  for (let i = 0; i < 120; i++) {
    if (child.exitCode !== null) throw new Error(`${what} exited (${child.exitCode}); see ${stack}/iamkit.log`);
    try {
      if ((await fetch(url)).ok) return;
    } catch {
      /* not yet */
    }
    await new Promise((r) => setTimeout(r, 500));
  }
  throw new Error(`${what} did not start; see ${stack}/iamkit.log`);
}

export default async function globalSetup() {
  rmSync(stack, { recursive: true, force: true });
  mkdirSync(stack, { recursive: true });
  const binary = build();

  const [db, mail] = await Promise.all([
    new PostgreSqlContainer("postgres:16-alpine").withDatabase("iamkit").withUsername("iamkit").withPassword(randomBytes(12).toString("hex")).start(),
    new GenericContainer("axllent/mailpit:v1.30.6").withExposedPorts(1025, 8025).withWaitStrategy(Wait.forHttp("/api/v1/info", 8025)).start(),
  ]);

  execFileSync("openssl", ["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1", "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1",
    "-keyout", path.join(stack, "tls.key"), "-out", path.join(stack, "tls.crt")], { stdio: "ignore" });
  execFileSync("openssl", ["genrsa", "-out", path.join(stack, "jwt.pem"), "2048"], { stdio: "ignore" });

  const hooks = receiver();
  const hooksPort = await listen(hooks);
  const iamPort = await freePort();
  const tls = proxy(iamPort, readFileSync(path.join(stack, "tls.crt")), readFileSync(path.join(stack, "tls.key")));
  const tlsPort = await listen(tls);
  const issuer = `https://localhost:${tlsPort}`;

  const bootstrapPassword = "Bootstrap-password-2026!";
  const operator = { email: "owner@browser.example", password: bootstrapPassword, newPassword: "Operator-password-2026!" };
  const log = createWriteStream(path.join(stack, "iamkit.log"));
  const child = spawn(binary, [], {
    env: {
      PATH: process.env.PATH,
      HOME: process.env.HOME,
      DATABASE_URL: `${db.getConnectionUri()}?sslmode=disable`,
      SERVER_PORT: String(iamPort),
      JWT_ISSUER: issuer,
      JWT_PRIVATE_KEY_PATH: path.join(stack, "jwt.pem"),
      OIDC_HMAC_SECRET: randomBytes(32).toString("hex"),
      IAMKIT_ENCRYPTION_KEY: randomBytes(32).toString("base64"),
      // Real SMTP: Mailpit on loopback (plaintext is allowed only there).
      EMAIL_PROVIDER: "smtp",
      SMTP_HOST: "127.0.0.1",
      SMTP_PORT: String(mail.getMappedPort(1025)),
      EMAIL_FROM: "no-reply@browser.example",
      EMAIL_FROM_NAME: "IAMKit browser tests",
      // Action targets and webhooks on the loopback receiver.
      IAMKIT_ALLOW_PRIVATE_DELIVERY: "true",
      // The console makes many calls per page; tests are one IP.
      RATE_LIMIT_PER_MINUTE: "100000",
      IAMKIT_BOOTSTRAP_EMAIL: operator.email,
      IAMKIT_BOOTSTRAP_WORKSPACE: "Browser tests",
      IAMKIT_BOOTSTRAP_PASSWORD: bootstrapPassword,
    },
    stdio: ["ignore", "pipe", "pipe"],
  });
  // A failed setup returns no teardown: never leave IAMKit running.
  process.once("exit", () => child.kill("SIGKILL"));
  let output = "";
  child.stdout!.on("data", (c) => { output += c; log.write(c); });
  child.stderr!.on("data", (c) => log.write(c));
  await waitFor(`http://127.0.0.1:${iamPort}/health`, "IAMKit", child);
  const key = output.match(/ik_mgmt_\S+/)?.[0];
  if (!key) throw new Error("no bootstrap management key in the IAMKit output");

  const fixture = await seed(`http://127.0.0.1:${iamPort}`, key);
  const full: Fixture = {
    ...fixture,
    issuer,
    operator,
    mailpit: `http://127.0.0.1:${mail.getMappedPort(8025)}`,
    receiver: `http://127.0.0.1:${hooksPort}`,
  };
  writeFileSync(path.join(stack, "fixture.json"), JSON.stringify(full, null, 2));

  return async () => {
    child.kill("SIGTERM");
    await new Promise((r) => (child.exitCode !== null ? r(null) : child.once("exit", r)));
    await Promise.all([new Promise((r) => tls.close(r)), new Promise((r) => hooks.close(r)), db.stop(), mail.stop()]);
  };
}

/** seed creates the hosted-login environment through the management API. */
async function seed(base: string, key: string) {
  async function call<T = Record<string, unknown>>(method: string, route: string, body?: unknown): Promise<T> {
    const res = await fetch(`${base}/management/v1${route}`, {
      method,
      headers: { "X-API-Key": key, "Content-Type": "application/json" },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    const text = await res.text();
    if (!res.ok) throw new Error(`${method} ${route}: ${res.status} ${text}`);
    return (text && res.headers.get("content-type")?.includes("json") ? JSON.parse(text) : {}) as T;
  }
  const id = (r: Record<string, unknown>) => String(r.id ?? r.client_id);
  const password = "User-password-2026!";
  const project = id(await call("POST", "/projects", { name: "Seeded" }));
  const environment = id(await call("POST", `/projects/${project}/environments`, { name: "Hosted" }));
  const E = `/environments/${environment}`;
  const acme = id(await call("POST", `${E}/organizations`, { name: "Acme" }));
  const secure = id(await call("POST", `${E}/organizations`, { name: "Secure" }));
  await call("PATCH", `${E}/organizations/${secure}`, { mfa_required: true });

  const redirect = "https://app.browser.example/callback";
  const application = id(await call("POST", `${E}/applications`, { name: "Shop", redirect_uris: [redirect] }));
  const resource = id(await call("POST", `${E}/resources`, { name: "Shop API", prefix: "shop", audience: "https://api.browser.example", permissions: ["shop:read"] }));
  await call("POST", `${E}/application-resources`, { application_id: application, resource_id: resource });
  const client = id(await call("POST", `${E}/oauth-clients`, { application_id: application, resource_id: resource, redirect_uris: [redirect], public: true, hosted_login: true }));
  // Sign-ups join Acme's Customers group, whose role grants shop:read.
  const reader = id(await call("POST", `${E}/roles`, { name: "reader", resource_id: resource, permissions: ["shop:read"] }));
  const customers = id(await call("POST", `${E}/organizations/${acme}/groups`, { name: "Customers" }));
  await call("POST", `${E}/group-role-assignments`, { role_id: reader, organization_id: acme, group_id: customers });
  await call("PUT", `${E}/sign-in-policy`, {
    allow_password: true, allow_email_code: true, allow_social: true, allow_password_reset: true,
    allow_signup: true, signup_organization_id: acme, signup_group_id: customers,
  });

  async function user(name: string, email: string, organization: string) {
    const u = id(await call("POST", `${E}/users`, { name, email, password, otp_enabled: true }));
    await call("POST", `${E}/memberships`, { organization_id: organization, user_id: u });
    await call("PUT", `${E}/grants`, { organization_id: organization, user_id: u, resource_id: resource, permissions: ["shop:read"] });
    return { id: u, email };
  }
  const alice = await user("Alice", "alice@browser.example", acme);
  const coder = await user("Casey", "casey@browser.example", acme);
  const resetter = await user("Riley", "riley@browser.example", acme);
  const mfa = await user("Morgan", "morgan@browser.example", secure);
  const blocked = await user("Blake", "blocked@browser.example", acme);
  const admin = await user("Ada", "ada@browser.example", acme);
  const roles = await call<{ items: { id: string; system_role?: string }[] }>("GET", `${E}/roles?limit=200`);
  const owner = roles.items.find((r) => r.system_role === "org_owner");
  if (!owner) throw new Error("no org_owner built-in role");
  await call("POST", `${E}/role-assignments`, { organization_id: acme, user_id: admin.id, role_id: owner.id });

  return { project, environment, acme, secure, application, resource, client, redirect, password, alice, coder, resetter, mfa, blocked, admin };
}

/** pkce returns a verifier and its S256 challenge. */
export function pkce() {
  const verifier = randomBytes(32).toString("base64url");
  return { verifier, challenge: createHash("sha256").update(verifier).digest("base64url") };
}
