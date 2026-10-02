// The fixture global-setup.ts writes and every test reads.
import { readFileSync } from "node:fs";
import path from "node:path";
import { expect, type Page } from "@playwright/test";

type Person = { id: string; email: string };
export interface Fixture {
  issuer: string;
  mailpit: string;
  receiver: string;
  operator: { email: string; password: string; newPassword: string };
  project: string;
  environment: string;
  acme: string;
  secure: string;
  application: string;
  resource: string;
  client: string;
  redirect: string;
  password: string;
  alice: Person;
  coder: Person;
  resetter: Person;
  mfa: Person;
  blocked: Person;
  admin: Person;
}

export const stackDir = path.join(import.meta.dirname, ".stack");
export const fixture = (): Fixture => JSON.parse(readFileSync(path.join(stackDir, "fixture.json"), "utf8"));

/** environmentURL is the console page of the seeded environment. */
export const environmentURL = (f: Fixture, page = "") => `${f.issuer}/projects/${f.project}/environments/${f.environment}${page ? `/${page}` : ""}`;

/** latestCode waits for the newest 8-digit code mailed to address after since. */
export async function latestCode(f: Fixture, address: string, since: number): Promise<string> {
  let code = "";
  await expect.poll(async () => {
    const res = await fetch(`${f.mailpit}/api/v1/search?query=${encodeURIComponent(`to:${address}`)}&limit=1`);
    const body = (await res.json()) as { messages: { ID: string; Created: string }[] };
    const m = body.messages?.[0];
    if (!m || Date.parse(m.Created) < since) return "";
    const full = (await (await fetch(`${f.mailpit}/api/v1/message/${m.ID}`)).json()) as { Text: string };
    code = full.Text.match(/\b\d{8}\b/)?.[0] ?? "";
    return code;
  }, { timeout: 20_000, message: `a code mailed to ${address}` }).not.toBe("");
  return code;
}

const callbacks = new WeakMap<Page, string>();

/** authorize opens the hosted sign-in page for the seeded client (PKCE). */
export async function authorize(page: Page, f: Fixture, extra: Record<string, string> = {}) {
  const params = new URLSearchParams({
    client_id: f.client, redirect_uri: f.redirect, response_type: "code", scope: "openid profile email",
    state: "browser-test-state", nonce: "browser-test-nonce", code_challenge: "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM", code_challenge_method: "S256", ...extra,
  });
  // The redirect goes to app.browser.example, which does not exist:
  // record where the browser was sent instead of loading it.
  page.on("request", (r) => { if (r.url().startsWith(f.redirect)) callbacks.set(page, r.url()); });
  await page.goto(`${f.issuer}/oauth/authorize?${params}`);
}

/** signedIn expects the authorization code redirect to the client. */
export async function signedIn(page: Page) {
  await expect.poll(() => callbacks.get(page) ?? "", { message: "the redirect to the client" }).toMatch(/^https:\/\/app\.browser\.example\/callback\?/);
  const url = new URL(callbacks.get(page)!);
  callbacks.delete(page);
  expect(url.searchParams.get("code")).toBeTruthy();
  expect(url.searchParams.get("state")).toBe("browser-test-state");
}
