// The operator console in headless Chromium against the real API: CRUD,
// extensibility (actions, webhooks, sign-in texts), features, limits,
// console languages and the org-admin portal.
import { expect, test, type Page } from "@playwright/test";
import { authorize, environmentURL, fixture, signedIn } from "./fixture.js";

const f = fixture();

/** ready waits until the page has loaded its data. */
async function ready(page: Page) {
  await expect(page.getByRole("status").filter({ hasText: /Loading/ })).toHaveCount(0);
}

async function dialog(page: Page, title: string) {
  const d = page.getByRole("dialog", { name: title });
  await expect(d).toBeVisible();
  return d;
}

test.describe.configure({ mode: "serial" });

test("projects, environments and the workspace overview", async ({ page }) => {
  await page.goto(`${f.issuer}/`);
  await expect(page.getByRole("heading", { name: "Workspace overview" })).toBeVisible();
  await page.goto(`${f.issuer}/projects`);
  await page.getByRole("button", { name: "Create project" }).click();
  const d = await dialog(page, "Create project");
  await d.getByLabel("Name", { exact: true }).fill("Browser project");
  await d.locator("button[type=submit]").click();
  await expect(page.locator("#content").getByText("Browser project").first()).toBeVisible();
  await expect(page.locator("#content").getByText("Seeded").first()).toBeVisible();
});

test("users: create, open, edit, history", async ({ page }) => {
  await page.goto(environmentURL(f, "users"));
  await expect(page.getByRole("heading", { name: "Users" })).toBeVisible();
  await expect(page.locator("#content").getByText(f.alice.email)).toBeVisible();
  await page.getByRole("button", { name: "Create user" }).click();
  const d = await dialog(page, "Create user");
  await d.getByLabel("Name", { exact: true }).fill("Console Created");
  await d.getByLabel("Email").fill("console-created@browser.example");
  await d.getByLabel(/Initial password/).fill("Console-created-2026!");
  await d.locator("button[type=submit]").click();
  // Creating a user opens its page.
  await expect(page).toHaveURL(/\/users\/[0-9a-f-]{36}$/);
  await expect(page.locator("#content").getByText("console-created@browser.example").first()).toBeVisible();
  await page.getByRole("button", { name: "Edit" }).first().click();
  const edit = await dialog(page, "Edit user");
  await edit.getByLabel("Name", { exact: true }).fill("Console Renamed");
  await edit.locator("button[type=submit]").click();
  await expect(page.locator("#content").getByText("Console Renamed").first()).toBeVisible();
  // The change history shows the diff (migration 047 trigger).
  const history = page.locator("section").filter({ has: page.getByRole("heading", { name: "History", exact: true }) });
  await expect(history.getByText("Console Created").first()).toBeVisible();
  await expect(history.getByText("Console Renamed").first()).toBeVisible();
});

test("organizations, applications and resources list the seeded data", async ({ page }) => {
  for (const [path, heading, text] of [["organizations", "Organizations", "Acme"], ["applications", "Applications", "Shop"], ["resources", "Resources & scopes", "Shop API"]]) {
    await page.goto(environmentURL(f, path));
    await expect(page.getByRole("heading", { name: heading })).toBeVisible();
    await expect(page.locator("#content").getByText(text, { exact: true }).first()).toBeVisible();
  }
  await page.goto(environmentURL(f, "organizations"));
  await page.getByRole("button", { name: "Create organization" }).click();
  const d = await dialog(page, "Create organization");
  await d.getByLabel("Name", { exact: true }).fill("Console Org");
  await d.locator("button[type=submit]").click();
  await expect(page).toHaveURL(/\/organizations\/[0-9a-f-]{36}/);
  await expect(page.locator("#content").getByText("Console Org").first()).toBeVisible();
});

test("oauth clients list the hosted client", async ({ page }) => {
  await page.goto(environmentURL(f, "oauth-clients"));
  await expect(page.locator("#content").getByText("Hosted page").first()).toBeVisible();
});

test("features: an environment override is saved and reset", async ({ page }) => {
  await page.goto(environmentURL(f, "features"));
  await expect(page.getByRole("heading", { name: "Features (beta)" })).toBeVisible();
  await ready(page);
  const flag = page.getByRole("switch", { name: "beta_languages" });
  await expect(flag).toBeChecked();
  await flag.click();
  await expect(page.getByText("beta_languages turned off")).toBeVisible();
  await expect(flag).not.toBeChecked();
  await page.reload();
  await ready(page);
  await expect(page.getByRole("switch", { name: "beta_languages" })).not.toBeChecked();
  await page.getByRole("button", { name: /Use the default/ }).first().click();
  await expect(page.getByText("beta_languages reset")).toBeVisible();
  await expect(page.getByRole("switch", { name: "beta_languages" })).toBeChecked();
  // Deployment-scoped flags are read-only here.
  await expect(page.getByText("saml_idp")).toBeVisible();
  await expect(page.getByRole("switch", { name: "saml_idp" })).toHaveCount(0);
});

test("usage and limits: a users cap is enforced, then lifted", async ({ page, request }) => {
  await page.goto(environmentURL(f, "usage"));
  await expect(page.getByRole("heading", { name: "Usage and limits" })).toBeVisible();
  await ready(page);
  await page.getByRole("spinbutton", { name: "Users", exact: true }).fill("1");
  await page.getByRole("button", { name: "Save limits" }).click();
  await expect(page.getByText("Limits saved")).toBeVisible();

  await page.goto(environmentURL(f, "users"));
  await page.getByRole("button", { name: "Create user" }).click();
  const d = await dialog(page, "Create user");
  await d.getByLabel("Name", { exact: true }).fill("Over Quota");
  await d.getByLabel("Email").fill("over-quota@browser.example");
  await d.locator("button[type=submit]").click();
  await expect(d.getByRole("alert")).toContainText("limit");
  await d.getByRole("button", { name: "Cancel" }).click();

  await page.goto(environmentURL(f, "usage"));
  await ready(page);
  await page.getByRole("spinbutton", { name: "Users", exact: true }).fill("");
  await page.getByRole("button", { name: "Save limits" }).click();
  await expect(page.getByText("Limits saved")).toBeVisible();
  void request;
});

test("sign-in texts: a client's wording shows on the hosted page", async ({ page, browser }) => {
  await page.goto(environmentURL(f, "hosted-login/texts"));
  await expect(page.getByRole("heading", { name: "Sign-in texts" })).toBeVisible();
  await page.getByLabel("Filter texts").fill("hosted.title.sign_in");
  await page.getByLabel("hosted.title.sign_in", { exact: true }).fill("Welcome to the Shop");
  await page.getByRole("button", { name: "Save", exact: true }).click();
  await expect(page.getByText("Sign-in texts saved")).toBeVisible();

  const end = await browser.newContext({ ignoreHTTPSErrors: true });
  const hosted = await end.newPage();
  await authorize(hosted, f);
  await expect(hosted.getByRole("heading", { name: "Welcome to the Shop" })).toBeVisible();

  await page.getByRole("button", { name: "Remove these texts" }).click();
  await (await dialog(page, "Remove these texts?")).getByRole("button", { name: "Remove" }).click();
  await expect(page.getByText("Sign-in texts removed")).toBeVisible();
  await hosted.reload();
  await expect(hosted.getByRole("heading", { name: "Sign in", exact: true })).toBeVisible();
  await end.close();
});

test("actions: a pre-sign-in target denies a user on the hosted page", async ({ page, browser }) => {
  await page.goto(environmentURL(f, "actions"));
  await page.getByRole("button", { name: "Add target" }).first().click();
  const d = await dialog(page, "Add target");
  await d.getByLabel("Name", { exact: true }).fill("Risk check");
  await d.getByLabel("Endpoint URL").fill(`${f.receiver}/action`);
  await d.locator("button[type=submit]").click();
  const secret = await dialog(page, "Signing secret");
  await expect(secret.locator("code")).toContainText("whsec_");
  await secret.getByRole("button", { name: "I have saved the secret" }).click();
  await expect(page.locator("#content").getByText("Risk check").first()).toBeVisible();

  await page.getByRole("button", { name: "Edit function:pre_sign_in" }).click();
  const bind = await dialog(page, "Pre sign in");
  await bind.getByLabel(/Risk check/).check();
  await bind.getByRole("button", { name: "Save" }).click();
  await expect(page.getByText("Saved")).toBeVisible();

  const end = await browser.newContext({ ignoreHTTPSErrors: true });
  const hosted = await end.newPage();
  await authorize(hosted, f);
  await hosted.getByLabel("Email or username").fill(f.blocked.email);
  await hosted.getByRole("button", { name: "Continue" }).click();
  await hosted.getByLabel("Password").fill(f.password);
  await hosted.getByRole("button", { name: "Sign in" }).click();
  await expect(hosted.getByRole("alert")).toContainText("Blocked by the browser-test action.");

  // Others still sign in; the target saw both calls.
  await authorize(hosted, f);
  await hosted.getByLabel("Email or username").fill(f.alice.email);
  await hosted.getByRole("button", { name: "Continue" }).click();
  await hosted.getByLabel("Password").fill(f.password);
  await hosted.getByRole("button", { name: "Sign in" }).click();
  await signedIn(hosted);
  await end.close();
  const calls = (await (await fetch(`${f.receiver}/calls`)).json()) as { user?: { email?: string } }[];
  expect(calls.map((c) => c.user?.email)).toEqual(expect.arrayContaining([f.blocked.email, f.alice.email]));

  // Unbind so later journeys are unaffected.
  await page.getByRole("button", { name: "Edit function:pre_sign_in" }).click();
  const unbind = await dialog(page, "Pre sign in");
  await unbind.getByLabel(/Risk check/).uncheck();
  await unbind.getByRole("button", { name: "Save" }).click();
  await expect(page.getByText("Saved").first()).toBeVisible();
});

test("webhooks: a test event is delivered and signed", async ({ page }) => {
  await page.goto(environmentURL(f, "webhooks"));
  await page.getByRole("button", { name: "Add webhook" }).first().click();
  const d = await dialog(page, "Add webhook");
  await d.getByLabel("Name", { exact: true }).fill("Audit sink");
  await d.getByLabel("Endpoint URL").fill(`${f.receiver}/hook`);
  await d.locator("button[type=submit]").click();
  const secret = await dialog(page, "Signing secret");
  await secret.getByRole("button", { name: "I have saved the secret" }).click();
  await page.locator("#content").getByText("Audit sink").first().click();
  await expect(page.getByRole("heading", { name: "Audit sink" })).toBeVisible();
  await page.getByRole("button", { name: "Send test event" }).click();
  await expect(page.getByText(/Test event delivered \(HTTP 204\)/)).toBeVisible();
  const hooks = (await (await fetch(`${f.receiver}/hooks`)).json()) as { headers: Record<string, string> }[];
  expect(hooks.length).toBeGreaterThan(0);
  expect(hooks.at(-1)!.headers["webhook-signature"]).toMatch(/^v1,/);
});

test("console language: Spanish is saved and follows the operator", async ({ page }) => {
  await page.goto(`${f.issuer}/`);
  await expect(page.getByRole("heading", { name: "Workspace overview" })).toBeVisible();
  await page.getByLabel("Console language").selectOption("es");
  await expect(page.getByRole("heading", { name: "Resumen del espacio de trabajo" })).toBeVisible();
  await expect(page.locator("html")).toHaveAttribute("lang", "es");
  // A fresh browser of the same operator gets it from the server.
  await page.evaluate(() => { localStorage.clear(); sessionStorage.clear(); });
  await page.reload();
  await expect(page.getByRole("heading", { name: "Resumen del espacio de trabajo" })).toBeVisible();
  await page.getByLabel("Idioma de la consola").selectOption("en");
  await expect(page.getByRole("heading", { name: "Workspace overview" })).toBeVisible();
});

test("org-admin portal: turned on, an organization owner manages members", async ({ page, browser }) => {
  await page.goto(environmentURL(f, "hosted-login"));
  await page.getByRole("button", { name: "Turn on" }).click();
  await expect(page.getByText("Organization admin portal turned on")).toBeVisible();
  const link = (await page.locator("code", { hasText: "/org-admin/" }).textContent())!.trim();
  expect(link).toContain(`/org-admin/${f.environment}`);

  const end = await browser.newContext({ ignoreHTTPSErrors: true });
  const portal = await end.newPage();
  await portal.goto(`${link}?organization_id=${f.acme}`);
  await expect(portal.getByRole("heading", { name: "Organization administration" })).toBeVisible();
  await portal.getByRole("button", { name: "Sign in" }).click();
  await portal.getByLabel("Email or username").fill(f.admin.email);
  await portal.getByRole("button", { name: "Continue" }).click();
  await portal.getByLabel("Password").fill(f.password);
  await portal.getByRole("button", { name: "Sign in" }).click();
  await expect(portal).toHaveURL(new RegExp(`/org-admin/${f.environment}`));
  await portal.getByRole("link", { name: "Members" }).click();
  await expect(portal.getByRole("heading", { name: "Members" })).toBeVisible();
  await expect(portal.getByText(f.alice.email).first()).toBeVisible();
  await expect(portal.getByText(f.mfa.email)).toHaveCount(0);
  await portal.getByRole("button", { name: "Sign out" }).click();
  await end.close();

  await page.getByRole("button", { name: "Turn off" }).click();
  await (await dialog(page, "Turn off the organization admin portal?")).getByRole("button", { name: "Turn off" }).click();
  await expect(page.getByText("Organization admin portal turned off")).toBeVisible();
});

test("sign out of the console", async ({ page }) => {
  await page.goto(`${f.issuer}/`);
  await page.getByRole("button", { name: "Sign out" }).click();
  await expect(page.getByRole("heading", { name: "Sign in to IAMKit" })).toBeVisible();
});
