// Hosted sign-in journeys in headless Chromium: real cookies, real TLS,
// codes delivered over real SMTP (Mailpit).
import { createHmac } from "node:crypto";
import { expect, test, type Page } from "@playwright/test";
import { authorize, fixture, latestCode, signedIn } from "./fixture.js";

// Hosted pages are for end users: no operator session.
test.use({ storageState: { cookies: [], origins: [] } });

const f = fixture();

async function identify(page: Page, login: string) {
  await expect(page.getByRole("heading", { name: "Sign in" })).toBeVisible();
  await page.getByLabel("Email or username").fill(login);
  await page.getByRole("button", { name: "Continue" }).click();
}

/** totp computes the RFC 6238 code of a base32 secret. */
function totp(secret: string, at = Date.now()) {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let bits = "";
  for (const c of secret.replace(/[\s=]/g, "").toUpperCase()) bits += alphabet.indexOf(c).toString(2).padStart(5, "0");
  const key = Buffer.from(bits.match(/.{8}/g)!.map((b) => parseInt(b, 2)));
  const counter = Buffer.alloc(8);
  counter.writeBigUInt64BE(BigInt(Math.floor(at / 30_000)));
  const h = createHmac("sha1", key).update(counter).digest();
  const o = h[h.length - 1] & 0xf;
  return String((h.readUInt32BE(o) & 0x7fffffff) % 1_000_000).padStart(6, "0");
}

test("password sign-in returns an authorization code", async ({ page }) => {
  await authorize(page, f);
  await identify(page, f.alice.email);
  await page.getByLabel("Password").fill(f.password);
  await page.getByRole("button", { name: "Sign in" }).click();
  await signedIn(page);
});

test("a wrong password is refused on the page", async ({ page }) => {
  await authorize(page, f);
  await identify(page, f.alice.email);
  await page.getByLabel("Password").fill("definitely-not-it-2026");
  await page.getByRole("button", { name: "Sign in" }).click();
  await expect(page.getByRole("alert")).toContainText("Incorrect email, username or password.");
});

test("an emailed code signs in (real SMTP)", async ({ page }) => {
  await authorize(page, f);
  await identify(page, f.coder.email);
  const since = Date.now() - 1000;
  await page.getByRole("button", { name: "Email me a code" }).click();
  await expect(page.getByRole("heading", { name: "Check your email" })).toBeVisible();
  await page.getByLabel("Code").fill(await latestCode(f, f.coder.email, since));
  await page.getByRole("button", { name: "Verify" }).click();
  await signedIn(page);
});

test("password reset by email, then sign in with the new password", async ({ page }) => {
  await authorize(page, f);
  await identify(page, f.resetter.email);
  const since = Date.now() - 1000;
  await page.getByRole("button", { name: "Forgot password?" }).click();
  await expect(page.getByRole("heading", { name: "Reset your password" })).toBeVisible();
  await page.getByLabel("Code").fill(await latestCode(f, f.resetter.email, since));
  await page.getByLabel("New password").fill("A-brand-new-password-2026");
  await page.getByRole("button", { name: "Set password" }).click();
  await expect(page.getByRole("status")).toContainText("Your password was changed.");
  await page.getByLabel("Password").fill("A-brand-new-password-2026");
  await page.getByRole("button", { name: "Sign in" }).click();
  await signedIn(page);
});

test("an organization requiring MFA enrolls an authenticator app", async ({ page }) => {
  await authorize(page, f);
  await identify(page, f.mfa.email);
  await page.getByLabel("Password").fill(f.password);
  await page.getByRole("button", { name: "Sign in" }).click();
  await expect(page.getByRole("heading", { name: "Set up two-step verification" })).toBeVisible();
  await expect(page.getByRole("img", { name: "QR code for your authenticator app" })).toBeVisible();
  const secret = (await page.locator("p > code").textContent())!.trim();
  await page.getByLabel("6-digit code").fill(totp(secret));
  await page.getByRole("button", { name: "Verify and continue" }).click();
  await expect(page.getByRole("heading", { name: "Save your recovery codes" })).toBeVisible();
  await expect(page.locator("ul.codes li")).toHaveCount(10);
  await page.getByRole("button", { name: "I saved my codes — continue" }).click();
  await signedIn(page);
});

test("sign-up verifies the email and joins the sign-up organization", async ({ page }) => {
  await authorize(page, f);
  await page.getByRole("button", { name: "Create account" }).click();
  await expect(page.getByRole("heading", { name: "Create your account" })).toBeVisible();
  const email = `new-${Date.now()}@browser.example`;
  await page.getByLabel("Name", { exact: true }).fill("New Person");
  await page.getByLabel("Email", { exact: true }).fill(email);
  await page.getByLabel(/^Password/).fill("New-person-password-2026");
  const since = Date.now() - 1000;
  await page.getByRole("button", { name: "Create account" }).click();
  await page.getByLabel("Code").fill(await latestCode(f, email, since));
  await page.getByRole("button", { name: "Verify" }).click();
  await signedIn(page);
});

test("the hosted page follows the browser language", async ({ browser }) => {
  const context = await browser.newContext({ locale: "es-ES", ignoreHTTPSErrors: true });
  const page = await context.newPage();
  await authorize(page, f);
  await expect(page.locator("html")).toHaveAttribute("lang", "es");
  await expect(page.getByRole("heading", { name: "Iniciar sesión" })).toBeVisible();
  await expect(page.getByLabel("Correo electrónico o usuario")).toBeVisible();
  await context.close();
});

test("an unknown client is refused without a sign-in form", async ({ page }) => {
  await page.goto(`${f.issuer}/oauth/authorize?client_id=00000000-0000-4000-8000-000000000000&redirect_uri=${encodeURIComponent(f.redirect)}&response_type=code&scope=openid&state=browser-test-state`);
  await expect(page.getByLabel("Email or username")).toHaveCount(0);
});
