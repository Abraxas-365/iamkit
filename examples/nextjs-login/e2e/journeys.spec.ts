// Parity of the custom sign-in UI (@iamkit/react in a Next.js app) with
// the hosted pages: the journeys of tests/e2e/hosted_test.go and
// custom_ui_test.go, in a real browser against a real IAMKit.
import { createHmac } from "node:crypto";
import { readFileSync } from "node:fs";
import { expect, test, type Page } from "@playwright/test";

interface Fixture {
  environment: string;
  organization: string;
  secure: string;
  clientId: string;
  password: string;
  alice: { id: string; email: string };
  reset: { id: string; email: string };
  coder: { id: string; email: string };
  mfa: { id: string; email: string };
  invitation: { token: string; email: string };
}

const fixture: Fixture = JSON.parse(readFileSync(process.env.E2E_FIXTURE ?? "e2e/.stack/fixture.json", "utf8"));
const mailSink = process.env.MAIL_SINK_URL ?? "http://127.0.0.1:18025";

interface Mail {
  email: string;
  purpose: string;
  code?: string;
  token?: string;
}

/** The newest message of a purpose to an address (the mail webhook sink). */
async function lastMail(email: string, purpose: string, after = 0): Promise<Mail> {
  for (let i = 0; i < 50; i++) {
    const all = (await (await fetch(`${mailSink}/messages`)).json()) as Mail[];
    const found = all.slice(after).filter((m) => m.email === email && m.purpose === purpose);
    if (found.length) return found[found.length - 1];
    await new Promise((r) => setTimeout(r, 200));
  }
  throw new Error(`no ${purpose} email to ${email}`);
}
const mailCount = async () => ((await (await fetch(`${mailSink}/messages`)).json()) as Mail[]).length;

/** RFC 6238 code of a base32 secret (SHA-1, 6 digits, 30 s). */
function totp(secret: string): string {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let bits = "";
  for (const ch of secret.replace(/=+$/, "").toUpperCase()) bits += alphabet.indexOf(ch).toString(2).padStart(5, "0");
  const key = Buffer.from(bits.match(/.{8}/g)!.map((b) => parseInt(b, 2)));
  const counter = Buffer.alloc(8);
  counter.writeBigUInt64BE(BigInt(Math.floor(Date.now() / 30_000)));
  const mac = createHmac("sha1", key).update(counter).digest();
  const offset = mac[mac.length - 1] & 0xf;
  return String((mac.readUInt32BE(offset) & 0x7fffffff) % 1_000_000).padStart(6, "0");
}

/** From the application's home page to the custom sign-in page. */
async function startSignIn(page: Page, organization?: string) {
  await page.goto(organization ? `/?organization=${organization}` : "/");
  await page.getByRole("button", { name: "Sign in" }).click();
  await expect(page).toHaveURL(/\/sign-in\?ticket=/);
  await expect(page.locator('[data-iamkit="root"]')).toHaveAttribute("data-step", "identify");
}

async function identify(page: Page, login: string) {
  await page.getByLabel("Email or username").fill(login);
  await page.getByRole("button", { name: "Continue" }).click();
}

async function expectSignedIn(page: Page, user: { id: string }, organization: string) {
  await expect(page.getByRole("heading", { name: "Signed in" })).toBeVisible();
  await expect(page.getByTestId("user")).toHaveText(user.id);
  await expect(page.getByTestId("organization")).toHaveText(organization);
}

test("password sign-in returns to the application signed in; the ticket is single use", async ({ page }) => {
  await startSignIn(page);
  // The client's own wording, served with the ticket.
  await expect(page.getByRole("heading", { name: "Sign in to Invoices" })).toBeVisible();
  const ticketUrl = page.url();
  await identify(page, fixture.alice.email);
  await page.getByLabel("Password").fill(fixture.password);
  await page.getByRole("button", { name: "Sign in", exact: true }).click();
  await expectSignedIn(page, fixture.alice, fixture.organization);
  await expect(page.getByTestId("amr")).toHaveText("pwd");

  // Like the hosted pages: a used ticket cannot sign in again.
  await page.goto(ticketUrl);
  await expect(page.locator('[data-iamkit="root"]')).toHaveAttribute("data-step", "failed");
});

test("a wrong password is refused on the page", async ({ page }) => {
  await startSignIn(page);
  await identify(page, fixture.alice.email);
  await page.getByLabel("Password").fill("not the password");
  await page.getByRole("button", { name: "Sign in", exact: true }).click();
  await expect(page.locator('[data-iamkit="error"]')).toBeVisible();
  await expect(page.locator('[data-iamkit="root"]')).toHaveAttribute("data-step", "password");
});

test("emailed code sign-in", async ({ page }) => {
  await startSignIn(page);
  await identify(page, fixture.coder.email);
  const before = await mailCount();
  await page.getByRole("button", { name: "Email me a code" }).click();
  const mail = await lastMail(fixture.coder.email, "login", before);
  await page.getByLabel("Code").fill(mail.code!);
  await page.getByRole("button", { name: "Verify" }).click();
  await expectSignedIn(page, fixture.coder, fixture.organization);
  await expect(page.getByTestId("amr")).toHaveText("email");
});

test("password reset, then sign-in with the new password", async ({ page }) => {
  await startSignIn(page);
  await identify(page, fixture.reset.email);
  const before = await mailCount();
  await page.getByRole("button", { name: "Forgot password?" }).click();
  const mail = await lastMail(fixture.reset.email, "password_reset", before);
  await page.getByLabel("Code").fill(mail.code!);
  await page.getByLabel("New password").fill("A-brand-new-password-2026");
  await page.getByRole("button", { name: "Set password" }).click();
  await expectSignedIn(page, fixture.reset, fixture.organization);
});

test("an organization requiring MFA enrolls an authenticator and shows recovery codes", async ({ page }) => {
  await startSignIn(page, fixture.secure);
  await identify(page, fixture.mfa.email);
  await page.getByLabel("Password").fill(fixture.password);
  await page.getByRole("button", { name: "Sign in", exact: true }).click();
  await expect(page.locator('[data-iamkit="root"]')).toHaveAttribute("data-step", "enroll");
  await expect(page.getByTestId("otpauth")).toHaveAttribute("href", /^otpauth:\/\/totp\//);
  const secret = (await page.locator('[data-iamkit="notice"] code').textContent())!.trim();
  await page.getByLabel("6-digit code").fill(totp(secret));
  await page.getByRole("button", { name: "Verify and continue" }).click();
  await expect(page.locator('[data-iamkit="codes"] li')).not.toHaveCount(0);
  await page.getByRole("button", { name: "I saved my codes — continue" }).click();
  await expectSignedIn(page, fixture.mfa, fixture.secure);
  await expect(page.getByTestId("amr")).toContainText("mfa");
});

test("sign-up with a verified email lands in the sign-up organization", async ({ page }) => {
  const email = `new-${Date.now()}@parity.example`;
  await startSignIn(page);
  await page.getByRole("button", { name: "Create account" }).click();
  await page.getByLabel("Email", { exact: true }).fill(email);
  await page.getByLabel("Name", { exact: true }).fill("New Customer");
  await page.locator('input[name="password"]').fill("Signup-password-2026!");
  const before = await mailCount();
  await page.getByRole("button", { name: "Create account" }).click();
  const mail = await lastMail(email, "email_verification", before);
  await page.getByLabel("Code").fill(mail.code!);
  await page.getByRole("button", { name: "Verify" }).click();
  await expect(page.getByRole("heading", { name: "Signed in" })).toBeVisible();
  await expect(page.getByTestId("organization")).toHaveText(fixture.organization);
});

test("an invitation is accepted on the application's page", async ({ page }) => {
  await page.goto(`/invitation?token=${encodeURIComponent(fixture.invitation.token)}`);
  await expect(page.getByRole("heading", { name: "Invitation" })).toBeVisible();
  // The preview masks the address, like the hosted page.
  await expect(page.getByText("i***@parity.example")).toBeVisible();
  await page.getByLabel("Name").fill("Ivy");
  await page.getByLabel("Password").fill("Invited-password-2026!");
  await page.getByRole("button", { name: /^Join/ }).click();
  await expect(page.getByRole("heading", { name: "Invitation accepted" })).toBeVisible();
});

test("a sign-in page without a ticket or authorize request asks to start from the application", async ({ page }) => {
  await page.goto("/sign-in");
  await expect(page.getByText("Start the sign-in from the application.")).toBeVisible();
});
