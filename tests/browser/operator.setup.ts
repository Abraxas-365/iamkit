// The bootstrap operator signs in to the console, changes the bootstrap
// password (required at the first sign-in) and the session is saved for
// every other test.
import path from "node:path";
import { expect, test } from "@playwright/test";
import { fixture, stackDir } from "./fixture.js";

test("operator signs in and replaces the bootstrap password", async ({ page }) => {
  const f = fixture();
  await page.goto(`${f.issuer}/login`);
  await expect(page.getByRole("heading", { name: "Sign in to IAMKit" })).toBeVisible();

  // A wrong password is refused without leaving the page.
  await page.getByLabel("Operator email").fill(f.operator.email);
  await page.getByLabel("Password").fill("not-the-password-1234");
  await page.getByRole("button", { name: "Sign in" }).click();
  await expect(page.getByRole("alert").first()).toBeVisible();
  await expect(page).toHaveURL(/\/login/);

  await page.getByLabel("Password").fill(f.operator.password);
  await page.getByRole("button", { name: "Sign in" }).click();
  await expect(page.getByRole("heading", { name: "Choose a new password" })).toBeVisible();
  await page.getByLabel("New password").fill(f.operator.newPassword);
  await page.getByLabel("Confirm password").fill(f.operator.newPassword);
  await page.getByRole("button", { name: "Set password and sign in" }).click();
  await expect(page.getByRole("heading", { name: "Workspace overview" })).toBeVisible();

  await page.context().storageState({ path: path.join(stackDir, "operator.json") });
});
