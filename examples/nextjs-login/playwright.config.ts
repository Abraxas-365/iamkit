import { defineConfig, devices } from "@playwright/test";

// Run through e2e/run.sh, which starts a disposable IAMKit + this app and
// writes the seeded fixture (E2E_FIXTURE).
export default defineConfig({
  testDir: "e2e",
  timeout: 60_000,
  workers: 1,
  reporter: process.env.CI ? [["list"], ["html", { open: "never" }]] : "list",
  use: {
    baseURL: process.env.APP_URL ?? "https://localhost:13443",
    ignoreHTTPSErrors: true,
    trace: "retain-on-failure",
  },
  projects: [{ name: "chromium", use: { ...devices["Desktop Chrome"] } }],
});
