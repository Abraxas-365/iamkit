// Headless Chromium against a disposable IAMKit (global-setup.ts): the
// operator console, the hosted sign-in pages and the org-admin portal.
import path from "node:path";
import { defineConfig, devices } from "@playwright/test";

const here = import.meta.dirname;

export default defineConfig({
  testDir: here,
  globalSetup: path.join(here, "global-setup.ts"),
  timeout: 90_000,
  expect: { timeout: 15_000 },
  // One stack, shared state (limits, texts, actions): run in order.
  fullyParallel: false,
  workers: 1,
  reporter: [["list"], ["html", { open: "never", outputFolder: path.join(here, "playwright-report") }]],
  outputDir: path.join(here, "test-results"),
  use: {
    ...devices["Desktop Chrome"],
    headless: true,
    ignoreHTTPSErrors: true,
    trace: "retain-on-failure",
    screenshot: "only-on-failure",
  },
  projects: [
    { name: "setup", testMatch: /operator\.setup\.ts$/ },
    {
      name: "chromium",
      testMatch: /\.spec\.ts$/,
      dependencies: ["setup"],
      use: { storageState: path.join(here, ".stack", "operator.json") },
    },
  ],
});
