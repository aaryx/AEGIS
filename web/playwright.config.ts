import { defineConfig } from "@playwright/test";
export default defineConfig({
  testDir: "./e2e", fullyParallel: false, workers: 1, retries: 0,
  use: { baseURL: process.env.AEGIS_WEB_URL || "http://127.0.0.1:3000", trace: "retain-on-failure", screenshot: "only-on-failure" },
  reporter: [["list"], ["html", { open: "never" }]],
  timeout: 45000
});
