import { defineConfig } from "@playwright/test";

const baseURL = process.env["API_BASE_URL"];
if (baseURL === undefined || baseURL === "") {
  throw new Error("API_BASE_URL is not set; start the server and export its URL (see scripts/verify-ts.sh)");
}

// API tests only: the `request` fixture needs no browser, so no browser download.
export default defineConfig({
  testDir: "api-tests",
  fullyParallel: true,
  forbidOnly: true,
  retries: 0,
  reporter: [["list"]],
  use: { baseURL },
});
