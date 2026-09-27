import { defineConfig } from "@playwright/test";

export default defineConfig({
  testDir: "./tests",
  testMatch: "**/*.spec.ts",
  workers: 1,
  use: {
    baseURL: "http://127.0.0.1:3000",
    reducedMotion: "reduce",
    screenshot: "only-on-failure",
  },
  webServer: [
    {
      command: "../../../.venv/bin/python ../../../src/main.py --serve",
      url: "http://127.0.0.1:8000/health",
      reuseExistingServer: !process.env.CI,
    },
    {
      command: "npm run start -- --hostname 127.0.0.1",
      url: "http://127.0.0.1:3000",
      reuseExistingServer: !process.env.CI,
    },
  ],
});
