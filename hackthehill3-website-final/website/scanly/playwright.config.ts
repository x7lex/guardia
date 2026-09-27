import { defineConfig } from "@playwright/test";

export default defineConfig({
  testDir: "./tests",
  testMatch: "**/*.spec.ts",
  workers: 1,
  use: {
    baseURL: "http://127.0.0.1:3100",
    reducedMotion: "reduce",
    screenshot: "only-on-failure",
  },
  webServer: [
    {
      command:
        "BACKEND_PORT=8100 GEMINI_API_KEY= API_TOKEN= REPUTATION_PROVIDER=disabled YARA_RULES_PATH= ../../../.venv/bin/python ../../../src/main.py --serve",
      url: "http://127.0.0.1:8100/health",
      reuseExistingServer: false,
    },
    {
      command:
        "BACKEND_URL=http://127.0.0.1:8100 npm run start -- --hostname 127.0.0.1 --port 3100",
      url: "http://127.0.0.1:3100",
      reuseExistingServer: false,
    },
  ],
});
