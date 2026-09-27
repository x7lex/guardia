import { _electron as electron, expect } from "@playwright/test";
import { execFileSync } from "node:child_process";
import { mkdtempSync, rmSync, existsSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const web = fileURLToPath(new URL("../", import.meta.url));
const root = resolve(web, "../../..");
const profile = mkdtempSync(join(tmpdir(), "guardia-desktop-test-"));
const python = join(root, process.platform === "win32" ? ".venv/Scripts/python.exe" : ".venv/bin/python");
const env = { ...process.env, GUARDIA_TEST_RESOURCES: join(web, ".desktop-resources"),
  API_TOKEN: "", GEMINI_API_KEY: "", REPUTATION_PROVIDER: "disabled", YARA_RULES_PATH: "" };
delete env.ELECTRON_RUN_AS_NODE;
const executablePath = process.env.GUARDIA_TEST_EXECUTABLE;
const desktop = await electron.launch({
  ...(executablePath ? { executablePath: resolve(web, executablePath) } : {}),
  args: [...(executablePath ? [] : [join(web, "electron/main.mjs")]), `--user-data-dir=${profile}`],
  env,
  timeout: 90000,
});
desktop.process().stderr.on("data", data => process.stderr.write(data));
try {
  const page = await desktop.firstWindow({ timeout: 90000 });
  await page.waitForURL("http://127.0.0.1:3765/");
  const prefs = await desktop.evaluate(({ BrowserWindow }) => BrowserWindow.getAllWindows()[0].webContents.getLastWebPreferences());
  expect(prefs.nodeIntegration).toBe(false);
  expect(prefs.contextIsolation).toBe(true);
  expect(prefs.sandbox).toBe(true);
  const buffer = execFileSync(python, ["-c", "import runpy,sys; sys.stdout.buffer.write(runpy.run_path('tests/test_api.py')['minimal_pe']())"], { cwd: root });
  await page.getByLabel("Choose files", { exact: true }).setInputFiles({ name: "desktop-smoke.exe", mimeType: "application/octet-stream", buffer });
  const response = page.waitForResponse(result => result.url().includes("/api/scan?"));
  await page.getByRole("button", { name: "Scan All (1)" }).click();
  const result = await (await response).json();
  expect(result.status).toBe("scanned");
  expect(result.report).not.toHaveProperty("gemini_review");
  await page.getByText("desktop-smoke.exe", { exact: true }).click();
  await expect(page.getByRole("button", { name: "✦ Review with Gemini", exact: true })).toBeVisible();
  console.log("PASS: bundled frontend + frozen scanner, real scan in Electron, sandbox, and opt-in Gemini.");
} finally {
  await desktop.close();
  const log = join(profile, "services.log");
  if (existsSync(log)) console.log(readFileSync(log, "utf8"));
  rmSync(profile, { recursive: true, force: true, maxRetries: 5, retryDelay: 500 });
}
for (const port of [3765, 8765]) {
  let responding = false;
  try { responding = (await fetch(`http://127.0.0.1:${port}`, { signal: AbortSignal.timeout(1000) })).status > 0; } catch { /* Expected after shutdown. */ }
  expect(responding, `service ${port} should stop when Electron closes`).toBe(false);
}
console.log("PASS: closing Electron stopped both bundled services.");
