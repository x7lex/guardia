import { _electron as electron, expect } from '@playwright/test';
import { mkdtempSync, rmSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import assert from 'node:assert/strict';

// A harmless, structurally valid PE, parsed but never executed.
const pe = Buffer.alloc(1024);
pe.write('MZ'); pe.writeUInt32LE(0x80, 0x3c); pe.write('PE\0\0', 0x80);
pe.writeUInt16LE(0x14c, 0x84); pe.writeUInt16LE(1, 0x86);
pe.writeUInt16LE(224, 0x94); pe.writeUInt16LE(0x102, 0x96);
const opt = 0x98;
pe.writeUInt16LE(0x10b, opt);
for (const [offset, value] of [[16,0x1000],[20,0x1000],[24,0x2000],[28,0x400000],[32,0x1000],[36,0x200],[56,0x2000],[60,0x200],[92,16]]) pe.writeUInt32LE(value,opt+offset);
pe.writeUInt16LE(3, opt+68);
const section = opt+224;
pe.write('.text',section);
for (const [offset,value] of [[8,1],[12,0x1000],[16,0x200],[20,0x200],[36,0x60000020]]) pe.writeUInt32LE(value,section+offset);
pe[0x200]=0xc3;
const profile = mkdtempSync(path.join(tmpdir(), 'guardia-desktop-test-'));
const app = await electron.launch({
  ...(process.env.GUARDIA_APP ? { executablePath: process.env.GUARDIA_APP } : {}),
  args: [...(process.env.GUARDIA_APP ? [] : ['.']), `--user-data-dir=${profile}`],
  env: { ...process.env, GEMINI_API_KEY: '', API_TOKEN: '', REPUTATION_PROVIDER: 'disabled', YARA_RULES_PATH: '', ...(process.env.GUARDIA_APP ? { PATH: '/nonexistent', GUARDIA_PYTHON: '/nonexistent' } : {}) },
  timeout: 90000,
});
let origin;
let backendOrigin;
try {
  const page = await app.firstWindow({ timeout: 90000 });
  await page.waitForLoadState();
  await expect(page.locator('.retro-desktop')).toHaveCSS('display', 'flex');
  await expect(page.locator('.home-workspace')).toHaveCSS('display', 'grid');
  await expect.poll(() => page.locator('img[alt="Guardia"]').evaluate(image => image.complete && image.naturalWidth > 0)).toBe(true);
  const stylesheets = await page.locator('link[rel="stylesheet"]').evaluateAll(links => links.map(link => link.href));
  assert.ok(stylesheets.length > 0, 'production stylesheets are present');
  for (const url of stylesheets) assert.equal((await fetch(url)).status, 200, `stylesheet loads: ${new URL(url).pathname}`);
  if (process.env.GUARDIA_SCREENSHOT) await page.screenshot({ path: process.env.GUARDIA_SCREENSHOT });
  origin = new URL(page.url()).origin;
  const logs = await app.evaluate(({ app }) => app.getPath('logs'));
  const handshake = readFileSync(path.join(logs, 'scanner.log'), 'utf8').trim().split('\n').filter(line => /^\{"port":/.test(line)).at(-1);
  assert.ok(handshake, 'scanner announces its local port');
  backendOrigin = `http://127.0.0.1:${JSON.parse(handshake).port}`;
  assert.equal((await fetch(`${backendOrigin}/health`)).status, 401);
  const errors = [];
  page.on('pageerror', error => errors.push(error.message));
  assert.equal((await fetch(`${origin}/api/scan?name=test.exe`, { method: 'POST', body: pe })).status, 401);
  await page.getByLabel('Choose files', { exact: true }).setInputFiles({ name: 'desktop-demo.exe', mimeType: 'application/octet-stream', buffer: pe });
  await page.getByRole('button', { name: 'Scan All (1)' }).click();
  await expect(page.getByText('desktop-demo.exe', { exact: true })).toBeVisible({ timeout: 30000 });
  await page.getByText('desktop-demo.exe', { exact: true }).click();
  await expect(page.getByRole('dialog', { name: 'Report for desktop-demo.exe' })).toBeVisible();
  await expect(page.getByText('/10 triage score', { exact: false })).toBeVisible();
  assert.deepEqual(errors, []);
  console.log('PASS: styled desktop, logo and CSS assets, standalone launch, unauthorized request blocked, file upload, real Python report, report UI.');
} finally {
  await app.close();
  rmSync(profile, { recursive: true, force: true });
}
if (origin) {
  await assert.rejects(fetch(origin, { signal: AbortSignal.timeout(2000) }));
  await assert.rejects(fetch(`${backendOrigin}/health`, { signal: AbortSignal.timeout(2000) }));
  console.log('PASS: interface and Python processes stop on quit.');
}
