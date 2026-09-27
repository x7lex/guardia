import test from "node:test";
import assert from "node:assert/strict";
import { reportMatches } from "../lib/report-view.ts";
import { readSettings, SETTINGS_KEY } from "../lib/retro-sounds.ts";
const report = (level, signed = false) => ({
  analysis: { file: { file_name: "Example.EXE" }, signature: { signed } },
  risk_assessment: { risk: { level } },
});
test("search matches filenames and paths without case sensitivity", () => {
  assert.ok(
    reportMatches(
      "/folder/example.exe",
      report("safe"),
      " EXAMPLE ",
      "all",
      false,
    ),
  );
  assert.ok(
    reportMatches(
      "/folder/example.exe",
      report("safe"),
      "folder",
      "all",
      false,
    ),
  );
  assert.equal(
    reportMatches(
      "/folder/example.exe",
      report("safe"),
      "missing",
      "all",
      false,
    ),
    false,
  );
});
test("risk and unsigned filters combine", () => {
  assert.ok(reportMatches("x", report("critical"), "", "unsafe", true));
  assert.equal(
    reportMatches("x", report("critical", true), "", "unsafe", true),
    false,
  );
  assert.ok(reportMatches("x", report("low"), "", "safe", false));
  assert.ok(reportMatches("x", report("medium"), "", "review", false));
});
test("settings restore persisted values and tolerate invalid storage", () => {
  const store = new Map([
    [
      SETTINGS_KEY,
      JSON.stringify({
        sounds: true,
        volume: 0.4,
        music: true,
        musicVolume: 0.3,
      }),
    ],
  ]);
  globalThis.localStorage = { getItem: (key) => store.get(key) ?? null };
  assert.deepEqual(readSettings(), {
    sounds: true,
    volume: 0.4,
    music: true,
    musicVolume: 0.3,
  });
  store.set(SETTINGS_KEY, JSON.stringify({ sounds: true, volume: 9 }));
  assert.equal(readSettings().volume, 1);
  store.set(SETTINGS_KEY, JSON.stringify({ music: false, musicVolume: 0.6 }));
  assert.equal(readSettings().music, false);
  assert.equal(readSettings().musicVolume, 0.6);
  store.set(SETTINGS_KEY, "invalid");
  assert.deepEqual(readSettings(), {
    sounds: false,
    volume: 0.25,
    music: true,
    musicVolume: 0.3,
  });
  delete globalThis.localStorage;
});
test("backend scoring labels map to the intended filters", () => {
  for (const level of ["No indicators detected", "Low Risk"])
    assert.ok(reportMatches("x", report(level), "", "safe", false));
  for (const level of ["Suspicious", "Use at your own risk"])
    assert.ok(reportMatches("x", report(level), "", "review", false));
  for (const level of ["High Risk", "Dangerous"])
    assert.ok(reportMatches("x", report(level), "", "unsafe", false));
});

test("visibility verdict overrides a low score when filtering", () => {
  const opaque = report("Low Risk");
  opaque.risk_assessment.risk.verdict = "Inconclusive";
  assert.ok(reportMatches("x", opaque, "", "review", false));
  assert.equal(reportMatches("x", opaque, "", "safe", false), false);
});
