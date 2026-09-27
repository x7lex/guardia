import { spawnSync, execFileSync } from "node:child_process";
import { cpSync, mkdirSync, rmSync, existsSync, realpathSync } from "node:fs";
import { basename, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const web = fileURLToPath(new URL("../", import.meta.url));
const root = resolve(web, "../../..");
const resources = join(web, ".desktop-resources");
const build = join(root, "build/desktop");
const python = process.env.GUARDIA_BUILD_PYTHON || join(root, process.platform === "win32" ? ".venv/Scripts/python.exe" : ".venv/bin/python");
function run(command, args, cwd, env = process.env) {
  const result = spawnSync(command, args, { cwd, env, stdio: "inherit" });
  if (result.error) throw result.error;
  if (result.status !== 0) throw new Error(`${basename(command)} failed (${result.status})`);
}
rmSync(resources, { recursive: true, force: true });
mkdirSync(resources, { recursive: true });
mkdirSync(build, { recursive: true });
// Homebrew Python's SSL needs its matching OpenSSL, rather than YARA's older copy.
const platformBinaries = [];
let macCrypto;
if (process.platform === "darwin") {
  const crypto = execFileSync(python, ["-c", "from ctypes.util import find_library; print(find_library('crypto') or '')"], { encoding: "utf8" }).trim();
  if (crypto && existsSync(crypto)) {
    macCrypto = realpathSync(crypto);
    platformBinaries.push("--add-binary", `${macCrypto}:.`);
  }
}
run(python, ["-m", "PyInstaller", "--noconfirm", "--clean", "--onedir",
  "--name", "guardia-scanner", "--paths", join(root, "src"),
  "--collect-submodules", "backend", "--collect-submodules", "uvicorn",
  "--collect-all", "capstone", "--collect-all", "lief",
  "--distpath", join(build, "dist"), "--workpath", join(build, "work"),
  "--specpath", build, ...platformBinaries, join(root, "scripts/backend_entry.py")], root);
cpSync(join(build, "dist/guardia-scanner"), join(resources, "backend"), { recursive: true, dereference: true });
if (macCrypto) {
  // PyInstaller can still substitute YARA's same-named library during collection.
  const destination = join(resources, "backend/_internal", basename(macCrypto));
  cpSync(macCrypto, destination);
  run("codesign", ["--force", "--sign", "-", destination], root);
}
const env = { ...process.env, GUARDIA_PACKAGE: "1", GUARDIA_DESKTOP: "0" };
run(process.execPath, [join(web, "node_modules/next/dist/bin/next"), "build"], web, env);
const standalone = join(web, ".next/standalone");
if (!existsSync(join(standalone, "server.js"))) throw new Error("Missing standalone Next.js server.js");
cpSync(standalone, join(resources, "web"), {
  recursive: true,
  dereference: true,
  // Never distribute developer credentials that Next copied into standalone output.
  filter: source => !basename(source).startsWith(".env"),
});
cpSync(join(web, "public"), join(resources, "web/public"), { recursive: true });
cpSync(join(web, ".next/static"), join(resources, "web/.next/static"), { recursive: true });
console.log(`Desktop resources prepared for ${process.platform}/${process.arch}`);
