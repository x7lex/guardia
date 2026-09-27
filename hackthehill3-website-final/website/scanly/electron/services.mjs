import { utilityProcess } from "electron";
import { spawn } from "node:child_process";
import { createServer } from "node:net";
import { join } from "node:path";
import { createWriteStream } from "node:fs";

async function requireFreePort(port) {
  await new Promise((resolve, reject) => {
    const probe = createServer();
    probe.once("error", () => reject(new Error(`Port ${port} is busy. Close the other Guardia instance and retry.`)));
    probe.listen(port, "127.0.0.1", () => probe.close(resolve));
  });
}

export async function startServices(resources, userData, onFailure) {
  await requireFreePort(3765);
  await requireFreePort(8765);
  const log = createWriteStream(join(userData, "services.log"), { flags: "a" });
  const children = [];
  let stopping = false;
  let failure;
  function watch(child, name) {
    children.push(child);
    child.stdout?.pipe(log, { end: false });
    child.stderr?.pipe(log, { end: false });
    const failed = (message) => {
      if (stopping) return;
      failure = new Error(`${name}: ${message}. See ${join(userData, "services.log")}`);
      onFailure(failure);
    };
    child.on("error", error => failed(error.message));
    child.on("exit", code => failed(`exited (${code})`));
  }
  async function stop() {
    if (stopping) return;
    stopping = true;
    await Promise.all(children.map(child => new Promise(resolve => {
      if (!child.pid || child.exitCode != null) return resolve();
      const timer = setTimeout(() => { child.kill(); resolve(); }, 5000);
      child.once("exit", () => { clearTimeout(timer); resolve(); });
      child.kill();
    })));
    log.end();
  }
  try {
    const env = { ...process.env, BACKEND_HOST: "127.0.0.1", BACKEND_PORT: "8765",
      BACKEND_URL: "http://127.0.0.1:8765", PORT: "3765", HOSTNAME: "127.0.0.1",
      NODE_ENV: "production" };
    delete env.ELECTRON_RUN_AS_NODE;
    const scanner = join(resources, "backend", process.platform === "win32" ? "guardia-scanner.exe" : "guardia-scanner");
    watch(spawn(scanner, [], { env, cwd: userData, windowsHide: true, stdio: ["ignore", "pipe", "pipe"] }), "Scanner");
    watch(utilityProcess.fork(join(resources, "web", "server.js"), [], {
      env, cwd: join(resources, "web"), stdio: "pipe", serviceName: "Guardia frontend",
    }), "Frontend");
    const deadline = Date.now() + 60000;
    for (const url of ["http://127.0.0.1:8765/health", "http://127.0.0.1:3765/"]) {
      while (true) {
        if (failure) throw failure;
        if (Date.now() > deadline) throw new Error(`Startup timed out. See ${join(userData, "services.log")}`);
        try {
          if ((await fetch(url, { signal: AbortSignal.timeout(1000) })).ok) break;
        } catch { /* The service may still be loading. */ }
        await new Promise(resolve => setTimeout(resolve, 200));
      }
    }
    if (failure) throw failure;
    return stop;
  } catch (error) {
    await stop();
    throw error;
  }
}
