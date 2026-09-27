import { app, BrowserWindow, dialog, utilityProcess } from 'electron';
import { spawn } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { createServer } from 'node:net';
import { createInterface } from 'node:readline';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
const __dirname = path.dirname(fileURLToPath(import.meta.url));
import fs from 'node:fs';

let window;
let scanner;
let web;
let quitting = false;
let failing = false;
const token = randomBytes(32).toString('hex');
const root = path.resolve(__dirname, '../../../..');
const webRoot = path.resolve(__dirname, '..');

function fail(error) {
  if (quitting || failing) return;
  failing = true;
  dialog.showErrorBox('Guardia could not run', `${error.message}\n\nPlease relaunch Guardia. Diagnostic logs are in ${app.getPath('logs')}.`);
  app.quit();
}

function logOutput(child, name) {
  const log = fs.createWriteStream(path.join(app.getPath('logs'), `${name}.log`), { flags: 'a' });
  child.stdout?.pipe(log, { end: false });
  child.stderr?.pipe(log, { end: false });
  child.once('error', fail);
  child.once('exit', (code) => {
    log.end();
    fail(new Error(`${name} stopped unexpectedly (exit ${code}).`));
  });
}

async function waitReady(url, child) {
  const deadline = Date.now() + 60000;
  while (Date.now() < deadline && !quitting && !failing) {
    try {
      const response = await fetch(url, {
        headers: { 'x-guardia-token': token },
        signal: AbortSignal.timeout(1000),
      });
      if (response.ok) return;
    } catch { /* Service is still starting. */ }
    if (child.exitCode != null) throw new Error('A service exited during startup.');
    await new Promise(resolve => setTimeout(resolve, 150));
  }
  throw new Error('Timed out waiting for the scanner interface to start.');
}

function scannerPort(child) {
  return new Promise((resolve, reject) => {
    const lines = createInterface({ input: child.stdout });
    const timer = setTimeout(() => finish(new Error('Scanner startup timed out.')), 60000);
    function finish(error, port) {
      clearTimeout(timer);
      lines.close();
      child.removeListener('exit', exited);
      child.removeListener('error', finish);
      if (error) reject(error);
      else resolve(port);
    }
    function exited() { finish(new Error('Scanner exited before becoming ready.')); }
    child.once('exit', exited);
    child.once('error', finish);
    lines.on('line', line => {
      try {
        const { port } = JSON.parse(line);
        if (Number.isInteger(port) && port > 0 && port < 65536) finish(null, port);
      } catch { /* Ignore diagnostics before the handshake. */ }
    });
  });
}

async function availablePort() {
  // Keep the origin stable across launches so existing browser scan history survives.
  const portFile = path.join(app.getPath('userData'), 'interface-port.json');
  let preferred = 0;
  try {
    const saved = JSON.parse(fs.readFileSync(portFile, 'utf8'));
    if (Number.isInteger(saved) && saved > 1023 && saved < 65536) preferred = saved;
  } catch { /* First launch. */ }
  async function reserve(port) {
    const server = createServer();
    await new Promise((resolve, reject) => {
      server.once('error', reject);
      server.listen(port, '127.0.0.1', resolve);
    });
    const selected = server.address().port;
    await new Promise(resolve => server.close(resolve));
    return selected;
  }
  let port;
  try { port = await reserve(preferred); }
  catch (error) {
    if (!preferred || error.code !== 'EADDRINUSE') throw error;
    port = await reserve(0);
  }
  fs.writeFileSync(portFile, JSON.stringify(port));
  return port;
}

async function start() {
  app.setAppLogsPath();
  fs.mkdirSync(app.getPath('logs'), { recursive: true });
  const env = {
    ...process.env,
    GUARDIA_DESKTOP_TOKEN: token,
    PYTHONUNBUFFERED: '1',
    GUARDIA_CONFIG_FILE: path.join(app.getPath('appData'), 'Guardia', 'scanner.env'),
  };
  const embeddedWindows = app.isPackaged && process.platform === 'win32' &&
    fs.existsSync(path.join(process.resourcesPath, 'scanner', 'python.exe'));
  const executable = embeddedWindows
    ? path.join(process.resourcesPath, 'scanner', 'python.exe')
    : app.isPackaged
    ? path.join(process.resourcesPath, 'scanner', process.platform === 'win32' ? 'guardia-scanner.exe' : 'guardia-scanner')
    : (process.env.GUARDIA_PYTHON || path.join(root, '.venv', process.platform === 'win32' ? 'Scripts/python.exe' : 'bin/python'));
  const scannerArgs = embeddedWindows
    ? [path.join(process.resourcesPath, 'scanner', 'app', 'desktop_server.py')]
    : app.isPackaged ? [] : [path.join(root, 'src/desktop_server.py')];
  scanner = spawn(executable, scannerArgs, {
    env, cwd: app.getPath('userData'), stdio: ['pipe', 'pipe', 'pipe'], windowsHide: true,
  });
  const portPromise = scannerPort(scanner);
  logOutput(scanner, 'scanner');
  const backendPort = await portPromise;
  const backendURL = `http://127.0.0.1:${backendPort}`;
  await waitReady(`${backendURL}/health`, scanner);
  const webPort = await availablePort();
  const origin = `http://127.0.0.1:${webPort}`;
  const directory = app.isPackaged ? path.join(process.resourcesPath, 'web') : path.join(webRoot, '.next/standalone');
  web = utilityProcess.fork(path.join(directory, 'server.js'), [], {
    cwd: directory,
    env: { ...env, NODE_ENV: 'production', HOSTNAME: '127.0.0.1', PORT: String(webPort), BACKEND_URL: backendURL },
    stdio: 'pipe', serviceName: 'Guardia interface',
  });
  logOutput(web, 'interface');
  await waitReady(origin, web);
  if (quitting || failing) return;
  window = new BrowserWindow({
    width: 1200, height: 850, minWidth: 850, minHeight: 600, title: 'Guardia',
    show: false,
    webPreferences: { nodeIntegration: false, contextIsolation: true, sandbox: true },
  });
  window.webContents.session.webRequest.onBeforeSendHeaders({ urls: [`${origin}/*`] }, (details, callback) => {
    details.requestHeaders['x-guardia-token'] = token;
    callback({ requestHeaders: details.requestHeaders });
  });
  window.webContents.session.setPermissionRequestHandler((_contents, _permission, callback) => callback(false));
  window.webContents.setWindowOpenHandler(() => ({ action: 'deny' }));
  window.webContents.on('will-navigate', (event, url) => {
    if (new URL(url).origin !== origin) event.preventDefault();
  });
  window.once('ready-to-show', () => window.show());
  await window.loadURL(origin);
}

if (!app.requestSingleInstanceLock()) {
  app.quit();
} else {
  app.on('second-instance', () => { if (window) { window.restore(); window.focus(); } });
  app.on('before-quit', event => {
    if (quitting) return;
    quitting = true;
    event.preventDefault();
    web?.kill();
    if (!scanner || scanner.exitCode != null || scanner.signalCode != null) {
      app.quit();
      return;
    }
    // Bound shutdown even if a native parser is busy with a large upload.
    const timer = setTimeout(() => scanner.kill('SIGKILL'), 3000);
    scanner.once('exit', () => { clearTimeout(timer); app.quit(); });
    scanner.stdin?.end();
    scanner.kill();
  });
  app.on('window-all-closed', () => app.quit());
  app.whenReady().then(start).catch(fail);
}
