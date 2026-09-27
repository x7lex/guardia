import { app, BrowserWindow, dialog, shell } from "electron";
import { startServices } from "./services.mjs";

app.setName("Guardia");
let mainWindow;
let stopServices;
let quitting = false;
const bundledResources = app.isPackaged ? process.resourcesPath : process.env.GUARDIA_TEST_RESOURCES;
const address = new URL(bundledResources ? "http://127.0.0.1:3765" : process.env.GUARDIA_DESKTOP_URL || "http://127.0.0.1:3765");
if (address.protocol !== "http:" || address.hostname !== "127.0.0.1") {
  throw new Error("Guardia desktop requires its local server.");
}

app.whenReady().then(async () => {
  if (bundledResources) {
    let ready = false;
    stopServices = await startServices(bundledResources, app.getPath("userData"), error => {
      if (!ready || quitting) return;
      if (process.env.GUARDIA_TEST_RESOURCES) console.error(error);
      else dialog.showErrorBox("Guardia service stopped", error.message);
      app.quit();
    });
    ready = true;
  }
  const window = mainWindow = new BrowserWindow({
    title: "Guardia",
    width: 1280,
    height: 900,
    minWidth: 800,
    minHeight: 600,
    backgroundColor: "#fffdf5",
    show: false,
    autoHideMenuBar: true,
    webPreferences: { nodeIntegration: false, contextIsolation: true, sandbox: true },
  });
  window.webContents.session.setPermissionRequestHandler((_contents, _permission, callback) => callback(false));
  window.webContents.setWindowOpenHandler(({ url }) => {
    if (url === "https://ai.studio/projects") void shell.openExternal(url);
    return { action: "deny" };
  });
  window.webContents.on("will-navigate", (event, url) => {
    if (new URL(url).origin !== address.origin) event.preventDefault();
  });
  window.once("ready-to-show", () => window.show());
  window.on("closed", () => { mainWindow = null; });
  await window.loadURL(address.href);
}).catch((error) => {
  if (process.env.GUARDIA_TEST_RESOURCES) console.error(error);
  else dialog.showErrorBox("Guardia could not start", error.message);
  process.exitCode = 1;
  app.quit();
});

// Closing the window exits the launcher and its owned Python/Next processes.
app.on("window-all-closed", () => app.quit());
app.on("activate", () => mainWindow?.show());
app.on("before-quit", event => {
  if (!stopServices || quitting) return;
  event.preventDefault();
  quitting = true;
  void stopServices().finally(() => app.quit());
});
