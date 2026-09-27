import { app, BrowserWindow, dialog, ipcMain } from 'electron';
import path from 'path';
import { createServer } from 'node:http';
import { readFile } from 'node:fs/promises';

const isDev = process.env.NODE_ENV === 'development';

let mainWindow;
let webServer;
let productionURL;

async function startWebsite() {
    // The upload and review proxies need a Next server, including in the desktop app.
    const { default: next } = await import('next');
    const directory = app.getAppPath();
    const { config } = JSON.parse(await readFile(path.join(directory, '.next/required-server-files.json'), 'utf8'));
    const website = next({ dev: false, dir: directory, conf: config });
    await website.prepare();
    webServer = createServer(website.getRequestHandler());
    await new Promise((resolve, reject) => {
        webServer.once('error', reject);
        webServer.listen(0, '127.0.0.1', resolve);
    });
    productionURL = `http://127.0.0.1:${webServer.address().port}`;
}

function createWindow() {
    mainWindow = new BrowserWindow({
        width: 1200,
        height: 800,
        webPreferences: {
            preload: path.join(app.getAppPath(), 'electron/preload.cjs'),
            contextIsolation: true,
            nodeIntegration: false,
        },
    });

    if (isDev) {
        // Hooks right into your active Next.js development build
        mainWindow.loadURL('http://localhost:3000');
        mainWindow.webContents.openDevTools();
    } else {
        mainWindow.loadURL(productionURL);
    }
}

app.whenReady().then(async () => {
    ipcMain.handle('select-folders', async (event) => {
        if (!mainWindow || event.sender !== mainWindow.webContents) throw new Error('Unknown window');
        const result = await dialog.showOpenDialog(mainWindow, {
            title: 'Choose folders to scan',
            properties: ['openDirectory', 'multiSelections'],
        });
        return result.canceled ? [] : result.filePaths;
    });
    if (!isDev) await startWebsite();
    createWindow();
}).catch(error => {
    dialog.showErrorBox('Could not start Guardia', error.message);
    app.quit();
});

app.on('before-quit', () => webServer?.close());

app.on('window-all-closed', () => {
    if (process.platform !== 'darwin') app.quit();
});
