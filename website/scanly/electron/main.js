import { app, BrowserWindow, dialog, ipcMain } from 'electron';
import path from 'path';
import serve from 'electron-serve';

const isDev = process.env.NODE_ENV === 'development';

// Handles rendering the production Next.js static files securely
const loadURL = serve({ directory: 'out' });

let mainWindow;

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
        // Production compiled app strategy
        loadURL(mainWindow);
    }
}

app.whenReady().then(() => {
    ipcMain.handle('select-folders', async (event) => {
        if (!mainWindow || event.sender !== mainWindow.webContents) throw new Error('Unknown window');
        const result = await dialog.showOpenDialog(mainWindow, {
            title: 'Choose folders to scan',
            properties: ['openDirectory', 'multiSelections'],
        });
        return result.canceled ? [] : result.filePaths;
    });
    createWindow();
});

app.on('window-all-closed', () => {
    if (process.platform !== 'darwin') app.quit();
});
