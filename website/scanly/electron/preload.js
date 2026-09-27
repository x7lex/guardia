import { contextBridge, ipcRenderer } from 'electron';

// Expose secure functions to your Next.js client-side code
contextBridge.exposeInMainWorld('electronAPI', {
    sayHello: () => console.log("Hello from Electron!"),
});
