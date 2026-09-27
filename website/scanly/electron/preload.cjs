const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('electronAPI', {
    selectFolders: () => ipcRenderer.invoke('select-folders'),
});
