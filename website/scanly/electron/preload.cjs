const { contextBridge, ipcRenderer, webUtils } = require('electron');

contextBridge.exposeInMainWorld('electronAPI', {
    selectFolders: () => ipcRenderer.invoke('select-folders'),
    getPathForFile: (file) => webUtils.getPathForFile(file),
});
