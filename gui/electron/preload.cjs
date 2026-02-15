const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('astra', {
  connect: () => ipcRenderer.invoke('connect'),
  disconnect: () => ipcRenderer.invoke('disconnect'),
  getStatus: () => ipcRenderer.invoke('get-status'),
  startPing: () => ipcRenderer.invoke('start-ping'),
  onPing: (cb) => {
    ipcRenderer.on('ping', (_, ms) => cb(ms));
  },
  openLogs: () => ipcRenderer.invoke('open-logs'),
});
