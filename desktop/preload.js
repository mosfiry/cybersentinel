const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('cybersentinelDesktop', {
  retry: () => ipcRenderer.invoke('csd:retry'),
  getState: () => ipcRenderer.invoke('csd:state'),
  onState: (callback) => ipcRenderer.on('csd:state', (_event, state) => callback(state)),
});
