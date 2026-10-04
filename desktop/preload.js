"use strict";

// The renderer remains untrusted: no Node integration, filesystem, process,
// bridge credentials, bootstrap key, or direct IPC channel access.
const { contextBridge, ipcRenderer } = require("electron");

contextBridge.exposeInMainWorld("cybersentinelDesktop", Object.freeze({
  isDesktop: true,
  retry: () => ipcRenderer.send("desktop:retry"),
  createOwner: (password) => ipcRenderer.invoke("desktop:create-owner", { password }),
  selectProjectFolder: (payload) => ipcRenderer.invoke("desktop:select-project-folder", payload),
}));
