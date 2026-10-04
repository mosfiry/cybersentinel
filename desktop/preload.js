"use strict";

// CyberSentinel Desktop — preload.
//
// The renderer is the existing CyberSentinel web client served by the
// bridge. It stays untrusted: no Node integration, no bridge tokens, no
// Owner credentials, no filesystem or process access. The only added
// surface is the retry signal for the desktop unavailable state.

const { contextBridge, ipcRenderer } = require("electron");

contextBridge.exposeInMainWorld("cybersentinelDesktop", {
  isDesktop: true,
  retry: () => ipcRenderer.send("desktop:retry"),
});
