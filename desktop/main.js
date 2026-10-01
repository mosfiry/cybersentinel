'use strict';

const { app, BrowserWindow, ipcMain, shell, Menu } = require('electron');
const { spawn } = require('child_process');
const http = require('http');
const path = require('path');
const { pathToFileURL } = require('url');

// Desktop shell configuration (all optional; defaults match the existing bridge).
// CYBERSENTINEL_BRIDGE_URL  - base URL of the existing bridge (default http://127.0.0.1:8787)
// CYBERSENTINEL_REPO_DIR     - repository root containing bridge.py (enables auto-start)
// CYBERSENTINEL_PYTHON       - Python interpreter used to start bridge.py (default "python")
// CYBERSENTINEL_AUTOSTART    - "0" disables auto-start; anything else keeps the resolved default
const BRIDGE_URL = (process.env.CYBERSENTINEL_BRIDGE_URL || 'http://127.0.0.1:8787').replace(/\/+$/, '');
const REPO_DIR = process.env.CYBERSENTINEL_REPO_DIR || '';
const PYTHON = process.env.CYBERSENTINEL_PYTHON || 'python';
const AUTOSTART = process.env.CYBERSENTINEL_AUTOSTART !== '0';

let win = null;
let bridge = null;
let bridgeLogs = [];
let pollTimer = null;
let currentState = { phase: 'starting', detail: '', bridgeUrl: BRIDGE_URL, autostart: false };

function isBridgeOrigin(target) {
  return typeof target === 'string' && target.startsWith(BRIDGE_URL + '/');
}

function setState(phase, detail) {
  currentState = Object.assign({}, currentState, { phase, detail: detail || '' });
  if (win && !win.isDestroyed()) {
    win.webContents.send('csd:state', currentState);
  }
}

// Health probe against the existing public endpoint added by PR #17.
function probeBridge() {
  return new Promise((resolve) => {
    const req = http.get(BRIDGE_URL + '/api/public/health', (res) => {
      res.resume();
      resolve({ reachable: true, status: res.statusCode });
    });
    req.setTimeout(2500, () => { req.destroy(new Error('timeout')); });
    req.on('error', () => resolve({ reachable: false, status: 0 }));
  });
}

function resolveRepoDir() {
  if (REPO_DIR) return REPO_DIR;
  if (!app.isPackaged) {
    const candidate = path.join(__dirname, '..');
    if (require('fs').existsSync(path.join(candidate, 'bridge.py'))) return candidate;
  }
  return '';
}

function startBridge() {
  const repoDir = resolveRepoDir();
  if (!repoDir || !AUTOSTART) return false;
  bridge = spawn(PYTHON, ['bridge.py'], {
    cwd: repoDir,
    env: Object.assign({}, process.env),
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  bridgeLogs = [];
  bridge.stdout.on('data', (data) => {
    bridgeLogs.push(String(data));
    if (bridgeLogs.length > 40) bridgeLogs.shift();
  });
  bridge.stderr.on('data', (data) => {
    bridgeLogs.push(String(data));
    if (bridgeLogs.length > 40) bridgeLogs.shift();
  });
  bridge.on('error', (err) => {
    setState('bridge-error', 'Failed to start bridge: ' + err.message);
  });
  bridge.on('exit', (code) => {
    if (currentState.phase !== 'quitting') {
      setState('bridge-exited', 'The bridge process exited with code ' + code + '.');
    }
  });
  return true;
}

function stopBridge() {
  if (bridge) {
    try { bridge.kill(); } catch (err) { /* already gone */ }
    bridge = null;
  }
}

function loadUi() {
  if (!win || win.isDestroyed()) return;
  win.loadURL(BRIDGE_URL + '/').catch(() => {
    showOffline('The bridge could not be loaded.');
  });
}

function showOffline(reason) {
  if (!win || win.isDestroyed()) return;
  win.loadURL(pathToFileURL(path.join(__dirname, 'offline.html')).href).then(() => {
    win.webContents.send('csd:state', currentState);
  }).catch(() => { /* window may be closing */ });
}

async function connectOnce() {
  const probe = await probeBridge();
  if (probe.reachable && probe.status === 200) {
    setState('connected', '');
    loadUi();
    return true;
  }
  if (probe.reachable && probe.status === 404) {
    setState('backend-disabled', 'The bridge is running but the public web boundary is disabled (set PUBLIC_WEB_ENABLED=true in .env and restart the bridge).');
  } else {
    setState('unavailable', 'The CyberSentinel bridge is not reachable at ' + BRIDGE_URL + '.');
  }
  if (win && !win.isDestroyed() && win.webContents.getURL().startsWith('file://')) {
    win.webContents.send('csd:state', currentState);
  }
  return false;
}

function startConnectLoop() {
  let attempts = 0;
  const maxAttempts = 120; // up to ~3 minutes while the bridge boots
  const tick = async () => {
    attempts += 1;
    const ok = await connectOnce();
    if (ok) {
      clearInterval(pollTimer);
      pollTimer = setInterval(async () => {
        const probe = await probeBridge();
        if (!probe.reachable && currentState.phase === 'connected') {
          setState('unavailable', 'The bridge connection was lost.');
          showOffline('The bridge connection was lost.');
        }
      }, 15000);
      return;
    }
    if (attempts === 1) showOffline('');
    if (attempts >= maxAttempts) {
      clearInterval(pollTimer);
      setState('unavailable', 'Timed out waiting for the bridge at ' + BRIDGE_URL + '.' + (bridgeLogs.length ? ' Recent bridge output:\n' + bridgeLogs.slice(-6).join('') : ''));
      showOffline(currentState.detail);
    }
  };
  pollTimer = setInterval(tick, 1500);
  tick();
}

function createWindow() {
  win = new BrowserWindow({
    width: 1280,
    height: 800,
    minWidth: 960,
    minHeight: 600,
    backgroundColor: '#080c12',
    title: 'CyberSentinel Desktop',
    show: false,
    autoHideMenuBar: false,
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: true,
    },
  });
  win.once('ready-to-show', () => win.show());
  win.webContents.on('did-fail-load', () => {
    if (currentState.phase !== 'quitting') showOffline('The bridge UI failed to load.');
  });
  // Desktop is a client: navigation is restricted to the bridge origin.
  win.webContents.on('will-navigate', (event, target) => {
    if (!isBridgeOrigin(target)) {
      event.preventDefault();
      shell.openExternal(target);
    }
  });
  win.webContents.setWindowOpenHandler(({ url: target }) => {
    if (!isBridgeOrigin(target)) shell.openExternal(target);
    return { action: 'deny' };
  });
  startBridge();
  startConnectLoop();
}

if (!app.requestSingleInstanceLock()) {
  app.quit();
} else {
  app.on('second-instance', () => {
    if (win) {
      if (win.isMinimized()) win.restore();
      win.focus();
    }
  });
  app.whenReady().then(() => {
    Menu.setApplicationMenu(Menu.buildFromTemplate([
      { label: 'CyberSentinel', submenu: [{ role: 'reload', label: 'Reload' }, { role: 'quit', label: 'Quit' }] },
      { label: 'Edit', submenu: [{ role: 'cut' }, { role: 'copy' }, { role: 'paste' }, { role: 'selectAll' }] },
      { label: 'View', submenu: [{ role: 'resetZoom' }, { role: 'zoomIn' }, { role: 'zoomOut' }, { type: 'separator' }, { role: 'togglefullscreen' }] },
    ]));
    createWindow();
    app.on('activate', () => { if (BrowserWindow.getAllWindows().length === 0) createWindow(); });
  });
  app.on('before-quit', () => { setState('quitting', ''); stopBridge(); });
  app.on('window-all-closed', () => { app.quit(); });
}

ipcMain.handle('csd:retry', async () => {
  const ok = await connectOnce();
  if (ok) { if (pollTimer) clearInterval(pollTimer); return currentState; }
  if (!bridge && AUTOSTART && resolveRepoDir()) startBridge();
  return currentState;
});
ipcMain.handle('csd:state', () => currentState);
