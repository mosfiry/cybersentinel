"use strict";

// CyberSentinel Desktop — Electron shell.
//
// Contract: the desktop application is a thin client over the existing
// CyberSentinel backend. It starts the checked-in bridge server
// (python bridge.py, loopback-only) and loads the served web client from
// http://127.0.0.1:<BRIDGE_PORT>/ so that the browser security contract
// (same-origin, server-side Owner sessions, CSRF, HttpOnly cookies) is
// preserved exactly. The desktop process never handles Owner credentials,
// bridge tokens, or authorization state itself.

const { app, BrowserWindow, Menu, ipcMain, shell } = require("electron");
const { spawn } = require("child_process");
const fs = require("node:fs");
const http = require("node:http");
const path = require("node:path");

const PYTHON_ENV_KEY = "CYBERSENTINEL_PYTHON";
const REPO_ENV_KEY = "CYBERSENTINEL_REPO";
const DEFAULT_PYTHON = "python";
const DEFAULT_PORT = 8787;
const HEALTH_START_TIMEOUT_MS = 60000;
const HEALTH_POLL_INTERVAL_MS = 600;
const REQUEST_TIMEOUT_MS = 1500;

let mainWindow = null;
let bridgeProcess = null;
let bridgePort = DEFAULT_PORT;
let startupRunning = false;
let quitting = false;

function repoRoot() {
  const candidates = [];
  if (process.env[REPO_ENV_KEY]) candidates.push(process.env[REPO_ENV_KEY]);
  candidates.push(path.resolve(app.getAppPath(), ".."));
  candidates.push(process.cwd());
  for (const candidate of candidates) {
    try {
      if (fs.existsSync(path.join(candidate, "bridge.py"))) return candidate;
    } catch (error) {
      // Unreadable candidate; keep searching.
    }
  }
  return null;
}

function parseDotEnv(text) {
  const result = {};
  for (const rawLine of text.split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line || line.startsWith("#")) continue;
    const separator = line.indexOf("=");
    if (separator <= 0) continue;
    const key = line.slice(0, separator).trim();
    let value = line.slice(separator + 1).trim();
    if (value.length >= 2) {
      const first = value[0];
      const last = value[value.length - 1];
      if ((first === '"' && last === '"') || (first === "'" && last === "'")) {
        value = value.slice(1, -1);
      }
    }
    if (key) result[key] = value;
  }
  return result;
}

function bridgeEnvironment(root) {
  // Start from the desktop process environment so an operator-provided
  // BRIDGE_TOKEN keeps working, then overlay the repository .env file.
  // The bridge itself fails closed when BRIDGE_TOKEN is missing.
  const env = {};
  for (const [key, value] of Object.entries(process.env)) env[key] = value;
  const envPath = path.join(root, ".env");
  try {
    if (fs.existsSync(envPath)) {
      Object.assign(env, parseDotEnv(fs.readFileSync(envPath, "utf8")));
    }
  } catch (error) {
    // The .env file is optional; the backend fail-closed rules still apply.
  }
  env.BRIDGE_HOST = "127.0.0.1";
  env.PUBLIC_WEB_ENABLED = "true";
  return env;
}

function resolvePort(env) {
  const parsed = Number.parseInt(String(env.BRIDGE_PORT || DEFAULT_PORT), 10);
  if (Number.isInteger(parsed) && parsed > 0 && parsed < 65536) return parsed;
  return DEFAULT_PORT;
}

function startBridge(root, env) {
  stopBridge();
  const python = process.env[PYTHON_ENV_KEY] || DEFAULT_PYTHON;
  bridgeProcess = spawn(python, ["bridge.py"], {
    cwd: root,
    env,
    stdio: ["ignore", "pipe", "pipe"],
  });
  bridgeProcess.stdout.on("data", (chunk) => {
    process.stdout.write(`[bridge] ${chunk}`);
  });
  bridgeProcess.stderr.on("data", (chunk) => {
    process.stderr.write(`[bridge] ${chunk}`);
  });
  bridgeProcess.on("exit", (code) => {
    bridgeProcess = null;
    if (!quitting) {
      showUnavailable("backend-exited", code === null ? "unknown" : String(code));
    }
  });
  bridgeProcess.on("error", () => {
    bridgeProcess = null;
    if (!quitting) showUnavailable("python-missing", "");
  });
}

function stopBridge() {
  if (bridgeProcess) {
    const child = bridgeProcess;
    bridgeProcess = null;
    try {
      child.kill();
    } catch (error) {
      // The process may already be gone.
    }
  }
}

function healthRequest(port) {
  return new Promise((resolve) => {
    const request = http.get(
      { host: "127.0.0.1", port, path: "/api/health", timeout: REQUEST_TIMEOUT_MS },
      (response) => {
        response.resume();
        resolve(response.statusCode === 200);
      }
    );
    request.on("timeout", () => {
      request.destroy();
      resolve(false);
    });
    request.on("error", () => resolve(false));
  });
}

function delay(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function waitUntilHealthy(port) {
  const deadline = Date.now() + HEALTH_START_TIMEOUT_MS;
  while (Date.now() < deadline) {
    if (await healthRequest(port)) return true;
    if (bridgeProcess === null) return false;
    await delay(HEALTH_POLL_INTERVAL_MS);
  }
  return false;
}

function appOrigin() {
  return `http://127.0.0.1:${bridgePort}`;
}

function isAppOrigin(url) {
  try {
    const parsed = new URL(url);
    return parsed.origin === appOrigin();
  } catch (error) {
    return false;
  }
}

function showUnavailable(reason, detail) {
  if (!mainWindow) return;
  if (isAppOrigin(mainWindow.webContents.getURL())) return;
  mainWindow.loadFile(path.join(__dirname, "unavailable.html"), {
    query: { reason: reason || "backend-unavailable", detail: detail || "" },
  });
}

function createWindow() {
  mainWindow = new BrowserWindow({
    width: 1440,
    height: 920,
    minWidth: 1024,
    minHeight: 700,
    backgroundColor: "#0b0f14",
    title: "CyberSentinel X",
    icon: path.join(__dirname, "build", "icon.png"),
    show: false,
    autoHideMenuBar: false,
    webPreferences: {
      preload: path.join(__dirname, "preload.js"),
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: true,
    },
  });
  mainWindow.once("ready-to-show", () => mainWindow.show());
  mainWindow.webContents.on("will-navigate", (event, url) => {
    if (isAppOrigin(url) || url.startsWith("file://")) return;
    event.preventDefault();
    if (url.startsWith("http://") || url.startsWith("https://")) shell.openExternal(url);
  });
  mainWindow.webContents.setWindowOpenHandler(({ url }) => {
    if (url.startsWith("http://") || url.startsWith("https://")) shell.openExternal(url);
    return { action: "deny" };
  });
  mainWindow.on("closed", () => {
    mainWindow = null;
  });
}

function buildMenu() {
  const template = [
    {
      label: "CyberSentinel",
      submenu: [
        { role: "reload", label: "Reload UI" },
        { role: "togglefullscreen" },
        { type: "separator" },
        { role: "quit", label: "Quit" },
      ],
    },
  ];
  Menu.setApplicationMenu(Menu.buildFromTemplate(template));
}

async function startup() {
  if (startupRunning) return;
  startupRunning = true;
  try {
    const root = repoRoot();
    if (!root) {
      showUnavailable("missing-repository", "");
      return;
    }
    const env = bridgeEnvironment(root);
    bridgePort = resolvePort(env);
    startBridge(root, env);
    const healthy = await waitUntilHealthy(bridgePort);
    if (quitting) return;
    if (healthy && mainWindow) {
      mainWindow.loadURL(`${appOrigin()}/`);
    } else {
      showUnavailable("backend-unavailable", String(bridgePort));
    }
  } finally {
    startupRunning = false;
  }
}

ipcMain.on("desktop:retry", () => {
  startup();
});

app.whenReady().then(() => {
  buildMenu();
  createWindow();
  startup();
});

app.on("window-all-closed", () => {
  quitting = true;
  stopBridge();
  app.quit();
});

app.on("before-quit", () => {
  quitting = true;
  stopBridge();
});
