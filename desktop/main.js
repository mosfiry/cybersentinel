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
const { fileURLToPath } = require("node:url");

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
let bridgeStopPromise = null;
let shutdownPending = false;
let shutdownComplete = false;

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

const BACKEND_ENV_ALLOWLIST = [
  "PATH", "SYSTEMROOT", "WINDIR", "TEMP", "TMP", "HOME", "USERPROFILE",
  "APPDATA", "LOCALAPPDATA", "PYTHONUTF8",
  "PYTHONIOENCODING", "BRIDGE_PORT", "DB_PATH", "TASK_DB_PATH", "MEMORY_DB_PATH",
  "KNOWLEDGE_DB_PATH", "SCOPE_DB_PATH", "OWNER_POLICY_STATE_PATH",
  "PUBLIC_SESSION_COOKIE", "PUBLIC_OWNER_SESSION_COOKIE",
  "PUBLIC_SESSION_TTL_SECONDS", "CYBERSENTINEL_SECRETS_DIR", "BRIDGE_TOKEN_FILE",
  "LLM_API_KEY_FILE", "LOCAL_LLM_API_KEY_FILE", "COLAB_LLM_API_KEY_FILE",
  "HF_LLM_API_KEY_FILE", "LLM_BASE_URL", "LLM_MODEL", "LOCAL_LLM_BASE_URL",
  "LOCAL_LLM_MODEL", "COLAB_LLM_BASE_URL", "COLAB_LLM_MODEL", "HF_LLM_BASE_URL",
  "HF_LLM_MODEL",
];

function bridgeEnvironment() {
  // Python loads the private .env and secret files itself; Electron forwards
  // only an explicit allowlist that excludes all credential values.
  const env = {};
  for (const key of BACKEND_ENV_ALLOWLIST) {
    if (process.env[key] !== undefined) env[key] = process.env[key];
  }
  env.BRIDGE_HOST = "127.0.0.1";
  env.PUBLIC_WEB_ENABLED = "true";
  env.PUBLIC_WEB_ORIGIN = "";
  env.BRIDGE_ALLOW_NON_LOOPBACK_BIND = "false";
  return env;
}

function resolvePort(env) {
  const parsed = Number.parseInt(String(env.BRIDGE_PORT || DEFAULT_PORT), 10);
  if (Number.isInteger(parsed) && parsed > 0 && parsed < 65536) return parsed;
  return DEFAULT_PORT;
}

async function startBridge(root, env) {
  await stopBridge();
  const python = process.env[PYTHON_ENV_KEY] || DEFAULT_PYTHON;
  bridgeProcess = spawn(python, ["bridge.py", "--desktop-stdio-control"], {
    cwd: root,
    env,
    stdio: ["pipe", "pipe", "pipe"],
  });
  // Drain child pipes without forwarding arbitrary backend/provider output to
  // the shell's terminal or installer logs.
  bridgeProcess.stdout.resume();
  bridgeProcess.stderr.resume();
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
  if (bridgeStopPromise) return bridgeStopPromise;
  const child = bridgeProcess;
  if (!child) return Promise.resolve();
  bridgeProcess = null;
  bridgeStopPromise = new Promise((resolve) => {
    let settled = false;
    const forceTimer = setTimeout(() => {
      if (settled) return;
      try {
        child.kill("SIGKILL");
      } catch (error) {
        // The child may have exited while the grace timer was pending.
      }
    }, 10000);
    if (typeof forceTimer.unref === "function") forceTimer.unref();
    const finish = () => {
      if (settled) return;
      settled = true;
      clearTimeout(forceTimer);
      resolve();
    };
    child.once("exit", finish);
    child.once("error", finish);
    try {
      if (child.stdin && child.stdin.writable) {
        child.stdin.end("CYBERSENTINEL_DESKTOP_SHUTDOWN\n");
      } else {
        child.kill("SIGTERM");
      }
    } catch (error) {
      try {
        child.kill("SIGTERM");
      } catch (killError) {
        finish();
      }
    }
  }).finally(() => {
    bridgeStopPromise = null;
  });
  return bridgeStopPromise;
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

function isUnavailableFile(url) {
  try {
    const parsed = new URL(url);
    if (parsed.protocol !== "file:") return false;
    const candidate = path.resolve(fileURLToPath(parsed));
    const expected = path.resolve(__dirname, "unavailable.html");
    return process.platform === "win32"
      ? candidate.toLowerCase() === expected.toLowerCase()
      : candidate === expected;
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

function guardNavigation(event, url) {
  if (isAppOrigin(url) || isUnavailableFile(url)) return;
  event.preventDefault();
  if (url.startsWith("http://") || url.startsWith("https://")) shell.openExternal(url);
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
  mainWindow.webContents.on("will-navigate", guardNavigation);
  mainWindow.webContents.on("will-redirect", guardNavigation);
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
    const env = bridgeEnvironment();
    bridgePort = resolvePort(env);
    await startBridge(root, env);
    const healthy = await waitUntilHealthy(bridgePort);
    if (quitting) return;
    if (healthy && mainWindow) {
      mainWindow.loadURL(`${appOrigin()}/`);
    } else {
      showUnavailable("backend-unavailable", String(bridgePort));
      await stopBridge();
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
  app.quit();
});

app.on("before-quit", (event) => {
  quitting = true;
  if (!shutdownComplete && (bridgeProcess || bridgeStopPromise)) {
    event.preventDefault();
    if (!shutdownPending) {
      shutdownPending = true;
      Promise.resolve(bridgeStopPromise || stopBridge()).finally(() => {
        shutdownComplete = true;
        app.quit();
      });
    }
  } else {
    shutdownComplete = true;
  }
});
