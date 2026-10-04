"use strict";

// CyberSentinel Desktop. Packaged builds contain the Python backend and the
// local llama.cpp CPU runtime as signed-by-hash build resources. End users do
// not need Python, Node, Docker, WSL, or a terminal.

const { app, BrowserWindow, Menu, ipcMain, shell, dialog } = require("electron");
const { spawn } = require("child_process");
const crypto = require("node:crypto");
const fs = require("node:fs");
const http = require("node:http");
const net = require("node:net");
const path = require("node:path");
const { fileURLToPath } = require("node:url");

const DEFAULT_PORT = 8787;
const HEALTH_START_TIMEOUT_MS = 90000;
const HEALTH_POLL_INTERVAL_MS = 600;
const REQUEST_TIMEOUT_MS = 1500;
const OWNER_SETUP_TIMEOUT_MS = 30000;

let mainWindow = null;
let bridgeProcess = null;
let bridgePort = DEFAULT_PORT;
let bridgeToken = "";
let desktopSetupToken = "";
let startupRunning = false;
let quitting = false;
let bridgeStopPromise = null;
let shutdownPending = false;
let shutdownComplete = false;

function repoRoot() {
  if (app.isPackaged) return null;
  const candidates = [path.resolve(app.getAppPath(), ".."), process.cwd()];
  for (const candidate of candidates) {
    try {
      if (fs.existsSync(path.join(candidate, "bridge.py"))) return candidate;
    } catch (error) {
      // Keep searching; an unreadable developer directory is not fatal.
    }
  }
  return null;
}

function appOrigin() {
  return `http://127.0.0.1:${bridgePort}`;
}

function isAppOrigin(url) {
  try {
    return new URL(url).origin === appOrigin();
  } catch (error) {
    return false;
  }
}

function trustedIpcSender(event) {
  return Boolean(event && event.senderFrame && isAppOrigin(event.senderFrame.url));
}

async function findFreeLoopbackPort() {
  const server = net.createServer();
  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolve);
  });
  const address = server.address();
  const port = address && typeof address === "object" ? address.port : 0;
  await new Promise((resolve) => server.close(resolve));
  if (!Number.isInteger(port) || port <= 0) throw new Error("loopback_port_unavailable");
  return port;
}

function createUserDataDirectories() {
  const root = app.getPath("userData");
  const state = path.join(root, "state");
  for (const directory of [root, state, path.join(root, "secrets"), path.join(root, "workspaces"), path.join(root, "local-model-manager")]) {
    fs.mkdirSync(directory, { recursive: true });
  }
  return { root, state };
}

const DEV_BACKEND_ENV_ALLOWLIST = [
  "PATH", "SYSTEMROOT", "WINDIR", "TEMP", "TMP", "HOME", "USERPROFILE",
  "APPDATA", "LOCALAPPDATA", "PYTHONUTF8", "PYTHONIOENCODING",
  "PUBLIC_SESSION_COOKIE", "PUBLIC_OWNER_SESSION_COOKIE", "PUBLIC_SESSION_TTL_SECONDS",
  "CYBERSENTINEL_SECRETS_DIR", "BRIDGE_TOKEN_FILE", "LLM_API_KEY_FILE",
  "LOCAL_LLM_API_KEY_FILE", "COLAB_LLM_API_KEY_FILE", "HF_LLM_API_KEY_FILE",
  "LLM_BASE_URL", "LLM_MODEL", "LOCAL_LLM_BASE_URL", "LOCAL_LLM_MODEL",
  "COLAB_LLM_BASE_URL", "COLAB_LLM_MODEL", "HF_LLM_BASE_URL", "HF_LLM_MODEL",
];

const OS_BACKEND_ENV_ALLOWLIST = [
  "PATH", "SYSTEMROOT", "WINDIR", "TEMP", "TMP", "HOME", "USERPROFILE",
  "APPDATA", "LOCALAPPDATA", "HOMEDRIVE", "HOMEPATH",
];

function bridgeEnvironment() {
  const { root, state } = createUserDataDirectories();
  const env = {};
  for (const key of OS_BACKEND_ENV_ALLOWLIST) {
    if (process.env[key] !== undefined) env[key] = process.env[key];
  }
  if (!app.isPackaged) {
    for (const key of DEV_BACKEND_ENV_ALLOWLIST) {
      if (process.env[key] !== undefined) env[key] = process.env[key];
    }
  }
  env.BRIDGE_HOST = "127.0.0.1";
  env.BRIDGE_PORT = String(bridgePort);
  env.BRIDGE_TOKEN = bridgeToken;
  env.BRIDGE_ALLOW_NON_LOOPBACK_BIND = "false";
  env.PUBLIC_WEB_ENABLED = "true";
  env.PUBLIC_WEB_ORIGIN = "";
  env.CYBERSENTINEL_DESKTOP_MODE = "true";
  env.CYBERSENTINEL_DESKTOP_SETUP_TOKEN = desktopSetupToken;
  env.CYBERSENTINEL_MODEL_ROOT = path.join(root, "local-model-manager");
  env.CYBERSENTINEL_LLM_RUNTIME_DIR = app.isPackaged
    ? path.join(process.resourcesPath, "llama")
    : path.join(app.getAppPath(), "build", "llama");
  env.CYBERSENTINEL_SECRETS_DIR = path.join(root, "secrets");
  env.DB_PATH = path.join(state, "intel.sqlite3");
  env.TASK_DB_PATH = path.join(state, "tasks.sqlite3");
  env.MEMORY_DB_PATH = path.join(state, "memory.sqlite3");
  env.KNOWLEDGE_DB_PATH = path.join(state, "knowledge.sqlite3");
  env.SCOPE_DB_PATH = path.join(state, "scope.sqlite3");
  env.OWNER_POLICY_STATE_PATH = path.join(state, "owner-policy.json");
  env.PYTHONUTF8 = "1";
  env.PYTHONIOENCODING = "utf-8";
  return env;
}

async function startBridge(env) {
  await stopBridge();
  let command;
  let args;
  let cwd;
  if (app.isPackaged) {
    command = path.join(process.resourcesPath, "backend", "cybersentinel-backend.exe");
    args = ["--desktop-stdio-control"];
    cwd = app.getPath("userData");
    if (!fs.existsSync(command)) throw new Error("bundled_backend_missing");
  } else {
    const root = repoRoot();
    if (!root) throw new Error("developer_repository_missing");
    command = process.env.CYBERSENTINEL_PYTHON || "python";
    args = [path.join(root, "bridge.py"), "--desktop-stdio-control"];
    cwd = root;
  }
  bridgeProcess = spawn(command, args, {
    cwd,
    env,
    windowsHide: true,
    stdio: ["pipe", "pipe", "pipe"],
  });
  // Child output may contain local diagnostics; never forward it to renderer,
  // installer logs, or the user's terminal.
  bridgeProcess.stdout.resume();
  bridgeProcess.stderr.resume();
  bridgeProcess.on("exit", (code) => {
    bridgeProcess = null;
    if (!quitting) showUnavailable("backend-exited", code === null ? "unknown" : String(code));
  });
  bridgeProcess.on("error", () => {
    bridgeProcess = null;
    if (!quitting) showUnavailable("backend-start-failed", "");
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
        // The process may already have stopped.
      }
    }, 12000);
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
      if (child.stdin && child.stdin.writable) child.stdin.end("CYBERSENTINEL_DESKTOP_SHUTDOWN\n");
      else child.kill("SIGTERM");
    } catch (error) {
      try { child.kill("SIGTERM"); } catch (killError) { finish(); }
    }
  }).finally(() => { bridgeStopPromise = null; });
  return bridgeStopPromise;
}

function healthRequest(port) {
  return new Promise((resolve) => {
    const request = http.get({
      host: "127.0.0.1",
      port,
      path: "/api/health",
      timeout: REQUEST_TIMEOUT_MS,
      headers: { "X-CyberSentinel-Token": bridgeToken },
    }, (response) => {
      response.resume();
      resolve(response.statusCode === 200);
    });
    request.on("timeout", () => { request.destroy(); resolve(false); });
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

function unavailablePagePath() {
  return path.join(__dirname, "unavailable.html");
}

function isUnavailableFile(url) {
  try {
    const parsed = new URL(url);
    if (parsed.protocol !== "file:") return false;
    const candidate = path.resolve(fileURLToPath(parsed));
    const expected = path.resolve(unavailablePagePath());
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
  mainWindow.loadFile(unavailablePagePath(), {
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
      devTools: !app.isPackaged,
    },
  });
  mainWindow.once("ready-to-show", () => mainWindow.show());
  mainWindow.webContents.on("will-navigate", guardNavigation);
  mainWindow.webContents.on("will-redirect", guardNavigation);
  mainWindow.webContents.setWindowOpenHandler(({ url }) => {
    if (url.startsWith("http://") || url.startsWith("https://")) shell.openExternal(url);
    return { action: "deny" };
  });
  mainWindow.on("closed", () => { mainWindow = null; });
}

function buildMenu() {
  Menu.setApplicationMenu(Menu.buildFromTemplate([{
    label: "CyberSentinel",
    submenu: [
      { role: "reload", label: "Reload UI" },
      { role: "togglefullscreen" },
      { type: "separator" },
      { role: "quit", label: "Quit" },
    ],
  }]));
}

function postOwnerBootstrap(password) {
  return new Promise((resolve, reject) => {
    const body = Buffer.from(JSON.stringify({ password }), "utf8");
    const request = http.request({
      host: "127.0.0.1",
      port: bridgePort,
      method: "POST",
      path: "/api/desktop/bootstrap-owner",
      timeout: OWNER_SETUP_TIMEOUT_MS,
      headers: {
        "Content-Type": "application/json",
        "Content-Length": body.length,
        Origin: appOrigin(),
        "X-CyberSentinel-Setup-Key": desktopSetupToken,
      },
    }, (response) => {
      const chunks = [];
      let size = 0;
      response.on("data", (chunk) => {
        size += chunk.length;
        if (size > 65536) request.destroy(new Error("setup_response_too_large"));
        else chunks.push(chunk);
      });
      response.on("end", () => {
        let data = {};
        try { data = JSON.parse(Buffer.concat(chunks).toString("utf8")); } catch (error) {}
        if (response.statusCode < 200 || response.statusCode >= 300) {
          reject(new Error(String(data.error || "owner_setup_failed")));
          return;
        }
        resolve({ ok: true, owner_created: data.owner_created === true });
      });
    });
    request.on("timeout", () => request.destroy(new Error("owner_setup_timeout")));
    request.on("error", (error) => reject(error));
    request.end(body);
  });
}

function postSelectedProject(payload, selectedRoot, cookieHeader) {
  return new Promise((resolve, reject) => {
    const body = Buffer.from(JSON.stringify({
      name: payload.name,
      description: payload.description || "",
      selected_root: selectedRoot,
    }), "utf8");
    const request = http.request({
      host: "127.0.0.1",
      port: bridgePort,
      method: "POST",
      path: "/api/public/projects/import",
      timeout: OWNER_SETUP_TIMEOUT_MS,
      headers: {
        "Content-Type": "application/json",
        "Content-Length": body.length,
        Origin: appOrigin(),
        Cookie: cookieHeader,
        "X-CSRF-Token": payload.csrfToken,
        "X-CyberSentinel-Desktop-Capability": desktopSetupToken,
      },
    }, (response) => {
      const chunks = [];
      let size = 0;
      response.on("data", (chunk) => {
        size += chunk.length;
        if (size > 65536) request.destroy(new Error("project_response_too_large"));
        else chunks.push(chunk);
      });
      response.on("end", () => {
        let data = {};
        try { data = JSON.parse(Buffer.concat(chunks).toString("utf8")); } catch (error) {}
        if (response.statusCode < 200 || response.statusCode >= 300) {
          reject(new Error(String(data.error || "project_import_failed")));
          return;
        }
        resolve({ ok: true, project: data.project || null });
      });
    });
    request.on("timeout", () => request.destroy(new Error("project_import_timeout")));
    request.on("error", (error) => reject(error));
    request.end(body);
  });
}

ipcMain.on("desktop:retry", (event) => {
  if (trustedIpcSender(event)) startup();
});

ipcMain.handle("desktop:create-owner", async (event, payload) => {
  if (!trustedIpcSender(event)) throw new Error("desktop_setup_unavailable");
  if (!payload || typeof payload.password !== "string" || payload.password.length < 12 || payload.password.length > 256) {
    throw new Error("password_must_be_12_to_256_characters");
  }
  return postOwnerBootstrap(payload.password);
});

ipcMain.handle("desktop:select-project-folder", async (event, payload) => {
  if (!trustedIpcSender(event) || !mainWindow) throw new Error("desktop_folder_picker_unavailable");
  if (!payload || typeof payload.name !== "string" || !payload.csrfToken) throw new Error("project_name_and_session_required");
  const result = await dialog.showOpenDialog(mainWindow, {
    title: "اختر مجلد المشروع الذي سيعمل ضمن حدوده فقط",
    buttonLabel: "استخدام هذا المجلد",
    properties: ["openDirectory"],
  });
  if (result.canceled || !result.filePaths || !result.filePaths[0]) return { cancelled: true };
  const cookies = await event.sender.session.cookies.get({ url: `${appOrigin()}/api/public` });
  const cookieHeader = cookies.map((item) => `${item.name}=${item.value}`).join("; ");
  if (!cookieHeader) throw new Error("owner_session_required");
  return postSelectedProject(payload, result.filePaths[0], cookieHeader);
});

async function startup() {
  if (startupRunning || quitting) return;
  startupRunning = true;
  try {
    if (!app.isPackaged && !repoRoot()) {
      showUnavailable("developer-repository-missing", "");
      return;
    }
    bridgePort = await findFreeLoopbackPort();
    bridgeToken = crypto.randomBytes(32).toString("base64url");
    desktopSetupToken = crypto.randomBytes(32).toString("base64url");
    const env = bridgeEnvironment();
    await startBridge(env);
    const healthy = await waitUntilHealthy(bridgePort);
    if (quitting) return;
    if (healthy && mainWindow) mainWindow.loadURL(`${appOrigin()}/`);
    else {
      showUnavailable("backend-unavailable", "");
      await stopBridge();
    }
  } catch (error) {
    showUnavailable("backend-start-failed", "");
    await stopBridge();
  } finally {
    startupRunning = false;
  }
}

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
