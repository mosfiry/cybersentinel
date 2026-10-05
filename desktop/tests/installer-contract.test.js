"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");

const root = path.resolve(__dirname, "../..");
const read = (name) => fs.readFileSync(path.join(root, name), "utf8");
const main = read("desktop/main.js");
const preload = read("desktop/preload.js");
const app = read("web/app.js");
const index = read("web/index.html");
const pkg = JSON.parse(read("desktop/package.json"));

test("packaged launch uses bundled executables and durable userData, not Python lookup", () => {
  assert.match(main, /if \(app\.isPackaged\) return null;/);
  assert.match(main, /process\.resourcesPath, "backend", "cybersentinel-backend\.exe"/);
  assert.match(main, /process\.resourcesPath, "llama"/);
  assert.match(main, /app\.getPath\("userData"\)/);
  assert.match(main, /findFreeLoopbackPort/);
  assert.match(main, /env\.BRIDGE_HOST = "127\.0\.0\.1"/);
  assert.doesNotMatch(main, /CYBERSENTINEL_REPO/);
});

test("renderer only receives narrow bootstrap and native-folder IPC methods", () => {
  assert.match(main, /contextIsolation: true/);
  assert.match(preload, /createOwner:/);
  assert.match(preload, /selectProjectFolder:/);
  assert.doesNotMatch(preload, /node:fs|child_process|BRIDGE_TOKEN|SETUP_TOKEN|sessionStorage|localStorage/);
});

test("user workflow exposes projects, model installation/switch, findings and lifecycle", () => {
  for (const marker of [
    "firstRunOverlay",
    "projectList",
    "importProjectFolder",
    "settingsModelList",
    "تنزيل وتثبيت",
    "تشغيل / تبديل إلى هذا النموذج",
    "renderAgentSubtasks",
    "renderMissionReport",
    "report",
    "Evidence",
  ]) {
    assert.ok(app.includes(marker), `missing renderer capability marker: ${marker}`);
  }
  for (const action of ["start", "resume", "pause", "cancel"]) {
    assert.ok(index.includes(`data-mission-action="${action}"`), `missing mission action: ${action}`);
  }
});

test("Owner Skill descriptions and procedure metadata render as inert text", () => {
  const start = app.indexOf("async function skillsPanel()");
  const end = app.indexOf("async function settingsPanel()");
  assert.ok(start >= 0 && end > start, "Skills panel renderer is present");
  const skillsUi = app.slice(start, end);
  assert.match(skillsUi, /description\.textContent\s*=\s*skill\.description/);
  assert.match(skillsUi, /constraints\.textContent\s*=\s*JSON\.stringify/);
  assert.doesNotMatch(skillsUi, /\.innerHTML|insertAdjacentHTML|DOMParser|eval\s*\(/);
  assert.ok(skillsUi.includes("UNTRUSTED") || skillsUi.includes("غير موثوقة"));
  assert.ok(skillsUi.includes("skill.procedure"), "only procedure metadata is presented");
});

test("NSIS installer packages backend and local runtime and has a stable artifact name", () => {
  assert.equal(pkg.version, "5.2.0-rc1");
  assert.deepEqual(pkg.build.win.target, [{ target: "nsis", arch: ["x64"] }]);
  assert.equal(pkg.build.win.icon, "build/icon.ico");
  assert.deepEqual(pkg.build.extraResources.map((resource) => resource.to), ["backend", "llama"]);
  assert.equal(pkg.build.nsis.allowToChangeInstallationDirectory, true);
  assert.equal(pkg.build.nsis.artifactName, "CyberSentinel-v${version}.exe");
});

test("Windows ICO contains a valid PNG-backed 256x256 image resource", () => {
  const icon = fs.readFileSync(path.join(root, "desktop/build/icon.ico"));
  assert.equal(icon.readUInt16LE(0), 0);
  assert.equal(icon.readUInt16LE(2), 1);
  assert.equal(icon.readUInt16LE(4), 1);
  assert.equal(icon[6], 0); // 256 px width
  assert.equal(icon[7], 0); // 256 px height
  assert.equal(icon.readUInt16LE(10), 1);
  assert.equal(icon.readUInt16LE(12), 32);
  assert.equal(icon.readUInt32LE(14), icon.length - 22);
  assert.equal(icon.readUInt32LE(18), 22);
  assert.deepEqual([...icon.subarray(22, 30)], [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);
});
