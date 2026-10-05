"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");
const vm = require("node:vm");
const { hideWindowOnClose, keepProcessAfterWindowClosure } = require("../background-lifecycle");

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
  assert.ok(pkg.build.files.includes("background-lifecycle.js"));
});

test("closing the window hides to tray while authorized background Missions keep running", () => {
  assert.match(main, /new Tray\(path\.join\(__dirname, "build", "icon\.png"\)\)/);
  assert.match(main, /hideWindowOnClose\(event/);
  assert.match(main, /Quit and stop background Missions/);
  let prevented = false;
  let hidden = false;
  const event = { preventDefault() { prevented = true; } };
  assert.equal(hideWindowOnClose(event, { quitting: false, trayAvailable: true, hide: () => { hidden = true; } }), true);
  assert.equal(prevented, true);
  assert.equal(hidden, true);
  assert.equal(keepProcessAfterWindowClosure({ trayAvailable: true, quitting: false }), true);

  prevented = false;
  hidden = false;
  assert.equal(hideWindowOnClose(event, { quitting: true, trayAvailable: true, hide: () => { hidden = true; } }), false);
  assert.equal(prevented, false);
  assert.equal(hidden, false);
  assert.equal(keepProcessAfterWindowClosure({ trayAvailable: true, quitting: true }), false);

  assert.equal(hideWindowOnClose(event, { quitting: false, trayAvailable: false, hide: () => { hidden = true; } }), false);
  assert.equal(keepProcessAfterWindowClosure({ trayAvailable: false, quitting: false }), false);
});

test("packaged Browser includes pinned Chromium and verifies the bundled runtime", () => {
  const resource = pkg.build.extraResources.find((item) => item.from === "build/browser/ms-playwright");
  assert.ok(resource, "Playwright's managed Chromium cache is included in the installer");
  assert.equal(resource.to, "browser/ms-playwright");
  assert.match(main, /env\.PLAYWRIGHT_BROWSERS_PATH\s*=\s*path\.join\(process\.resourcesPath, "browser", "ms-playwright"\)/);
  const builder = read("scripts/build_desktop_backend.py");
  assert.match(builder, /playwright_version_mismatch/);
  assert.match(builder, /--desktop-browser-self-test/);
  assert.match(builder, /--collect-all[\s\S]*?playwright/);
  const dockerfile = read("Dockerfile");
  assert.match(dockerfile, /PLAYWRIGHT_BROWSERS_PATH=\/ms-playwright/);
  assert.match(dockerfile, /playwright install --with-deps chromium/);
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

test("Mission observability renderer treats hostile graph and event strings as inert text", () => {
  const start = app.indexOf("function renderMissionObservability(");
  const end = app.indexOf("\nasync function loadMoreMissionProgress", start);
  assert.ok(start >= 0 && end > start, "Mission observability renderer is present");
  const renderer = app.slice(start, end);
  assert.match(renderer, /\.textContent\s*=/);
  assert.doesNotMatch(renderer, /\.innerHTML|insertAdjacentHTML|DOMParser|eval\s*\(/);
  assert.doesNotMatch(renderer, /argument_sha256|raw_tool_arguments|\btask\.result\b|\btask\.error\b/);

  const elements = [];
  class Element {
    constructor(tagName) {
      this.tagName = tagName;
      this.children = [];
      this.textContent = "";
      this.className = "";
      this.listeners = {};
      elements.push(this);
    }
    set innerHTML(_value) { throw new Error("HTML parsing is forbidden in this renderer"); }
    appendChild(child) { this.children.push(child); return child; }
    addEventListener(name, callback) { this.listeners[name] = callback; }
  }
  const context = {
    document: { createElement: (tag) => new Element(tag) },
    state: { missionViews: { observabilityError: "" }, selectedMissionId: "mission-safe" },
    errorText: (error) => String(error?.message || ""),
    loadMission: () => {},
    loadMoreMissionProgress: () => {},
  };
  vm.runInNewContext(`${renderer}; globalThis.render = renderMissionObservability;`, context);
  const root = new Element("root");
  const attack = `<img src=x onerror=alert(1)>`;
  context.render({
    stage: { status: attack, current_step: { index: 0, step_id: attack, action: attack, task_status: "RUNNING", specialist_task_id: attack, specialist_task_status: "RUNNING" }, step_count: 1 },
    graph: {
      available: true,
      revision: 1,
      specialist_available: true,
      specialist_revision: 2,
      tasks: [
        { task_id: attack, task_kind: "mission_specialist_analysis", status: "RUNNING", agent_id: attack, agent_role: attack, agent_status: "RUNNING", dependencies: [attack], attempt_count: 1, result_state: "UNVERIFIED", error_category: attack, evidence_refs: [attack] },
      ],
      agents: [],
    },
    evidence_refs: [{ evidence_id: attack, sequence: 1, task_id: attack }],
    evidence_ref_count: 1,
    timeline: { events: [{ type: attack, timestamp: attack, step_ref: attack, error_category: attack }], has_more: false },
    event_log: { events: [{ type: attack, timestamp: attack, tool: attack, task_ref: attack, success: true }], has_more: false },
  }, root);
  const renderedText = elements.map((element) => element.textContent).join("\n");
  assert.ok(renderedText.includes(attack), "untrusted display values are represented only as text");
  assert.equal(elements.length > 0, true);
});

test("Mission evaluation summary renders only whitelisted numbers and opaque evidence references", () => {
  const start = app.indexOf("function renderMissionObservability(");
  const end = app.indexOf("\nasync function loadMoreMissionProgress", start);
  assert.ok(start >= 0 && end > start, "Mission observability renderer is present");
  const renderer = app.slice(start, end);
  assert.match(renderer, /evaluation-summary/);
  assert.match(renderer, /\.textContent\s*=/);
  assert.doesNotMatch(renderer, /\.innerHTML|insertAdjacentHTML|DOMParser|eval\s*\(/);

  const elements = [];
  class Element {
    constructor(tagName) {
      this.tagName = tagName;
      this.children = [];
      this.textContent = "";
      this.className = "";
      this.listeners = {};
      elements.push(this);
    }
    set innerHTML(_value) { throw new Error("HTML parsing is forbidden in this renderer"); }
    appendChild(child) { this.children.push(child); return child; }
    addEventListener(name, callback) { this.listeners[name] = callback; }
  }
  const attack = `<img src=x onerror=alert(1)>`;
  const context = {
    document: { createElement: (tag) => new Element(tag) },
    state: {
      missionViews: {
        observabilityError: "",
        evaluationError: "",
        evaluation: {
          status: "run_recorded",
          verdict: attack,
          metrics: [
            { metric: "task_success", value: attack, verified_evidence_refs: [attack] },
            { metric: attack, value: 1, verified_evidence_refs: ["evref_" + "a".repeat(64)] },
            { metric: "evidence_quality", value: 0.9, verified_evidence_refs: ["evref_" + "b".repeat(64)] },
          ],
        },
      },
      selectedMissionId: "mission-safe",
    },
    errorText: (error) => String(error?.message || ""),
    loadMission: () => {},
    loadMoreMissionProgress: () => {},
  };
  vm.runInNewContext(`${renderer}; globalThis.render = renderMissionObservability;`, context);
  const root = new Element("root");
  context.render({}, root);
  const renderedText = elements.map((element) => element.textContent).join("\n");
  assert.ok(renderedText.includes("task_success: غير مسجّل"));
  assert.ok(renderedText.includes("evref_" + "b".repeat(64)));
  assert.ok(!renderedText.includes(attack), "arbitrary evaluation strings and raw evidence IDs are omitted");
});

test("aggregate evaluation dashboard is navigable and renders hostile fields only as fixed text", () => {
  assert.ok(index.includes('id="evaluationDashboardLink"'));
  assert.ok(app.includes("/api/public/evaluation-dashboard?limit=10"));
  const start = app.indexOf("const EVALUATION_DASHBOARD_METRICS =");
  const end = app.indexOf("\nasync function evaluationDashboardPanel", start);
  assert.ok(start >= 0 && end > start, "aggregate evaluation dashboard renderer is present");
  const renderer = app.slice(start, end);
  assert.match(renderer, /\.textContent\s*=/);
  assert.match(renderer, /Object\.hasOwn\(EVALUATION_DASHBOARD_METRICS/);
  assert.doesNotMatch(renderer, /\.innerHTML|insertAdjacentHTML|DOMParser|eval\s*\(/);

  const elements = [];
  class Element {
    constructor(tagName) {
      this.tagName = tagName;
      this.children = [];
      this.textContent = "";
      this.className = "";
      elements.push(this);
    }
    set innerHTML(_value) { throw new Error("HTML parsing is forbidden in this renderer"); }
    append(...children) { this.children.push(...children); }
    appendChild(child) { this.children.push(child); return child; }
    replaceChildren(...children) { this.children = [...children]; }
  }
  const context = { document: { createElement: (tag) => new Element(tag) } };
  vm.runInNewContext(`${renderer}; globalThis.render = renderEvaluationDashboard;`, context);
  const root = new Element("root");
  const attack = `<img src=x onerror=alert(1)>`;
  context.render(root, {
    status: "available",
    mission_count: 2,
    mission_count_capped: false,
    evaluated_mission_count: 2,
    private_mission_id: "PRIVATE_MISSION_ID",
    metrics: [
      { metric: attack, status: "recorded", value: 1, unit: attack, sample_mission_count: 2 },
      { metric: "task_success", status: attack, value: 0.99, unit: "ratio", sample_mission_count: 999 },
      { metric: "evidence_quality", status: "recorded", value: 0.62, unit: "ratio", sample_mission_count: 1, evidence_refs: ["PRIVATE_EVIDENCE_ID"] },
    ],
  });
  const renderedText = elements.map((element) => element.textContent).join("\n");
  assert.ok(renderedText.includes("0.62 ratio"));
  assert.ok(renderedText.includes("غير متاح"));
  assert.ok(!renderedText.includes(attack), "hostile metric keys/status/value/unit fields never render");
  assert.ok(!renderedText.includes("PRIVATE_MISSION_ID"));
  assert.ok(!renderedText.includes("PRIVATE_EVIDENCE_ID"));

  const emptyRoot = new Element("root");
  context.render(emptyRoot, {
    status: "no_run",
    mission_count: 1,
    mission_count_capped: false,
    evaluated_mission_count: 0,
    metrics: [
      { metric: "task_success", status: "unavailable", value: null, unit: "ratio", sample_mission_count: 0 },
    ],
  });
  const emptyText = elements.map((element) => element.textContent).join("\n");
  assert.ok(emptyText.includes("لا توجد سجلات تقييم متاحة"));
  assert.ok(emptyText.includes("غير متاح"));
  assert.ok(!emptyText.includes("0 ratio"), "an absent run does not become a zero score");
});

test("NSIS installer packages backend and local runtime and has a stable artifact name", () => {
  assert.equal(pkg.version, "5.2.0-rc1");
  assert.deepEqual(pkg.build.win.target, [{ target: "nsis", arch: ["x64"] }]);
  assert.equal(pkg.build.win.icon, "build/icon.ico");
  assert.deepEqual(pkg.build.extraResources.map((resource) => resource.to), ["backend", "llama", "browser/ms-playwright"]);
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
