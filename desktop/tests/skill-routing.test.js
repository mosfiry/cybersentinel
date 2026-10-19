"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");
const vm = require("node:vm");
const app = fs.readFileSync(path.resolve(__dirname, "../../web/app.js"), "utf8");

class Element {
  constructor(tagName) {
    this.tagName = tagName;
    this.children = [];
    this.textContent = "";
    this.value = "";
    this.disabled = false;
  }
  set innerHTML(_value) { throw new Error("Untrusted mission content must not be parsed as HTML"); }
  replaceChildren() { this.children = []; }
  appendChild(child) { this.children.push(child); return child; }
}

function overview(mission) {
  const root = new Element("root");
  const context = {
    $: () => root,
    document: { createElement: (tag) => new Element(tag) },
    state: { selectedMission: mission, missionViews: {} },
  };
  const start = app.indexOf("function renderMissionView(");
  const end = app.indexOf("function renderMissionObservability(", start);
  assert.ok(start >= 0 && end > start);
  vm.runInNewContext(`${app.slice(start, end)}; globalThis.render = renderMissionView;`, context);
  context.render("overview");
  return root.children.map((child) => child.textContent).join("\n");
}

test("routed Mission overview renders skill, lexical reason, current step and error only as text", () => {
  const hostile = '<img src=x onerror=alert("no")>';
  const rendered = overview({
    status: "READY", owner_instruction: hostile, current_step: 0,
    plan: { steps: [{ step_id: "step-1", action: "status" }] },
    error: "controlled failure", checkpoint: { status: "ready" },
    skill_routing: { outcome: "selected", reason_code: "eligible_positive_match", skill_id: hostile, version: 2 },
    skill_binding: { skill_id: hostile, version: 2 },
  });
  assert.ok(rendered.includes(hostile));
  assert.ok(rendered.includes("step-1 · status"));
  assert.ok(rendered.includes("controlled failure"));
  assert.ok(rendered.includes("أعلى تطابق كلمات مؤهل دون تعادل"));
  assert.ok(rendered.includes("الإصدار 2"));
});

test("abstained and unknown routing reasons never render external reason text", () => {
  const rendered = overview({
    status: "READY",
    skill_routing: { outcome: "ambiguous", reason_code: "top_score_tie" },
  });
  assert.ok(rendered.includes("لم تُختر مهارة"));
  assert.ok(rendered.includes("تعادل بين أفضل التطابقات"));
  const hostile = "external instruction must not become a reason";
  assert.ok(!overview({ skill_routing: { outcome: "unknown", reason_code: hostile } }).includes(hostile));
});

test("automatic routing disables explicit selector without hiding approval lifecycle requirements", () => {
  const selector = new Element("select");
  const checkbox = { checked: true };
  const context = {
    document: {
      querySelector: (query) => query === "#missionSkill" ? selector : checkbox,
      createElement: (tag) => new Element(tag),
    },
    state: {
      ownerAuthenticated: true,
      skills: [
        { status: "approved", active: true, skill_id: "active", name: "Status", version: 1 },
        { status: "candidate", active: false, skill_id: "candidate", name: "Not approved", version: 1 },
      ],
    },
  };
  const start = app.indexOf("function renderMissionSkillOptions(");
  const end = app.indexOf("async function loadSkills(", start);
  vm.runInNewContext(`${app.slice(start, end)}; globalThis.render = renderMissionSkillOptions;`, context);
  context.render();
  assert.equal(selector.disabled, true);
  assert.deepEqual(selector.children.map((child) => child.value), ["", "active"]);
  checkbox.checked = false;
  context.render();
  assert.equal(selector.disabled, false);
  context.state.ownerAuthenticated = false;
  context.render();
  assert.equal(selector.disabled, true);
});
