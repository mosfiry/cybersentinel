import { describe, it, expect } from "vitest";
import { createStore, initialRuntimeState, runtimeReducer } from "../src/state/store.js";
import { mapTaskState, TASK_STATE, CONNECTION_MODEL } from "../src/state/lifecycle.js";

describe("runtime reducer", () => {
  it("appends events bounded", () => {
    const s = createStore(initialRuntimeState, runtimeReducer);
    for (let i = 0; i < 2500; i++) s.dispatch({ type: "event/received", event: { event_id: "e" + i } });
    expect(s.getState().events.length).toBeLessThanOrEqual(2000);
  });
  it("records task snapshots and errors separately", () => {
    const s = createStore(initialRuntimeState, runtimeReducer);
    s.dispatch({ type: "task/snapshot", task: { id: "t1", status: "running" } });
    expect(s.getState().task.id).toBe("t1");
    s.dispatch({ type: "task/error", error: { kind: "forbidden" } });
    expect(s.getState().taskError.kind).toBe("forbidden");
  });
});

describe("task state mapping", () => {
  it("maps known states", () => {
    expect(mapTaskState({ status: "running" })).toBe("RUNNING");
    expect(mapTaskState({ status: "paused" })).toBe("PAUSED");
    expect(mapTaskState({ state: "completed" })).toBe("COMPLETED");
  });
  it("maps unknown/missing to UNKNOWN honestly", () => {
    expect(mapTaskState({})).toBe("UNKNOWN");
    expect(mapTaskState(null)).toBe("UNKNOWN");
    expect(mapTaskState({ status: "warp-drive" })).toBe("UNKNOWN");
  });
  it("every state has icon, text and tone (never color alone)", () => {
    for (const [k, v] of Object.entries(TASK_STATE)) {
      expect(v.icon).toBeDefined(); expect(v.text).toBe(k); expect(v.tone).toBeDefined();
    }
    for (const v of Object.values(CONNECTION_MODEL)) { expect(v.icon); expect(v.text); }
  });
});
