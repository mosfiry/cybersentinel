import { describe, it, expect } from "vitest";
import { parseChatSse } from "../src/api/conversation.js";
import { mapMissionState, trajectoryModel, MISSION_STATE, TRAJECTORY_EVENT } from "../src/state/lifecycle.js";

describe("parseChatSse (verified /api/chat/stream wire format)", () => {
  it("parses event name + JSON data blocks", () => {
    const wire = 'event: started\ndata: {"conversation_id":"c1"}\n\n' +
      'event: ToolExecuted\ndata: {"event_type":"ToolExecuted","step_id":"s1","tool":"scanner"}\n\n';
    const [events, rest] = parseChatSse(wire);
    expect(rest).toBe("");
    expect(events).toHaveLength(2);
    expect(events[0].event).toBe("started");
    expect(events[0].data.conversation_id).toBe("c1");
    expect(events[1].event).toBe("ToolExecuted");
    expect(events[1].data.tool).toBe("scanner");
  });

  it("keeps an incomplete block as remainder", () => {
    const wire = 'event: completed\ndata: {"answer":"ok"}\n\nevent: star';
    const [events, rest] = parseChatSse(wire);
    expect(events).toHaveLength(1);
    expect(events[0].event).toBe("completed");
    expect(rest).toBe("event: star");
  });

  it("tolerates non-JSON data without faking a payload", () => {
    const [events] = parseChatSse("data: not-json\n\n");
    expect(events[0].data).toEqual({ raw: "not-json" });
  });
});

describe("mission lifecycle mapping (verified MissionStatus enum)", () => {
  it("maps every backend mission status", () => {
    for (const s of ["CREATED","PLANNING","READY","RUNNING","OBSERVING","VERIFYING","REPLANNING","GOAL_COMPLETED","OWNER_INPUT_REQUIRED","AUTHORIZATION_BLOCKED","SCOPE_BLOCKED","RESOURCE_BLOCKED","RECOVERY_REQUIRED","SAFETY_BLOCKED","FAILED_RETRY_EXHAUSTED","CANCELLED"]) {
      expect(mapMissionState(s)).toBe(s);
      expect(MISSION_STATE[s]).toBeTruthy();
    }
  });

  it("defaults unknown states to UNKNOWN, never invents", () => {
    expect(mapMissionState("SOMETHING_ELSE")).toBe("UNKNOWN");
    expect(mapMissionState(null)).toBe("UNKNOWN");
    expect(mapMissionState({ status: "RUNNING" })).toBe("RUNNING");
    expect(mapMissionState({ mission: { status: "paused" } })).toBe("PAUSED");
  });
});

describe("trajectory display model (structured, no raw chain-of-thought)", () => {
  it("labels verified trajectory events", () => {
    const m = trajectoryModel({ event_type: "ToolExecuted", step_id: "s1", tool: "recon" });
    expect(m.label).toBe("Tool executed");
    expect(m.detail).toContain("step s1");
    expect(m.detail).toContain("tool recon");
  });

  it("never renders ModelTurn content", () => {
    const m = trajectoryModel({ event_type: "ModelTurn", content: "internal reasoning text" });
    expect(m.label).toBe("Model turn");
    expect(m.detail).not.toContain("internal reasoning text");
  });

  it("covers all verified EventType values", () => {
    for (const t of Object.keys(TRAJECTORY_EVENT)) {
      expect(trajectoryModel({ event_type: t }).label).toBeTruthy();
    }
  });
});
