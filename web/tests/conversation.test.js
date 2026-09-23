import { describe, it, expect } from "vitest";
import { parseChatSse } from "../src/api/conversation.js";
import { mapMissionState, missionControlState, controlActions, MISSION_STATE, MISSION_CONTROL, MISSION_TERMINAL, trajectoryModel, TRAJECTORY_EVENT } from "../src/state/lifecycle.js";

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

  it("PAUSED is NOT a backend MissionStatus — never mapped as official status", () => {
    expect(MISSION_STATE.PAUSED).toBeUndefined();
    expect(mapMissionState("PAUSED")).toBe("UNKNOWN");
  });

  it("defaults unknown states to UNKNOWN, never invents", () => {
    expect(mapMissionState("SOMETHING_ELSE")).toBe("UNKNOWN");
    expect(mapMissionState(null)).toBe("UNKNOWN");
    expect(mapMissionState({ status: "RUNNING" })).toBe("RUNNING");
    expect(mapMissionState({ mission: { status: "paused" } })).toBe("UNKNOWN"); // lowercase 'paused' is NOT an enum value
  });
});

describe("derived control state (verified pause/resume contract: api/missions.py)", () => {
  // REAL contract: pause sets progress.pause_requested=True AND
  // checkpoint.status="paused" while mission.status may stay RUNNING.
  it("running mission with pause_requested is PAUSE_REQUESTED with resume available", () => {
    const m = { status: "RUNNING", progress: { pause_requested: true }, checkpoint: {} };
    expect(missionControlState(m)).toBe("PAUSE_REQUESTED");
    expect(controlActions(m).resume).toBe(true);
    expect(controlActions(m).pause).toBe(false);
  });

  it("status RUNNING with pause_requested AND checkpoint paused is PAUSED (resume available)", () => {
    const m = { status: "RUNNING", progress: { pause_requested: true }, checkpoint: { status: "paused" } };
    expect(mapMissionState(m)).toBe("RUNNING"); // official status stays RUNNING
    expect(missionControlState(m)).toBe("PAUSED");
    expect(controlActions(m).resume).toBe(true);
  });

  it("checkpoint paused without pause_requested is PAUSED_CHECKPOINT (resume available)", () => {
    const m = { status: "RUNNING", progress: {}, checkpoint: { status: "paused" } };
    expect(missionControlState(m)).toBe("PAUSED_CHECKPOINT");
    expect(controlActions(m).resume).toBe(true);
  });

  it("clean running mission: pause available, resume not", () => {
    const m = { status: "RUNNING", progress: {}, checkpoint: { status: "in_flight" } };
    expect(missionControlState(m)).toBe("RUNNABLE");
    expect(controlActions(m)).toEqual({ pause: true, resume: false, cancel: true });
  });

  it("RECOVERY_REQUIRED: backend refuses resume — UI must NOT offer it", () => {
    const m = { status: "RECOVERY_REQUIRED", progress: {}, checkpoint: { status: "in_flight" } };
    expect(missionControlState(m)).toBe("RECOVERY_REQUIRED");
    expect(controlActions(m).resume).toBe(false);
    expect(controlActions(m).pause).toBe(false);
    expect(controlActions(m).cancel).toBe(false); // terminal for cancel (no transition happens)
  });

  it("terminal missions: no pause/resume/cancel", () => {
    for (const s of MISSION_TERMINAL) {
      if (s === "RECOVERY_REQUIRED") continue; // handled with its own control state
      const m = { status: s, progress: {}, checkpoint: {} };
      expect(missionControlState(m)).toBe("TERMINAL");
      expect(controlActions(m)).toEqual({ pause: false, resume: false, cancel: false });
    }
  });

  it("freshly created mission: IDLE with pause+cancel", () => {
    const m = { status: "CREATED", progress: {}, checkpoint: {} };
    expect(missionControlState(m)).toBe("IDLE");
    expect(controlActions(m).pause).toBe(true);
    expect(controlActions(m).resume).toBe(false);
  });

  it("missing record fields derive honestly (UNKNOWN, no controls)", () => {
    expect(missionControlState(null)).toBe("UNKNOWN");
    expect(missionControlState({})).toBe("UNKNOWN");
    expect(controlActions({}).resume).toBe(false);
  });

  it("every derived control state has icon+text+tone display", () => {
    for (const k of Object.keys(MISSION_CONTROL)) {
      expect(MISSION_CONTROL[k].icon).toBeTruthy();
      expect(MISSION_CONTROL[k].text).toBeTruthy();
      expect(MISSION_CONTROL[k].tone).toBeTruthy();
    }
  });

  it("pause -> resume full cycle over the real record shape", () => {
    // mission running
    let m = { status: "RUNNING", progress: {}, checkpoint: { status: "in_flight" } };
    expect(controlActions(m).pause).toBe(true);
    // backend pause_mission result (verified): progress.pause_requested + checkpoint.status="paused", status unchanged
    m = { status: "RUNNING", progress: { pause_requested: true }, checkpoint: { status: "paused" } };
    expect(missionControlState(m)).toBe("PAUSED");
    expect(controlActions(m).resume).toBe(true);
    // backend resume_mission result (verified): pause_requested popped, mission re-enqueued, status unchanged
    m = { status: "RUNNING", progress: {}, checkpoint: { status: "paused" } };
    expect(controlActions(m).resume).toBe(true); // still resumable if only the checkpoint says paused
    m = { status: "RUNNING", progress: {}, checkpoint: {} };
    expect(controlActions(m).pause).toBe(true);   // back to normal running controls
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
