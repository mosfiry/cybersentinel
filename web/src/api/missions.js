// Mission lifecycle over VERIFIED /api/missions* contracts (bridge.py on main).
// The agent owns planning/reasoning/tool selection; the UI only surfaces
// mission state, timeline, evidence and owner lifecycle actions.
import { get, post } from "./client.js";

const ACTION_KEYS = { status: "status", timeline: "timeline", evidence: "evidence", artifacts: "artifacts", logs: "logs" };

async function missionFetch(missionId, action) {
  const r = await get("/api/missions/" + encodeURIComponent(missionId) + "/" + action);
  const key = ACTION_KEYS[action];
  const value = r.data && r.data[key];
  return value === undefined ? r.data : value;
}

export async function missionStatus(missionId) { return missionFetch(missionId, "status"); }
export async function missionTimeline(missionId) { return missionFetch(missionId, "timeline"); }
export async function missionEvidence(missionId) { return missionFetch(missionId, "evidence"); }
export async function missionArtifacts(missionId) { return missionFetch(missionId, "artifacts"); }
export async function missionLogs(missionId) { return missionFetch(missionId, "logs"); }

/** start|resume|pause|cancel (VERIFIED POST /api/missions/{id}/{action}). */
export async function controlMission(missionId, action) {
  const r = await post("/api/missions/" + encodeURIComponent(missionId) + "/" + action, {});
  return r.data;
}
