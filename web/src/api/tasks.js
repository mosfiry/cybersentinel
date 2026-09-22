// Task lifecycle over VERIFIED endpoints (POST /api/tasks, GET+stream,
// pause/resume/cancel). In the current backend, "tasks" are the closest
// thing to missions; the UI maps them honestly and never invents mission ids.
import { get, post } from "./client.js";

export async function createTask(payload) {
  const res = await post("/api/tasks", payload);
  return res.data;
}

export async function getTask(taskId, opts) {
  const res = await get("/api/tasks/" + encodeURIComponent(taskId), opts);
  return res.data;
}

export async function controlTask(taskId, action) { // "pause" | "resume" | "cancel"
  const res = await post("/api/tasks/" + encodeURIComponent(taskId) + "/" + action, {});
  return res.data;
}

/** Open the VERIFIED SSE stream for a task. Returns a Response; caller pipes through EventTransport. */
export function openTaskStream(taskId) {
  return fetchTaskSse("/api/tasks/" + encodeURIComponent(taskId) + "/stream");
}

async function fetchTaskSse(path) {
  const { runtimeConfig } = await import("./config.js");
  const headers = { "X-CyberSentinel-Token": runtimeConfig.bridgeToken };
  const o = runtimeConfig.owner;
  if (o.token) headers["X-CyberSentinel-Owner-Token"] = o.token;
  if (o.sessionId) headers["X-CyberSentinel-Owner-Session"] = o.sessionId;
  return fetch(runtimeConfig.baseUrl + path, { headers, credentials: "omit", cache: "no-store" });
}
