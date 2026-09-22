// Remaining VERIFIED endpoints: status, tools, execution lifecycle,
// owner-only reasoning memory, request cancel, command submission.
import { get, post } from "./client.js";

export async function health() { const r = await get("/api/health"); return r.data; }
export async function engineStatus() { const r = await get("/api/status"); return r.data; }
export async function toolRegistry() { const r = await get("/api/tools"); return r.data; }
export async function executionLifecycle(requestId) {
  const r = await get("/api/execution/" + encodeURIComponent(requestId));
  return r.data;
}
/** Owner-only (backend enforces verify_owner — 403 for non-owners). */
export async function reasoningMemory(requestId) {
  const r = await get("/api/reasoning/" + encodeURIComponent(requestId));
  return r.data;
}
export async function cancelRequest(requestId) {
  const r = await post("/api/cancel", { request_id: requestId });
  return r.data;
}
/** Submit a command; returns { ok, request_id, ... } — stream via EventTransport. */
export async function submitCommand(text, requestId) {
  const r = await post("/api/command", { text, request_id: requestId || "" });
  return r.data;
}
