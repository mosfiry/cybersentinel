// Conversational contract — VERIFIED against api/chat.py + bridge.py on main.
// The Owner writes natural language; the backend agent does understanding,
// planning, authorization, tool selection, execution and verification.
// The UI renders structured progress and the final answer — never raw
// chain-of-thought, never invented events.
import { runtimeConfig } from "./config.js";
import { get, post } from "./client.js";
import { ApiError, ErrorKind } from "./errors.js";
import { newRequestId } from "./util.js";

/**
 * Parse an SSE buffer for the chat stream. Bridge emits blocks of
 *   event: <name>\ndata: <json>\n\n
 * Returns [{ event, data }, ...] and the unconsumed remainder.
 */
export function parseChatSse(buffer) {
  const events = [];
  let rest = buffer;
  for (;;) {
    const idx = rest.indexOf("\n\n");
    if (idx === -1) break;
    const block = rest.slice(0, idx);
    rest = rest.slice(idx + 2);
    let name = "message";
    const dataLines = [];
    for (const line of block.split("\n")) {
      if (line.startsWith("event:")) name = line.slice(6).trim();
      else if (line.startsWith("data:")) dataLines.push(line.slice(5).trimStart());
    }
    if (!dataLines.length) continue;
    let data;
    try { data = JSON.parse(dataLines.join("\n")); }
    catch { data = { raw: dataLines.join("\n") }; }
    events.push({ event: name, data });
  }
  return [events, rest];
}

/** Open the VERIFIED GET /api/chat/stream SSE endpoint. Returns a Response. */
export function openConversationStream(text, conversationId) {
  const qs = new URLSearchParams({
    text: String(text || ""),
    conversation_id: String(conversationId || ""),
  });
  const headers = {
    "X-CyberSentinel-Token": runtimeConfig.bridgeToken,
    "X-Request-Id": newRequestId(),
  };
  const o = runtimeConfig.owner;
  if (o.token) headers["X-CyberSentinel-Owner-Token"] = o.token;
  if (o.sessionId) headers["X-CyberSentinel-Owner-Session"] = o.sessionId;
  if (o.challenge) headers["X-CyberSentinel-Owner-Challenge"] = o.challenge;
  return fetch(runtimeConfig.baseUrl + "/api/chat/stream?" + qs.toString(), {
    headers, credentials: "omit", cache: "no-store",
  });
}

/**
 * Run one conversational turn end-to-end over the verified stream:
 * 'started' -> per-activity events -> 'completed'. Resolves with the
 * completed payload ({conversation_id, answer, mission_id, status,
 * activity, mission}) or null if the stream ended without completion —
 * callers must treat null as failure, never as success.
 */
export async function runConversation(text, { conversationId, onEvent } = {}) {
  const res = await openConversationStream(text, conversationId);
  if (!res.ok || !res.body) {
    const kind = res.status === 401 ? ErrorKind.UNAUTHORIZED
      : res.status === 403 ? ErrorKind.FORBIDDEN : ErrorKind.SERVER;
    throw new ApiError(kind, res.status, "chat stream open failed: HTTP " + res.status);
  }
  const reader = res.body.getReader();
  const decoder = new TextDecoder();
  let buffer = "";
  let completed = null;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    buffer += decoder.decode(value, { stream: true });
    const [events, rest] = parseChatSse(buffer);
    buffer = rest;
    for (const evt of events) {
      if (onEvent) { try { onEvent(evt); } catch {} }
      if (evt.event === "completed") completed = evt.data;
    }
  }
  return completed;
}

/**
 * POST /api/missions (VERIFIED chat path) — blocking, supports mission
 * resume via { text, conversation_id, mission_id }. Response carries the
 * full mission record; the answer, if any, is read from mission progress
 * (last_model_content) honestly — absent content is never invented.
 */
export async function continueMission(text, { conversationId, missionId } = {}) {
  const r = await post("/api/missions", {
    text: String(text || ""),
    conversation_id: String(conversationId || ""),
    mission_id: String(missionId || ""),
  });
  const mission = r.data && r.data.mission;
  let answer = "";
  if (mission && mission.progress && typeof mission.progress.last_model_content === "string") {
    answer = mission.progress.last_model_content;
    try {
      const parsed = JSON.parse(answer);
      if (parsed && typeof parsed === "object") answer = String(parsed.content || parsed.answer || answer);
    } catch {}
  }
  return { mission, missionId: r.data && r.data.mission_id, status: r.data && r.data.status, answer };
}

/** GET /api/session/{id} (VERIFIED, owner-only) — conversation history. */
export async function getConversation(conversationId) {
  const r = await get("/api/session/" + encodeURIComponent(conversationId));
  return r.data;
}
