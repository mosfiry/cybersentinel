// EventTransport — SSE-based live event abstraction over the VERIFIED
// backend SSE streams (GET /api/tasks/{id}/stream, GET /api/chat/stream).
// Contract-agnostic: the backend event payload schema is consumed as-is;
// no events are invented. If the backend later adds WebSocket, only the
// transport implementation inside connect() changes — the UI keeps the
// same interface.
//
// Reconnection policy: exponential backoff with jitter, bounded retries,
// visible connection status, and a resync hook (onResync) so the caller
// can reconcile full state after reconnect — we never assume the last
// event arrived.

export const TransportStatus = Object.freeze({
  CONNECTED: "CONNECTED",
  RECONNECTING: "RECONNECTING",
  DISCONNECTED: "DISCONNECTED",
});

const BASE_DELAY_MS = 800;
const MAX_DELAY_MS = 20000;
const MAX_RETRIES = 6;

export class EventTransport {
  /**
   * openStream: () => Promise<Response>  — must return a fetch Response
   * whose body is an SSE stream (verified backend contract).
   */
  constructor({ openStream, onEvent, onStatus, onResync, dedupeWindow = 500 }) {
    this._openStream = openStream;
    this._onEvent = onEvent || (() => {});
    this._onStatus = onStatus || (() => {});
    this._onResync = onResync || null;
    this._dedupeWindow = dedupeWindow;
    this._status = TransportStatus.DISCONNECTED;
    this._seen = new Set();       // event identity dedupe (id or seq)
    this._retries = 0;
    this._closed = false;
    this._abort = null;
  }

  get status() { return this._status; }

  _setStatus(s) {
    if (this._status !== s) { this._status = s; this._onStatus(s); }
  }

  _seenKey(evt) {
    if (!evt || typeof evt !== "object") return null;
    return evt.event_id || evt.id || evt.seq || evt.request_id + ":" + (evt.type || "") + ":" + (evt.timestamp || "");
  }

  _accept(evt) {
    const key = this._seenKey(evt);
    if (key !== null) {
      if (this._seen.has(key)) return false; // no duplicate event rendering
      this._seen.add(key);
      if (this._seen.size > 5000) { // bounded memory
        const it = this._seen.values(); for (let i = 0; i < 2500; i++) it.next(); this._seen.delete(it.next().value);
      }
    }
    return true;
  }

  /** Parse a text/event-stream chunk buffer. Returns [events, remainder]. */
  static parseSse(buffer) {
    const events = [];
    let rest = buffer;
    for (;;) {
      const idx = rest.indexOf("\n\n");
      if (idx === -1) break;
      const block = rest.slice(0, idx);
      rest = rest.slice(idx + 2);
      const dataLines = block.split("\n").filter((l) => l.startsWith("data:")).map((l) => l.slice(5).trimStart());
      if (!dataLines.length) continue;
      const raw = dataLines.join("\n");
      let evt;
      try { evt = JSON.parse(raw); } catch { evt = { type: "raw", raw }; }
      events.push(evt);
    }
    return [events, rest];
  }

  async start() {
    this._closed = false;
    this._retries = 0;
    this._loop();
  }

  async _loop() {
    while (!this._closed) {
      try {
        this._abort = new AbortController();
        const res = await this._openStream();
        if (!res.ok || !res.body) throw new Error("stream open failed: HTTP " + res.status);
        this._retries = 0;
        this._setStatus(TransportStatus.CONNECTED);
        const reader = res.body.getReader();
        const decoder = new TextDecoder();
        let buffer = "";
        for (;;) {
          const { done, value } = await reader.read();
          if (done) break;
          buffer += decoder.decode(value, { stream: true });
          const [events, rest] = EventTransport.parseSse(buffer);
          buffer = rest;
          for (const evt of events) if (this._accept(evt)) this._onEvent(evt);
        }
        // stream ended gracefully — treat as disconnect then retry
        this._setStatus(TransportStatus.RECONNECTING);
      } catch (e) {
        if (this._closed) return;
        this._setStatus(TransportStatus.RECONNECTING);
      }
      if (this._closed) return;
      this._retries += 1;
      if (this._retries > MAX_RETRIES) {
        this._setStatus(TransportStatus.DISCONNECTED);
        return;
      }
      const delay = Math.min(MAX_DELAY_MS, BASE_DELAY_MS * Math.pow(2, this._retries - 1));
      const jitter = delay * (0.75 + Math.random() * 0.5);
      await new Promise((r) => setTimeout(r, jitter));
      // state reconciliation: after reconnect the caller re-fetches truth
      if (this._onResync) { try { await this._onResync(); } catch {} }
    }
  }

  stop() {
    this._closed = true;
    if (this._abort) this._abort.abort();
    this._setStatus(TransportStatus.DISCONNECTED);
  }
}
