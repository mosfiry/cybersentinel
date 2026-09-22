import { describe, it, expect } from "vitest";
import { EventTransport, TransportStatus } from "../src/events/EventTransport.js";

function sseResponse(chunks, { ok = true } = {}) {
  const enc = new TextEncoder();
  let i = 0;
  return {
    ok,
    status: ok ? 200 : 500,
    body: { getReader: () => ({ read: async () =>
      i < chunks.length ? { done: false, value: enc.encode(chunks[i++]) } : { done: true, value: undefined } }) },
  };
}

describe("EventTransport.parseSse", () => {
  it("parses data-only SSE blocks", () => {
    const [events, rest] = EventTransport.parseSse('data: {"type":"a"}\n\ndata: {"type":"b"}\n\n');
    expect(events).toEqual([{ type: "a" }, { type: "b" }]);
    expect(rest).toBe("");
  });
  it("keeps partial block in remainder", () => {
    const [events, rest] = EventTransport.parseSse('data: {"type":"a"}\n\ndata: {"type":"b"}');
    expect(events).toEqual([{ type: "a" }]);
    expect(rest).toBe('data: {"type":"b"}');
  });
  it("treats non-JSON data as raw event (no invention, no crash)", () => {
    const [events] = EventTransport.parseSse("data: hello\n\n");
    expect(events[0].type).toBe("raw");
    expect(events[0].raw).toBe("hello");
  });
});

describe("EventTransport dedupe + status", () => {
  it("drops duplicate events (no duplicate rendering)", async () => {
    const seen = [];
    const t = new EventTransport({
      openStream: async () => sseResponse(['data: {"event_id":"e1","type":"x"}\n\ndata: {"event_id":"e1","type":"x"}\n\n']),
      onEvent: (e) => seen.push(e),
      onStatus: () => {},
    });
    t._closed = true; // prevent reconnect loop in unit context
    t._loop = async function () {}; // neutralize
    // drive parsing directly
    const res = await t._openStream();
    const reader = res.body.getReader();
    const dec = new TextDecoder();
    let buffer = "";
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      buffer += dec.decode(value, { stream: true });
      const [events, rest] = EventTransport.parseSse(buffer);
      buffer = rest;
      for (const e of events) if (t._accept(e)) seen.push(e);
    }
    expect(seen.length).toBe(1);
  });
  it("maps graceful stream end to RECONNECTING", () => {
    const statuses = [];
    const t = new EventTransport({ openStream: async () => sseResponse([]), onEvent: () => {}, onStatus: (s) => statuses.push(s) });
    t._setStatus(TransportStatus.RECONNECTING);
    expect(t.status).toBe(TransportStatus.RECONNECTING);
  });
});
