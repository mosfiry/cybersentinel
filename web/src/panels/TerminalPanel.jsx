import { useState, useRef, useCallback } from "react";
import { submitCommand, cancelRequest } from "../api/bridge.js";
import { ApiError } from "../api/errors.js";

const MAX_LINES = 5000; // bounded terminal rendering

/**
 * Terminal panel. Commands are submitted ONLY through the verified
 * POST /api/command contract (backend authorization applies). Output is
 * rendered from backend responses/streams — nothing executes locally.
 * One-shot command submission exists; an interactive session contract
 * (streaming exec + per-exec cancel) is BLOCKED and documented.
 */
export function TerminalPanel({ tall = false }) {
  const [lines, setLines] = useState([]);
  const [input, setInput] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState(null);
  const [lastRequestId, setLastRequestId] = useState(null);
  const scrollRef = useRef(null);

  const append = useCallback((text, tone = "out") => {
    setLines((ls) => [...ls, { text: String(text), tone }].slice(-MAX_LINES));
  }, []);

  const submit = async () => {
    const text = input.trim();
    if (!text || busy) return;
    setInput("");
    append("$ " + text, "cmd");
    setBusy(true); setError(null);
    try {
      const res = await submitCommand(text);
      const rid = res.request_id || (res.data && res.data.request_id);
      if (rid) setLastRequestId(rid);
      append("submitted — request_id: " + (rid || "not returned"), "meta");
      if (res && typeof res.text === "string") append(res.text);
      if (Array.isArray(res.events)) for (const ev of res.events) append(ev.type || JSON.stringify(ev));
    } catch (e) {
      const err = e instanceof ApiError ? e : new ApiError("server", 0, String(e && e.message || e));
      setError(err);
      append("ERROR [" + err.kind + "]: " + err.message, "err");
    } finally {
      setBusy(false);
      requestAnimationFrame(() => { if (scrollRef.current) scrollRef.current.scrollTop = scrollRef.current.scrollHeight; });
    }
  };

  const cancelLast = async () => {
    if (!lastRequestId) return;
    try { await cancelRequest(lastRequestId); append("cancel requested for " + lastRequestId, "meta"); }
    catch (e) { append("cancel failed: " + (e && e.message), "err"); }
  };

  return (
    <div className={(tall ? "" : "flex h-full ") + "flex min-h-0 h-full flex-col"} dir="ltr">
      <div ref={scrollRef} className="min-h-0 flex-1 overflow-auto bg-slate-950/70 p-2 font-mono text-[11px] leading-[18px]">
        {lines.length === 0 && <div className="text-slate-600">Authorized command submission — POST /api/command (verified contract).</div>}
        {lines.map((l, i) => (
          <div key={i} className={l.tone === "cmd" ? "text-emerald-300" : l.tone === "err" ? "text-rose-300" : l.tone === "meta" ? "text-sky-300" : "text-slate-300"}>
            {l.text}
          </div>
        ))}
      </div>
      {error && <div className="border-t border-slate-800 px-2 py-1 text-[10px] text-rose-300">{error.kind}: {error.message}</div>}
      <div className="flex shrink-0 items-center gap-1 border-t border-slate-800 p-1">
        <span className="pl-1 font-mono text-emerald-400">$</span>
        <input value={input} onChange={(e) => setInput(e.target.value)}
          onKeyDown={(e) => { if (e.key === "Enter") submit(); }}
          disabled={busy}
          aria-label="Command input (backend-authorized execution)"
          placeholder="command…"
          className="min-w-0 flex-1 bg-transparent font-mono text-[11px] text-slate-200 outline-none placeholder:text-slate-600" />
        {lastRequestId && (
          <button onClick={cancelLast} title={"Cancel request " + lastRequestId}
            className="rounded border border-slate-700 px-1.5 py-0.5 text-[10px] text-slate-300 hover:bg-slate-800">
            cancel last
          </button>
        )}
      </div>
    </div>
  );
}
