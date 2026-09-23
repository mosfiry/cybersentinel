import { useState, useRef, useCallback, useEffect } from "react";
import { runtimeConfig, setBridgeToken, setOwnerCredentials } from "../api/config.js";
import { runConversation, continueMission } from "../api/conversation.js";
import { controlMission, missionStatus } from "../api/missions.js";
import { mapMissionState, missionControlState, controlActions, MISSION_CONTROL } from "../state/lifecycle.js";
import { MissionChip, MissionControlChip, TrajectoryView, MissionSummary } from "../components/MissionView.jsx";
import { ApiError } from "../api/errors.js";

/**
 * The conversational CyberSentinel experience. The Owner writes natural
 * language; the backend agent understands, plans, authorizes, selects
 * tools, executes, observes and verifies. The UI renders:
 *   - the conversation (user / assistant messages)
 *   - structured agent progress (verified trajectory events, no raw CoT)
 *   - mission lifecycle state and owner lifecycle actions
 * Pause/Resume follows the REAL backend contract: pause is recorded in
 * progress.pause_requested + checkpoint.status == "paused" while
 * mission.status may stay RUNNING. The official status chip and the
 * derived control chip are therefore shown side by side.
 */
export function ChatPanel() {
  const [authed, setAuthed] = useState(Boolean(runtimeConfig.baseUrl && runtimeConfig.bridgeToken && (runtimeConfig.owner.token || runtimeConfig.owner.sessionId)));
  const [bridgeTokenInput, setBridgeTokenInput] = useState(runtimeConfig.bridgeToken);
  const [ownerTokenInput, setOwnerTokenInput] = useState(runtimeConfig.owner.token);

  const [messages, setMessages] = useState([]);
  const [liveActivity, setLiveActivity] = useState([]);
  const [phase, setPhase] = useState("idle");
  const [mission, setMission] = useState(null);
  const [conversationId, setConversationId] = useState("");
  const [input, setInput] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState(null);
  const scrollRef = useRef(null);

  const scrollToBottom = () => requestAnimationFrame(() => {
    if (scrollRef.current) scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
  });
  useEffect(scrollToBottom, [messages, liveActivity]);

  const configure = () => {
    setBridgeToken(bridgeTokenInput);
    setOwnerCredentials({ token: ownerTokenInput });
    setAuthed(Boolean(runtimeConfig.baseUrl && runtimeConfig.bridgeToken && runtimeConfig.owner.token));
  };

  // Conversational resume is the verified path for an owner decision
  // (OWNER_INPUT_REQUIRED). It is NOT offered for other states.
  const isResume = mission !== null && mapMissionState(mission) === "OWNER_INPUT_REQUIRED";

  const send = async () => {
    const text = input.trim();
    if (!text || busy) return;
    if (!authed) { setError(new ApiError("unauthorized", 0, "owner credentials required for chat")); return; }
    setInput(""); setError(null); setBusy(true); setPhase("understanding");
    setMessages((m) => [...m, { role: "user", text }]);
    const activity = [];
    try {
      if (isResume) {
        // Verified blocking resume path: POST /api/missions { text, conversation_id, mission_id }.
        const res = await continueMission(text, { conversationId, missionId: mission.mission_id });
        const st = res.status || (res.mission && res.mission.status) || "";
        setMission(res.mission ? res.mission : { mission_id: res.missionId, status: st });
        setMessages((m) => [...m, {
          role: "assistant",
          text: res.answer || "Mission " + st,
          mission_id: res.missionId, status: st,
        }]);
        setPhase("completed");
      } else {
        // Verified streaming path: GET /api/chat/stream (SSE started -> activity -> completed).
        const completed = await runConversation(text, {
          conversationId,
          onEvent: (evt) => {
            if (evt.event === "started") { setPhase("understanding"); return; }
            if (evt.event === "completed") return;
            activity.push(evt.data && typeof evt.data === "object" ? evt.data : { event: evt.event });
            setLiveActivity([...activity]);
            const t = evt.data && (evt.data.event_type || evt.data.event);
            if (t === "PlanCreated") setPhase("planning");
            else if (t === "ToolExecuted" || t === "ToolProposed") setPhase("executing");
            else if (t === "ObservationReceived" || t === "ObservationInterpreted") setPhase("inspecting");
            else if (t === "ReplanTriggered" || t === "PlanRevised") setPhase("replanning");
            else if (t === "GoalVerificationStarted" || t === "GoalVerified") setPhase("verifying");
            else if (t === "OwnerInputRequired") setPhase("needs owner");
          },
        });
        if (!completed) throw new ApiError("server", 0, "chat stream ended without completion — result unknown, not faked");
        if (completed.conversation_id) setConversationId(completed.conversation_id);
        const missionRec = completed.mission || null;
        setMission(missionRec || { mission_id: completed.mission_id, status: completed.status });
        setMessages((m) => [...m, {
          role: "assistant",
          text: completed.answer || "Mission " + completed.status,
          mission_id: completed.mission_id, status: completed.status,
          trajectory: (missionRec && missionRec.trajectory) || completed.activity || [],
        }]);
        setPhase("completed");
      }
    } catch (e) {
      const err = e instanceof ApiError ? e : new ApiError("server", 0, String((e && e.message) || e));
      setError(err);
      setMessages((m) => [...m, { role: "assistant", text: "ERROR [" + err.kind + "]: " + err.message, error: true }]);
      setPhase("error");
    } finally {
      setBusy(false);
      setLiveActivity([]);
    }
  };

  const doControl = async (action) => {
    if (!mission || !mission.mission_id || busy) return;
    try {
      const res = await controlMission(mission.mission_id, action);
      const rec = res && res.mission;
      if (rec) setMission(rec); else setMission((m) => ({ ...m, status: res && res.status || m.status }));
    } catch (e) { setError(e instanceof ApiError ? e : new ApiError("server", 0, String((e && e.message) || e))); }
  };

  if (!authed) {
    return (
      <div className="flex h-full items-center justify-center p-6" dir="ltr">
        <div className="w-full max-w-sm rounded border border-slate-800 bg-slate-900/60 p-4">
          <div className="mb-1 text-sm font-semibold text-slate-200">Owner authorization</div>
          <div className="mb-3 text-[11px] text-slate-500">
            Chat requires the verified owner contract. Credentials are kept in memory only — never in the bundle or localStorage — and the backend remains the authority.
          </div>
          <label className="mb-1 block text-[10px] text-slate-400" htmlFor="bridge-token">Bridge token</label>
          <input id="bridge-token" type="password" value={bridgeTokenInput} onChange={(e) => setBridgeTokenInput(e.target.value)}
            className="mb-2 w-full rounded border border-slate-700 bg-slate-900 px-2 py-1 text-[11px] outline-none focus:border-emerald-600" />
          <label className="mb-1 block text-[10px] text-slate-400" htmlFor="owner-token">Owner token</label>
          <input id="owner-token" type="password" value={ownerTokenInput} onChange={(e) => setOwnerTokenInput(e.target.value)}
            className="mb-3 w-full rounded border border-slate-700 bg-slate-900 px-2 py-1 text-[11px] outline-none focus:border-emerald-600" />
          <button onClick={configure}
            className="w-full rounded border border-emerald-600/50 bg-emerald-500/10 px-2 py-1 text-[11px] text-emerald-300 hover:bg-emerald-500/20">
            Authorize this session
          </button>
          {error && <div className="mt-2 text-[10px] text-rose-300">{error.message}</div>}
        </div>
      </div>
    );
  }

  const missionState = mapMissionState(mission);
  const ctrl = mission ? controlActions(mission) : { pause: false, resume: false, cancel: false };
  const controlKey = mission ? missionControlState(mission) : null;
  const needsOwner = missionState === "OWNER_INPUT_REQUIRED";
  const recoveryNeeded = missionState === "RECOVERY_REQUIRED";

  return (
    <div className="flex h-full min-h-0 flex-col" dir="ltr">
      {/* conversation */}
      <div ref={scrollRef} className="min-h-0 flex-1 overflow-auto px-4 py-3">
        {messages.length === 0 && (
          <div className="mt-6 text-center text-[11px] text-slate-500">
            <div className="mb-1 text-sm text-slate-300">Talk to CyberSentinel</div>
            Describe the objective in your own words. The agent understands, plans, requests
            authorization, chooses tools, executes, observes, verifies and reports — you do not
            need tool names, endpoints or plans.
          </div>
        )}
        <div className="mx-auto max-w-3xl space-y-3">
          {messages.map((msg, i) => (
            <div key={i} className={msg.role === "user" ? "flex justify-end" : "flex justify-start"}>
              <div className={"max-w-[85%] rounded-lg px-3 py-2 text-xs leading-5 " + (msg.role === "user"
                ? "bg-emerald-500/10 text-emerald-100"
                : msg.error ? "border border-rose-500/40 bg-rose-500/5 text-rose-200"
                : "border border-slate-800 bg-slate-900/60 text-slate-200")}>
                <div className="whitespace-pre-wrap">{msg.text}</div>
                {msg.mission_id && (
                  <div className="mt-1.5 flex items-center gap-2">
                    <span className="font-mono text-[9px] text-slate-500">{msg.mission_id}</span>
                    <MissionChip status={msg.status} />
                  </div>
                )}
                {msg.role === "assistant" && msg.trajectory && msg.trajectory.length > 0 && (
                  <details className="mt-2 border-t border-slate-800 pt-2">
                    <summary className="cursor-pointer text-[10px] text-slate-500">Agent activity ({msg.trajectory.length})</summary>
                    <div className="mt-1"><TrajectoryView events={msg.trajectory} /></div>
                  </details>
                )}
              </div>
            </div>
          ))}

          {/* live structured progress while the agent works */}
          {busy && (
            <div className="mx-auto max-w-3xl rounded-lg border border-slate-800 bg-slate-900/40 px-3 py-2">
              <div className="flex items-center gap-2 text-[11px] text-sky-300">
                <span className="animate-pulse">◉</span>
                <span className="font-medium">{phase}</span>
                <span className="text-slate-500">— the agent is working; structured progress only, no raw chain-of-thought</span>
              </div>
              {liveActivity.length > 0 && <div className="mt-1.5"><TrajectoryView events={liveActivity} /></div>}
            </div>
          )}

          {needsOwner && !busy && (
            <div className="mx-auto max-w-3xl rounded-lg border border-amber-500/40 bg-amber-500/5 px-3 py-2 text-[11px] text-amber-200" role="alert">
              The mission is waiting on an owner decision. Reply in the conversation to continue it
              (verified resume path). You stay the authority — the backend enforces authorization.
            </div>
          )}

          {recoveryNeeded && !busy && (
            <div className="mx-auto max-w-3xl rounded-lg border border-amber-500/40 bg-amber-500/5 px-3 py-2 text-[11px] text-amber-200" role="alert">
              The mission has an in-flight checkpoint that requires reconciliation. The backend refuses
              resume in this state (verified contract) — no resume button is shown until the backend
              reports a resumable state.
            </div>
          )}
        </div>
      </div>

      {/* mission bar: official status + derived control state + owner actions */}
      {mission && (
        <div className="flex shrink-0 flex-wrap items-center gap-2 border-t border-slate-800 bg-slate-900/60 px-4 py-1.5 text-[10px]">
          <span className="font-mono text-slate-400">{mission.mission_id || ""}</span>
          <MissionChip status={mission} />
          <MissionControlChip mission={mission} />
          <div className="ml-auto flex gap-1.5">
            {ctrl.pause && (
              <button onClick={() => doControl("pause")} className="rounded border border-slate-700 px-1.5 py-0.5 text-slate-300 hover:bg-slate-800">pause mission</button>
            )}
            {ctrl.resume && (
              <button onClick={() => doControl("resume")} className="rounded border border-emerald-600/50 bg-emerald-500/10 px-1.5 py-0.5 text-emerald-300 hover:bg-emerald-500/20">resume mission</button>
            )}
            {ctrl.cancel && (
              <button onClick={() => doControl("cancel")} className="rounded border border-slate-700 px-1.5 py-0.5 text-slate-300 hover:bg-slate-800">cancel mission</button>
            )}
          </div>
        </div>
      )}

      {error && !busy && (
        <div className="shrink-0 border-t border-slate-800 px-4 py-1 text-[10px] text-rose-300" role="alert">
          {error.kind}: {error.message}
        </div>
      )}

      {/* composer */}
      <div className="shrink-0 border-t border-slate-800 bg-slate-900 p-3">
        <div className="mx-auto flex max-w-3xl items-end gap-2">
          <textarea
            value={input}
            onChange={(e) => setInput(e.target.value)}
            onKeyDown={(e) => { if (e.key === "Enter" && !e.shiftKey) { e.preventDefault(); send(); } }}
            disabled={busy}
            rows={2}
            aria-label="Message CyberSentinel (natural language)"
            placeholder={busy ? "the agent is working…" : "Describe what CyberSentinel should investigate or do…"}
            className="min-h-[44px] flex-1 resize-none rounded border border-slate-700 bg-slate-950 px-2 py-1.5 text-xs text-slate-200 outline-none placeholder:text-slate-600 focus:border-emerald-600" />
          <button onClick={send} disabled={busy || !input.trim()}
            className="rounded border border-emerald-600/50 bg-emerald-500/10 px-3 py-2 text-[11px] text-emerald-300 hover:bg-emerald-500/20 disabled:opacity-40">
            {isResume ? "Reply & continue mission" : "Send"}
          </button>
        </div>
        <div className="mx-auto mt-1 max-w-3xl text-[9px] text-slate-600">
          Natural language in, natural language out. Tool selection, planning and reasoning stay inside the agent —
          the UI only shows verified structured progress. Enter to send, Shift+Enter for a new line.
        </div>
      </div>
    </div>
  );
}
