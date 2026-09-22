import React, { useState, useCallback } from "react";
import { useTask } from "./hooks/useTask.js";
import { useEventStream } from "./hooks/useEventStream.js";
import { createStore, initialRuntimeState, runtimeReducer } from "./state/store.js";
import { TerminalPanel } from "./panels/TerminalPanel.jsx";
import { ActivityTimeline, TaskHeader } from "./components/ActivityView.jsx";
import { ConnectionChip } from "./components/StateChip.jsx";
import { ErrorState, LoadingState, EmptyState } from "./components/ErrorState.jsx";
import { health } from "./api/bridge.js";

/*
 * Thin composition root — NOT a God Component. All data comes from the
 * verified backend contract through the api/ layer; capabilities without
 * backend contracts render explicit blocked states (see api/adapters.js).
 * Credentials live in memory only (api/config.js).
 */

const store = createStore(initialRuntimeState, runtimeReducer);

export default function App() {
  const [taskId, setTaskId] = useState("");
  const [taskIdInput, setTaskIdInput] = useState("");
  const [healthInfo, setHealthInfo] = useState(null);
  const [healthError, setHealthError] = useState(null);
  const [conn, setConn] = useState("DISCONNECTED");
  const [events, setEvents] = useState([]);

  const { task, state, error, loading, refresh, control } = useTask(taskId || null);

  const onEvent = useCallback((evt) => store.dispatch({ type: "event/received", event: evt }), []);
  const onStatus = useCallback((status) => store.dispatch({ type: "connection/status", status }), []);
  const onResync = useCallback(async () => { if (taskId) await refresh(); }, [taskId, refresh]);
  useEventStream(taskId || null, { onEvent, onStatus, onResync });

  store.subscribe((s) => setConn(s.connection));
  store.subscribe((s) => setEvents(s.events.slice(-200)));

  const checkHealth = async () => {
    setHealthError(null);
    try { const h = await health(); setHealthInfo(h); }
    catch (e) { setHealthError(e); }
  };

  return (
    <div className="flex h-screen flex-col overflow-hidden bg-slate-950 text-slate-200"
      style={{ fontFamily: "ui-sans-serif, system-ui, sans-serif" }}>
      <header className="flex h-9 shrink-0 items-center gap-3 border-b border-slate-800 bg-slate-900 px-3">
        <span className="text-xs font-bold">CyberSentinel <span className="text-emerald-400">X</span></span>
        <button onClick={checkHealth} className="rounded border border-slate-700 px-2 py-0.5 text-[10px] hover:bg-slate-800">
          check backend
        </button>
        {healthInfo && <span className="font-mono text-[10px] text-emerald-300">{healthInfo.service} v{healthInfo.version}</span>}
        {healthError && <span className="text-[10px] text-rose-300">backend unreachable</span>}
        <div className="ml-auto flex items-center gap-3">
          <ConnectionChip status={conn} />
        </div>
      </header>

      <div className="flex min-h-0 flex-1">
        <aside className="flex w-64 shrink-0 flex-col border-r border-slate-800 bg-slate-900/40">
          <div className="border-b border-slate-800 p-2">
            <input value={taskIdInput} onChange={(e) => setTaskIdInput(e.target.value)}
              onKeyDown={(e) => { if (e.key === "Enter") setTaskId(taskIdInput.trim()); }}
              placeholder="task id (backend-issued)"
              aria-label="Task id"
              className="w-full rounded border border-slate-700 bg-slate-900 px-2 py-1 text-[11px] outline-none focus:border-emerald-600" />
            <button onClick={() => setTaskId(taskIdInput.trim())}
              className="mt-1 w-full rounded border border-emerald-600/50 bg-emerald-500/10 px-2 py-1 text-[11px] text-emerald-300 hover:bg-emerald-500/20">
              Open task stream
            </button>
          </div>
          {task && (
            <div className="space-y-1 p-2">
              {["pause", "resume", "cancel"].map((a) => (
                <button key={a} onClick={() => control(a).catch(() => {})}
                  className="w-full rounded border border-slate-700 px-2 py-1 text-[11px] text-slate-200 hover:bg-slate-800">
                  {a} task
                </button>
              ))}
            </div>
          )}
          <div className="mt-auto border-t border-slate-800 p-2 text-[9px] leading-4 text-slate-500">
            Workspace / missions list / git / evidence / findings / scheduler:
            backend contracts not yet available — adapters fail loudly, no fake data.
          </div>
        </aside>

        <main className="flex min-h-0 min-w-0 flex-1 flex-col">
          <div className="min-h-0 flex-1 overflow-auto p-3">
            {!taskId && <EmptyState title="No task open" hint="Enter a backend-issued task id to open its live stream." />}
            {taskId && loading && <LoadingState label="Fetching task snapshot…" />}
            {taskId && error && <ErrorState error={error} onRetry={refresh} />}
            {taskId && !loading && !error && task && <TaskHeader task={task} state={state} />}
            <div className="mt-2">
              <ActivityTimeline events={events} />
            </div>
          </div>
          <div className="h-56 shrink-0 border-t border-slate-800">
            <TerminalPanel />
          </div>
        </main>
      </div>

      <footer className="flex h-6 shrink-0 items-center gap-3 border-t border-slate-800 bg-slate-900 px-3 text-[10px] text-slate-500">
        <span>secrets in bundle/localStorage: none (memory-only session)</span>
        <span>authorization: backend-enforced</span>
        <span className="ml-auto">verified contracts: bridge.py @ main</span>
      </footer>
    </div>
  );
}
