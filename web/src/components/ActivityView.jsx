import { TASK_STATE } from "../state/lifecycle.js";
import { StateChip } from "./StateChip.jsx";

/**
 * Agent activity view — operational events only. Every entry is a real
 * backend event from the verified SSE stream (or a real task snapshot).
 * Model chain-of-thought is NEVER displayed here, by design.
 */
export function ActivityTimeline({ events }) {
  if (!events.length) return <EmptyStateLike />;
  return (
    <ol className="space-y-1" aria-label="Agent activity">
      {events.map((e, i) => {
        const type = String((e && (e.type || e.event)) || "event");
        const ts = e && (e.timestamp || e.time || "");
        return (
          <li key={(e && (e.event_id || e.id)) || i} className="flex gap-2 rounded px-1 py-1 text-[11px] hover:bg-slate-800/40">
            <span className="shrink-0 font-mono text-slate-500">{ts || "—"}</span>
            <span className="text-slate-300">{type}</span>
            {e && e.detail != null && <span className="truncate text-slate-500">{String(e.detail)}</span>}
          </li>
        );
      })}
    </ol>
  );
}
function EmptyStateLike() {
  return <div className="p-3 text-[11px] text-slate-500">No events received yet.</div>;
}

/** Mission/task header: id, state, target info — all from verified task snapshot. */
export function TaskHeader({ task, state }) {
  if (!task) return null;
  const m = TASK_STATE[state];
  return (
    <header className="border-b border-slate-800 px-3 py-2">
      <div className="flex flex-wrap items-center gap-2">
        <span className="font-mono text-xs text-slate-200">{task.task_id || task.id || "task"}</span>
        <StateChip state={state} timestamp={task.updated_at || ""} />
      </div>
      <div className="mt-1 text-[11px] text-slate-400">{m.desc}</div>
    </header>
  );
}
