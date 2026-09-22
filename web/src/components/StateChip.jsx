import { TASK_STATE, CONNECTION_MODEL } from "../state/lifecycle.js";

const TONE = {
  run: "text-emerald-300 border-emerald-500/40 bg-emerald-500/10",
  ok: "text-emerald-300 border-emerald-500/40 bg-emerald-500/10",
  warn: "text-amber-300 border-amber-500/40 bg-amber-500/10",
  err: "text-rose-300 border-rose-500/40 bg-rose-500/10",
  info: "text-sky-300 border-sky-500/40 bg-sky-500/10",
  muted: "text-slate-400 border-slate-600 bg-slate-500/10",
};

/** State chip: icon + text + tone (never color alone). */
export function StateChip({ state, timestamp }) {
  const m = TASK_STATE[state] || TASK_STATE.UNKNOWN;
  return (
    <span className={"inline-flex items-center gap-1.5 rounded border px-1.5 py-0.5 text-[10px] font-semibold " + (TONE[m.tone] || TONE.muted)}
      title={m.desc} role="status">
      <span aria-hidden="true">{m.icon}</span>{m.text}
      {timestamp && <span className="font-mono font-normal opacity-70">{timestamp}</span>}
    </span>
  );
}

/** Connection status chip (icon + text). */
export function ConnectionChip({ status }) {
  const m = CONNECTION_MODEL[status] || CONNECTION_MODEL.DISCONNECTED;
  return (
    <span className="inline-flex items-center gap-1 text-[10px] font-semibold text-slate-300" role="status" title={"Event stream: " + status}>
      <span aria-hidden="true">{m.icon}</span>{m.text}
    </span>
  );
}
