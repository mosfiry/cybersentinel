import { MISSION_STATE, mapMissionState, trajectoryModel } from "../state/lifecycle.js";

const TONE_CLASS = {
  run: "text-emerald-300 border-emerald-500/40 bg-emerald-500/10",
  ok: "text-emerald-300 border-emerald-500/40 bg-emerald-500/10",
  warn: "text-amber-300 border-amber-500/40 bg-amber-500/10",
  err: "text-rose-300 border-rose-500/40 bg-rose-500/10",
  info: "text-sky-300 border-sky-500/40 bg-sky-500/10",
  muted: "text-slate-400 border-slate-600 bg-slate-500/10",
};

/** Mission lifecycle chip: icon + text + tone (never color alone). */
export function MissionChip({ status, missionId }) {
  const key = mapMissionState(status);
  const m = MISSION_STATE[key];
  return (
    <span className={"inline-flex items-center gap-1.5 rounded border px-1.5 py-0.5 text-[10px] font-semibold " + (TONE_CLASS[m.tone] || TONE_CLASS.muted)}
      title={m.desc + (missionId ? " — " + missionId : "")} role="status">
      <span aria-hidden="true">{m.icon}</span>{m.text}
    </span>
  );
}

/**
 * Structured agent progress: verified trajectory events with operational
 * labels. Raw chain-of-thought (ModelTurn content) is never rendered.
 */
export function TrajectoryView({ events }) {
  if (!events || !events.length) {
    return <div className="p-2 text-[11px] text-slate-500">No agent activity yet.</div>;
  }
  return (
    <ol className="space-y-0.5" aria-label="Agent activity">
      {events.slice(-100).map((e, i) => {
        const m = trajectoryModel(e);
        return (
          <li key={(e && (e.event_id || e.id)) || i}
            className={"flex items-baseline gap-2 rounded px-1 py-0.5 text-[11px] " + (TONE_CLASS[m.tone] || TONE_CLASS.muted)}>
            <span className="shrink-0 font-medium">{m.label}</span>
            {m.detail && <span className="truncate font-mono text-slate-500">{m.detail}</span>}
          </li>
        );
      })}
    </ol>
  );
}

/** Mission summary from the verified mission record — nothing invented. */
export function MissionSummary({ mission }) {
  if (!mission) return null;
  const plan = mission.plan || {};
  const steps = Array.isArray(plan.steps) ? plan.steps.length : null;
  return (
    <div className="rounded border border-slate-800 bg-slate-900/40 p-2 text-[11px]">
      <div className="flex flex-wrap items-center gap-2">
        <span className="font-mono text-slate-300">{mission.mission_id || "mission"}</span>
        <MissionChip status={mission.status} />
      </div>
      {plan.objective && <div className="mt-1 text-slate-400">Objective: {plan.objective}</div>}
      {steps !== null && <div className="mt-0.5 text-slate-500">Plan steps: {steps}</div>}
    </div>
  );
}
