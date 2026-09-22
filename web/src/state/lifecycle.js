// Task/mission state mapping. The backend task lifecycle states are mapped
// to UI states with icon + text + color (never color alone). States not
// reported by the backend are still listed because the IDE must render
// them when the backend starts reporting them; mapping is honest about
// which states the verified backend emits today: the verified contract
// exposes task create/get/pause/resume/cancel, i.e. running/paused/
// cancelled/completed/failed style transitions via task records and SSE.
export const TASK_STATE = {
  QUEUED:            { icon: "…", text: "QUEUED",            tone: "muted",   desc: "created, not started" },
  RUNNING:           { icon: "▶", text: "RUNNING",           tone: "run",     desc: "executing" },
  PAUSED:            { icon: "⏸", text: "PAUSED",            tone: "warn",    desc: "paused by owner" },
  CANCELLING:        { icon: "…", text: "CANCELLING",        tone: "warn",    desc: "cancel requested" },
  CANCELLED:         { icon: "✕", text: "CANCELLED",         tone: "muted",   desc: "cancelled" },
  COMPLETED:         { icon: "✓", text: "COMPLETED",         tone: "ok",      desc: "finished successfully" },
  PARTIAL_SUCCESS:   { icon: "△", text: "PARTIAL SUCCESS",   tone: "warn",    desc: "finished with issues" },
  FAILED:            { icon: "!", text: "FAILED",            tone: "err",     desc: "failed" },
  NEEDS_INPUT:       { icon: "?", text: "NEEDS INPUT",        tone: "info",    desc: "waiting on owner input" },
  BLOCKED:           { icon: "⛔", text: "BLOCKED",          tone: "err",     desc: "blocked by policy/authorization" },
  UNKNOWN:           { icon: " ", text: "UNKNOWN",           tone: "muted",   desc: "state not reported" },
};

/** Map any backend task record to a known UI state, honestly defaulting to UNKNOWN. */
export function mapTaskState(task) {
  if (!task || typeof task !== "object") return "UNKNOWN";
  const raw = String(task.status || task.state || "").toUpperCase().replace(/[\s-]/g, "_");
  return TASK_STATE[raw] ? raw : "UNKNOWN";
}

/** Connection status chip model (icon + text, not color alone). */
export const CONNECTION_MODEL = {
  CONNECTED:     { icon: "●", text: "LIVE" },
  RECONNECTING:  { icon: "◌", text: "RECONNECTING" },
  DISCONNECTED:  { icon: "○", text: "DISCONNECTED" },
};
