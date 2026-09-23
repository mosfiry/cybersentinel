// Task/mission state mapping. Backend lifecycle states are mapped to UI
// states with icon + text + tone (never color alone). Mapping is honest:
// unreported states default to UNKNOWN; the backend remains the authority.
// Mission statuses verified against agent/mission.py MissionStatus on main.
export const TASK_STATE = {
  QUEUED:            { icon: "…", text: "QUEUED",            tone: "muted",   desc: "created, not started" },
  RUNNING:           { icon: "▶", text: "RUNNING",           tone: "run",     desc: "executing" },
  PAUSED:            { icon: "⏸", text: "PAUSED",            tone: "warn",    desc: "paused by owner" },
  CANCELLING:        { icon: "…", text: "CANCELLING",        tone: "warn",    desc: "cancel requested" },
  CANCELLED:         { icon: "✕", text: "CANCELLED",         tone: "muted",   desc: "cancelled" },
  COMPLETED:         { icon: "✓", text: "COMPLETED",         tone: "ok",      desc: "finished successfully" },
  PARTIAL_SUCCESS:   { icon: "△", text: "PARTIAL SUCCESS",   tone: "warn",    desc: "finished with issues" },
  FAILED:            { icon: "!", text: "FAILED",            tone: "err",     desc: "failed" },
  NEEDS_INPUT:       { icon: "?", text: "NEEDS INPUT",       tone: "info",    desc: "waiting on owner input" },
  BLOCKED:           { icon: "⛔", text: "BLOCKED",          tone: "err",     desc: "blocked by policy/authorization" },
  UNKNOWN:           { icon: " ", text: "UNKNOWN",           tone: "muted",   desc: "state not reported" },
};

/** Map any backend task record to a known UI state, honestly defaulting to UNKNOWN. */
export function mapTaskState(task) {
  if (!task || typeof task !== "object") return "UNKNOWN";
  const raw = String(task.status || task.state || "").toUpperCase().replace(/[\s-]/g, "_");
  return TASK_STATE[raw] ? raw : "UNKNOWN";
}

// Mission lifecycle (verified: agent/mission.py MissionStatus enum).
export const MISSION_STATE = {
  CREATED:                { icon: "○", text: "CREATED",           tone: "muted", desc: "mission created, not started" },
  PLANNING:               { icon: "…", text: "PLANNING",          tone: "info",  desc: "the agent is building a plan" },
  READY:                  { icon: "◆", text: "READY",             tone: "info",  desc: "plan ready, awaiting start" },
  RUNNING:                { icon: "▶", text: "EXECUTING",         tone: "run",   desc: "executing authorized plan steps" },
  OBSERVING:              { icon: "◉", text: "INSPECTING RESULT", tone: "info",  desc: "inspecting tool output" },
  VERIFYING:              { icon: "✓", text: "VERIFYING",         tone: "info",  desc: "verifying goal completion" },
  REPLANNING:             { icon: "↻", text: "REPLANNING",        tone: "warn",  desc: "re-planning after observation" },
  GOAL_COMPLETED:         { icon: "✓", text: "COMPLETED",        tone: "ok",    desc: "goal verified complete" },
  OWNER_INPUT_REQUIRED:   { icon: "?", text: "NEEDS OWNER",      tone: "warn",  desc: "waiting on an owner decision" },
  AUTHORIZATION_BLOCKED:  { icon: "⛔", text: "AUTH BLOCKED",   tone: "err",   desc: "authorization refused by the backend" },
  SCOPE_BLOCKED:          { icon: "⛔", text: "SCOPE BLOCKED",   tone: "err",   desc: "outside the scope firewall" },
  RESOURCE_BLOCKED:       { icon: "⛔", text: "RESOURCE BLOCKED", tone: "err",  desc: "resource limits reached" },
  RECOVERY_REQUIRED:      { icon: "↻", text: "RECOVERY NEEDED",  tone: "warn",  desc: "failure recovery required" },
  SAFETY_BLOCKED:         { icon: "⛔", text: "SAFETY BLOCKED",   tone: "err",   desc: "stopped by safety policy" },
  FAILED_RETRY_EXHAUSTED: { icon: "!", text: "FAILED",           tone: "err",   desc: "retries exhausted" },
  CANCELLED:              { icon: "✕", text: "CANCELLED",        tone: "muted", desc: "cancelled by owner" },
  UNKNOWN:                { icon: " ", text: "UNKNOWN",         tone: "muted", desc: "state not reported" },
};

/** Map a mission record (or status string) to a UI mission state. */
export function mapMissionState(mission) {
  const raw = typeof mission === "string" ? mission
    : (mission && (mission.status || (mission.mission && mission.mission.status))) || "";
  const norm = String(raw).toUpperCase().replace(/[\s-]/g, "_");
  return MISSION_STATE[norm] ? norm : "UNKNOWN";
}

// ---------------------------------------------------------------------------
// DERIVED control state — verified against api/missions.py on main.
//
// The backend pause contract does NOT set mission.status = PAUSED (PAUSED is
// not a MissionStatus). It records:
//   mission.progress["pause_requested"] = True
//   mission.checkpoint["status"] = "paused"
// and mission.status may legitimately remain RUNNING. Resume pops
// pause_requested and re-enqueues, but REFUSES (400) when status is
// RECOVERY_REQUIRED ("in-flight mission requires reconciliation before
// resume"). Cancel only transitions non-terminal missions.
//
// So the UI derives a SEPARATE control state from progress/checkpoint while
// keeping mission.status as the official backend state. No new MissionStatus
// values are invented here.
// ---------------------------------------------------------------------------

/** Verified terminal statuses (agent/mission.py TERMINAL_MISSION_STATUSES). */
export const MISSION_TERMINAL = new Set([
  "GOAL_COMPLETED", "OWNER_INPUT_REQUIRED", "AUTHORIZATION_BLOCKED",
  "SCOPE_BLOCKED", "RESOURCE_BLOCKED", "RECOVERY_REQUIRED",
  "SAFETY_BLOCKED", "FAILED_RETRY_EXHAUSTED", "CANCELLED",
]);

/** Derived control states (UI-only, NOT backend MissionStatus values). */
export const MISSION_CONTROL = {
  TERMINAL:           { icon: "■", text: "CONTROL LOCKED",       tone: "muted", desc: "mission is in a terminal state; no pause/resume/cancel" },
  RECOVERY_REQUIRED:  { icon: "↻", text: "RECOVERY REQUIRED",     tone: "warn",  desc: "in-flight checkpoint needs reconciliation; backend refuses resume until then" },
  PAUSED:             { icon: "⏸", text: "PAUSED",               tone: "warn",  desc: "pause requested and checkpoint paused; resume available" },
  PAUSE_REQUESTED:    { icon: "⏸", text: "PAUSE REQUESTED",       tone: "warn",  desc: "pause requested; the worker honors it at the next safe point; resume available" },
  PAUSED_CHECKPOINT:  { icon: "⏸", text: "PAUSED — CHECKPOINT",  tone: "warn",  desc: "checkpoint status is paused; resume available" },
  RUNNABLE:           { icon: "▶", text: "ACTIVE",                tone: "run",   desc: "mission is active; pause and cancel available" },
  IDLE:               { icon: "○", text: "NOT STARTED",           tone: "muted", desc: "mission created; pause and cancel available" },
  UNKNOWN:            { icon: " ", text: "UNKNOWN",              tone: "muted", desc: "control state not derivable from the mission record" },
};

/**
 * Derive the control state from the REAL contract fields:
 * mission.status (official) + mission.progress.pause_requested +
 * mission.checkpoint.status. Nothing invented, nothing ignored.
 */
export function missionControlState(mission) {
  if (!mission || typeof mission !== "object") return "UNKNOWN";
  const status = mapMissionState(mission);
  const progress = (mission.progress && typeof mission.progress === "object") ? mission.progress : {};
  const checkpoint = (mission.checkpoint && typeof mission.checkpoint === "object") ? mission.checkpoint : {};
  if (MISSION_TERMINAL.has(status)) {
    return status === "RECOVERY_REQUIRED" ? "RECOVERY_REQUIRED" : "TERMINAL";
  }
  if (progress.pause_requested === true) {
    return checkpoint.status === "paused" ? "PAUSED" : "PAUSE_REQUESTED";
  }
  if (checkpoint.status === "paused") return "PAUSED_CHECKPOINT";
  if (status === "CREATED" || status === "READY" || status === "PLANNING") return "IDLE";
  return "RUNNABLE";
}

/**
 * Which owner control actions the verified endpoints accept for this mission:
 * pause/resume/cancel via POST /api/missions/{id}/{action}.
 */
export function controlActions(mission) {
  const cs = missionControlState(mission);
  return {
    pause: cs === "RUNNABLE" || cs === "IDLE",
    resume: cs === "PAUSED" || cs === "PAUSE_REQUESTED" || cs === "PAUSED_CHECKPOINT",
    cancel: cs !== "TERMINAL" && cs !== "RECOVERY_REQUIRED" && cs !== "UNKNOWN",
  };
}

// Structured trajectory display (verified: agent/trajectory.py EventType).
// These labels expose operational progress — NOT the model's raw
// chain-of-thought. ModelTurn content is deliberately never rendered.
export const TRAJECTORY_EVENT = {
  MissionStarted:          { label: "Mission started",         tone: "info" },
  PlanCreated:             { label: "Plan created",            tone: "info" },
  PlanRevised:             { label: "Plan revised",            tone: "warn" },
  StepSelected:            { label: "Step selected",           tone: "info" },
  ToolProposed:            { label: "Tool selected",           tone: "info" },
  AuthorizationChecked:    { label: "Authorization checked",   tone: "info" },
  ToolExecuted:            { label: "Tool executed",            tone: "run"  },
  ObservationReceived:     { label: "Result received",         tone: "info" },
  ObservationInterpreted:  { label: "Result interpreted",      tone: "info" },
  EvidenceAdded:           { label: "Evidence collected",       tone: "ok"   },
  HypothesisUpdated:       { label: "Hypothesis updated",      tone: "info" },
  StrategyDecided:         { label: "Strategy decided",        tone: "info" },
  FailureDetected:         { label: "Failure detected",        tone: "err"  },
  FailureDiagnosed:        { label: "Failure diagnosed",       tone: "warn" },
  RecoveryAttempted:       { label: "Recovery attempted",      tone: "warn" },
  ReplanTriggered:         { label: "Re-plan triggered",       tone: "warn" },
  OwnerInputRequired:      { label: "Owner decision required", tone: "warn" },
  GoalVerificationStarted: { label: "Verification started",    tone: "info" },
  GoalVerified:            { label: "Goal verified",            tone: "ok"   },
  MissionCompleted:        { label: "Mission completed",       tone: "ok"   },
  RecoveryRequired:        { label: "Recovery required",       tone: "warn" },
  ModelTurn:               { label: "Model turn",              tone: "muted" },
};

export function trajectoryModel(entry) {
  if (!entry || typeof entry !== "object") return { label: "Event", tone: "muted", detail: "" };
  const type = String(entry.event_type || entry.event || entry.type || "");
  const m = TRAJECTORY_EVENT[type] || { label: type || "Event", tone: "muted" };
  const detailParts = [];
  if (entry.step_id) detailParts.push("step " + entry.step_id);
  if (entry.tool) detailParts.push("tool " + entry.tool);
  if (entry.action_id) detailParts.push("action " + entry.action_id);
  // ModelTurn content is intentionally NOT included (no raw chain-of-thought).
  return { label: m.label, tone: m.tone, detail: detailParts.join(" · ") };
}

/** Connection status chip model (icon + text, not color alone). */
export const CONNECTION_MODEL = {
  CONNECTED:     { icon: "●", text: "LIVE" },
  RECONNECTING:  { icon: "◌", text: "RECONNECTING" },
  DISCONNECTED:  { icon: "○", text: "DISCONNECTED" },
};
