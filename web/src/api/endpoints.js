// VERIFIED backend contract map.
// Every entry marked VERIFIED was read directly from bridge.py (and its
// imported modules api/chat.py, api/missions.py) on main: routing strings in
// BaseHTTPRequestHandler.do_GET / do_POST. Anything not listed here as
// VERIFIED does NOT exist and the UI must never fake it.

export const CONTRACTS = {
  health:            { method: "GET",  path: "/api/health",            auth: "none",   verified: true,  evidence: "bridge.py do_GET: path == '/api/health'" },
  tools:             { method: "GET",  path: "/api/tools",             auth: "bridge", verified: true,  evidence: "bridge.py do_GET: parsed.path == '/api/tools'" },
  status:            { method: "GET",  path: "/api/status",            auth: "bridge", verified: true,  evidence: "bridge.py do_GET: self.path == '/api/status'" },
  sessionGet:        { method: "GET",  path: "/api/session/{id}",      auth: "bridge+owner", verified: true, evidence: "bridge.py do_GET: path.startswith('/api/session/') + verify_owner" },
  chatStream:        { method: "GET",  path: "/api/chat/stream",       auth: "bridge+owner", verified: true, evidence: "bridge.py do_GET + api/chat.py stream(): SSE events 'started', per-activity event names, 'completed'" },
  missionCreate:     { method: "POST", path: "/api/missions",          auth: "bridge+owner", verified: true, evidence: "bridge.py do_POST: plan dict -> structured mission; otherwise chat(payload) blocking path (supports mission_id resume)" },
  missionGet:        { method: "GET",  path: "/api/missions/{id}/{action}", action: "status|timeline|evidence|artifacts|logs", auth: "bridge+owner", verified: true, evidence: "bridge.py do_GET: values map -> service.status/timeline/evidence/artifacts/logs" },
  missionControl:    { method: "POST", path: "/api/missions/{id}/{action}", action: "start|resume|pause|cancel|schedule", auth: "bridge+owner", verified: true, evidence: "bridge.py do_POST: service.start_mission/resume_mission/pause_mission/cancel_mission/schedule_mission" },
  taskGet:           { method: "GET",  path: "/api/tasks/{id}",        auth: "bridge+owner", verified: true, evidence: "bridge.py do_GET: path.startswith('/api/tasks/') + verify_owner" },
  taskStream:        { method: "GET",  path: "/api/tasks/{id}/stream", auth: "bridge+owner", verified: true, evidence: "bridge.py do_GET: task_id.endswith('/stream') (SSE)" },
  execution:         { method: "GET",  path: "/api/execution/{request_id}", auth: "bridge", verified: true, evidence: "bridge.py do_GET: path.startswith('/api/execution/')" },
  reasoning:         { method: "GET",  path: "/api/reasoning/{request_id}", auth: "bridge+owner", verified: true, evidence: "bridge.py do_GET + verify_owner('Owner reasoning memory')" },
  ownerSession:      { method: "POST", path: "/api/owner/session",     auth: "bridge + X-CyberSentinel-Owner-Token", verified: true, evidence: "bridge.py do_POST: create_owner_session(...)" },
  taskCreate:        { method: "POST", path: "/api/tasks",             auth: "bridge+owner", verified: true, evidence: "bridge.py do_POST: self.path == '/api/tasks' -> create_task" },
  taskControl:       { method: "POST", path: "/api/tasks/{id}/{action}", action: "pause|resume|cancel", auth: "bridge+owner", verified: true, evidence: "bridge.py do_POST: task_id/action split -> pause_task/resume_task/cancel_task" },
  cancelRequest:     { method: "POST", path: "/api/cancel",            auth: "bridge", verified: true, evidence: "bridge.py do_POST: request_cancel(request_id)" },
  command:           { method: "POST", path: "/api/command",          auth: "bridge", verified: true, evidence: "bridge.py do_POST: text required -> request_id + stream" },
};

// Backend capabilities the IDE needs but the backend does NOT expose yet.
// Each blocker names the missing endpoint. The UI renders an explicit
// "backend contract not available" state for these — never fake success.
// NOTE: mission-level endpoints exist now (see CONTRACTS.mission*) — the
// remaining blockers are workspace/file, interactive terminal sessions,
// git, generic evidence listing, findings, and schedule listing.
export const BLOCKED = {
  workspaceTree:  { missing: "GET /api/missions/{id}/workspace/tree" },
  workspaceFile:  { missing: "GET/PUT /api/missions/{id}/workspace/file" },
  terminal:       { missing: "authorized interactive terminal session endpoints (streaming exec beyond /api/command)" },
  git:            { missing: "GET /api/missions/{id}/git (branch, diff, commits)" },
  evidence:       { missing: "GET /api/evidence/{id} generic evidence listing (mission-scoped evidence exists via /api/missions/{id}/evidence)" },
  findings:       { missing: "GET /api/findings?mission={id} with claim/validated status" },
  scheduler:      { missing: "GET/POST /api/schedules (mission schedule action exists; listing/management contract does not)" },
};
