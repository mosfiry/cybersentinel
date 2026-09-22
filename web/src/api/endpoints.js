// VERIFIED backend contract map.
// Every entry marked VERIFIED was read directly from bridge.py on main:
// routing strings in BaseHTTPRequestHandler.do_GET / do_POST.
// Anything not listed here as VERIFIED does NOT exist and the UI must
// never fake it.

export const CONTRACTS = {
  health:            { method: "GET",  path: "/api/health",            auth: "none",   verified: true,  evidence: "bridge.py do_GET: path == '/api/health'" },
  tools:             { method: "GET",  path: "/api/tools",             auth: "bridge", verified: true,  evidence: "bridge.py do_GET: parsed.path == '/api/tools'" },
  status:            { method: "GET",  path: "/api/status",            auth: "bridge", verified: true,  evidence: "bridge.py do_GET: self.path == '/api/status'" },
  sessionGet:        { method: "GET",  path: "/api/session/{id}",      auth: "bridge", verified: true,  evidence: "bridge.py do_GET: path.startswith('/api/session/')" },
  chatStream:        { method: "GET",  path: "/api/chat/stream",       auth: "bridge+chat", verified: true, evidence: "bridge.py do_GET: parsed.path == '/api/chat/stream' (SSE)" },
  taskGet:           { method: "GET",  path: "/api/tasks/{id}",        auth: "bridge+owner", verified: true, evidence: "bridge.py do_GET: path.startswith('/api/tasks/') + verify_owner" },
  taskStream:        { method: "GET",  path: "/api/tasks/{id}/stream", auth: "bridge+owner", verified: true, evidence: "bridge.py do_GET: task_id.endswith('/stream') (SSE)" },
  execution:         { method: "GET",  path: "/api/execution/{request_id}", auth: "bridge", verified: true, evidence: "bridge.py do_GET: path.startswith('/api/execution/')" },
  reasoning:         { method: "GET",  path: "/api/reasoning/{request_id}", auth: "bridge+owner", verified: true, evidence: "bridge.py do_GET + verify_owner('Owner reasoning memory')" },
  ownerSession:      { method: "POST", path: "/api/owner/session",     auth: "bridge + X-CyberSentinel-Owner-Token", verified: true, evidence: "bridge.py do_POST: create_owner_session(...)" },
  chat:              { method: "POST", path: "/api/chat",              auth: "bridge+chat", verified: true, evidence: "bridge.py do_POST: self.path == '/api/chat'" },
  taskCreate:        { method: "POST", path: "/api/tasks",             auth: "bridge+owner", verified: true, evidence: "bridge.py do_POST: self.path == '/api/tasks' -> create_task" },
  taskControl:       { method: "POST", path: "/api/tasks/{id}/{action}", action: "pause|resume|cancel", auth: "bridge+owner", verified: true, evidence: "bridge.py do_POST: task_id/action split -> pause_task/resume_task/cancel_task" },
  cancelRequest:     { method: "POST", path: "/api/cancel",            auth: "bridge", verified: true, evidence: "bridge.py do_POST: request_cancel(request_id)" },
  command:           { method: "POST", path: "/api/command",          auth: "bridge", verified: true, evidence: "bridge.py do_POST: text required -> request_id + stream" },
};

// Backend capabilities the IDE needs but the backend does NOT expose yet.
// Each blocker names the missing endpoint. The UI renders an explicit
// "backend contract not available" state for these — never fake success.
export const BLOCKED = {
  missions:       { missing: "GET /api/missions, POST /api/missions, mission lifecycle endpoints" },
  workspaceTree:  { missing: "GET /api/missions/{id}/workspace/tree" },
  workspaceFile:  { missing: "GET/PUT /api/missions/{id}/workspace/file" },
  terminal:       { missing: "authorized interactive terminal session endpoints (streaming exec beyond /api/command)" },
  git:            { missing: "GET /api/missions/{id}/git (branch, diff, commits)" },
  evidence:       { missing: "GET /api/evidence/{id} and mission-evidence linkage" },
  findings:       { missing: "GET /api/findings?mission={id} with claim/validated status" },
  scheduler:      { missing: "GET/POST /api/schedules" },
};
