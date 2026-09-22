
import React, { useState, useMemo } from "react";

/* ============================================================
   CyberSentinel X — IDE UI (Product/UI Layer ONLY)
   All data below is clearly-marked MOCK fixture data.
   No backend is connected. No tokens/secrets in this bundle.
   Backend authorization semantics are NOT redefined here.
   ============================================================ */

// ---------- mock fixtures (all clearly marked) ----------
const MISSIONS = [
  { id: "MSN-2041", status: "running", objective: "Audit auth surface of target web app", target: "webapp.lab.internal", started: "09:41:07", elapsed: "01:12:44", eta: "~00:18:00", phase: "recon → planning", action: "Analyzing authentication surface…", progress: 72, risk: "in-scope", checkpoint: "ckpt-014 (10:53:12)", next: "Fuzz session token expiry paths" },
  { id: "MSN-2039", status: "paused", objective: "Credentialed scan of staging API", target: "api.staging.lab", started: "08:02:11", elapsed: "00:47:03", eta: "—", phase: "recon", action: "Paused by Owner at 08:49", progress: 31, risk: "in-scope", checkpoint: "ckpt-006 (08:44:56)", next: "Await resume confirmation" },
  { id: "MSN-2036", status: "scheduled", objective: "Recurring dependency audit", target: "repo: payments-svc", started: "—", elapsed: "—", eta: "next 02:00 UTC", phase: "—", action: "Waiting for wake condition", progress: 0, risk: "in-scope", checkpoint: "—", next: "Wake on cron (daily 02:00)" },
  { id: "MSN-2033", status: "needs_input", objective: "Exploit reproduction on snapshot VM", target: "vm.snapshot-07", started: "yesterday 21:14", elapsed: "—", eta: "—", phase: "verification", action: "Owner input required: confirm VM snapshot id", progress: 64, risk: "boundary-approval", checkpoint: "ckpt-021 (21:58:03)", next: "Blocked on Owner decision" },
  { id: "MSN-2028", status: "completed", objective: "Secret scan of CI pipeline", target: "ci-runner", started: "07:15:00", elapsed: "00:22:41", eta: "—", phase: "report", action: "Report generated (3 findings)", progress: 100, risk: "in-scope", checkpoint: "final", next: "—" },
  { id: "MSN-2025", status: "failed", objective: "Recon of perimeter host", target: "edge-01.lab", started: "06:40:00", elapsed: "00:05:12", eta: "—", phase: "recon", action: "Tool failure: connectivity refused (exit 1)", progress: 12, risk: "in-scope", checkpoint: "ckpt-002", next: "Retry policy: exhausted (3/3)" },
  { id: "MSN-2020", status: "cancelled", objective: "Draft hypothesis: token leakage", target: "webapp.lab.internal", started: "05:12", elapsed: "00:09:44", eta: "—", phase: "planning", action: "Cancelled by Owner", progress: 18, risk: "in-scope", checkpoint: "ckpt-001", next: "—" },
];

const TIMELINE = [
  { t: "09:41:07", type: "mission-created", label: "Mission Created", detail: "MSN-2041 created by Owner (auth v3.2 approved)." },
  { t: "09:41:09", type: "auth", label: "Authorization Approved", detail: "Scope: webapp.lab.internal/web/*; tools: nmap, curl, custom-http; window 09:40–12:40 UTC." },
  { t: "09:41:15", type: "workspace", label: "Workspace Prepared", detail: "mission/2041/ mounted read-write; evidence dir hashed." },
  { t: "09:42:02", type: "planning", label: "Planning", detail: "Plan: (1) route map (2) auth surface inventory (3) test harness (4) verification." },
  { t: "09:44:31", type: "recon", label: "Recon", detail: "Endpoint inventory: 38 routes, 4 auth-relevant." },
  { t: "09:47:03", type: "tool", label: "Tool Executed: nmap", detail: "cmd: nmap -sV -p 443 webapp.lab.internal · exit 0 · 1.4s · exec E-0117" },
  { t: "09:49:12", type: "observation", label: "Observation", detail: "Session cookie lacks Secure flag on /login (obs-0031)." },
  { t: "09:51:40", type: "hypothesis", label: "Hypothesis", detail: "H-014: session tokens may be replayable over plain HTTP. Status: CANDIDATE (not verified)." },
  { t: "09:55:00", type: "code", label: "Code Change", detail: "created tools/replay_probe.py (+64 −0) by Agent." },
  { t: "09:58:44", type: "test", label: "Test Run", detail: "pytest -q tests/test_replay_probe.py · 5 passed, 1 failed." },
  { t: "10:01:02", type: "failure", label: "Test Failure", detail: "test_expiry: AssertionError — token TTL assertion off by 60s." },
  { t: "10:03:19", type: "repair", label: "Repair", detail: "Agent patched TTL constant from 3600 → 3660 (config mismatch)." },
  { t: "10:04:10", type: "retry", label: "Retry", detail: "Re-ran suite: 6/6 passed." },
  { t: "10:07:55", type: "verification", label: "Verification", detail: "Validator V-031 PASS on evidence E-0451 (input/output hashes match)." },
  { t: "10:09:20", type: "finding", label: "Finding F-007", detail: "Session replay over HTTP — status: VERIFIED (evidence E-0451)." },
  { t: "10:12:44", type: "checkpoint", label: "Checkpoint ckpt-014", detail: "Full state snapshot; safe to close this page." },
];

const AGENT_ACTIVITY = [
  { s: "planning", text: "Analyzing repository structure…" },
  { s: "planning", text: "Finding authentication surface (4 routes flagged)…" },
  { s: "executing", text: "Creating test harness tools/replay_probe.py…" },
  { s: "executing", text: "Running tests: 5 passed, 1 failed (1.9s)…" },
  { s: "failure", text: "Tool returned failure: test_expiry assertion (exit 1)" },
  { s: "executing", text: "Diagnosing failure: diffing token TTL config…" },
  { s: "executing", text: "Repairing: patch applied to config constant…" },
  { s: "executing", text: "Retrying test suite… 6/6 passed" },
  { s: "verifying", text: "Evidence collected: E-0451 (sha256 in/out recorded)" },
  { s: "verifying", text: "Validator V-031 PASS — hypothesis H-014 → finding F-007" },
  { s: "verifying", text: "Checkpoint ckpt-014 written" },
  { s: "executing", text: "Next planned: fuzz session token expiry paths" },
];

const FILES = {
  "mission/": ["mission.json", "auth_snapshot.json"],
  "target/": ["scope.yaml", "routes.txt"],
  "recon/": ["nmap_443.txt", "endpoint_inventory.md"],
  "source/": ["auth/session.py", "auth/tokens.py"],
  "tools/": ["replay_probe.py"],
  "exploits/": ["(empty)"],
  "evidence/": ["E-0451.json", "E-0442.json"],
  "hypotheses/": ["H-014.json"],
  "notes/": ["2026-09-22-session.md"],
  "reports/": ["draft.md"],
  "artifacts/": ["token_capture.pcap"],
  "logs/": ["exec.log"],
  "tests/": ["test_replay_probe.py"],
};

const FILE_CONTENTS = {
  "tools/replay_probe.py": [
    "# agent-authored probe — reviewed by Owner before merge",
    "import requests, sys",
    "",
    "def probe(base_url, token):",
    '    """Replay a captured session token over plain HTTP.',
    "    Scope: authorized target only (auth v3.2, MSN-2041).\"\"\"",
    '    r = requests.get(f"http://{base_url}/account", cookies={{"sid": token}}, timeout=5)',
    "    return r.status_code",
    "",
    'if __name__ == "__main__":',
    "    print(probe(sys.argv[1], sys.argv[2]))",
  ].join("\n"),
  "auth/session.py": [
    "SESSION_TTL_SECONDS = 3660  # patched by agent after test failure",
    "COOKIE_SECURE = False       # finding F-007 relates to this line",
  ].join("\n"),
};

const TERMINAL = [
  { cmd: "nmap -sV -p 443 webapp.lab.internal", out: "443/tcp open  https  nginx 1.24", exit: 0, dur: "1.4s", exec: "E-0117" },
  { cmd: "pytest -q tests/test_replay_probe.py", out: ".....F\n1 failed, 5 passed in 1.9s", exit: 1, dur: "1.9s", exec: "E-0119" },
  { cmd: "pytest -q tests/test_replay_probe.py (retry)", out: "......\n6 passed in 1.8s", exit: 0, dur: "1.8s", exec: "E-0121" },
];

const EVIDENCE = [
  { id: "E-0451", step: "verification", source: "replay_probe.py", time: "10:07:55", tool: "custom-http", inHash: "b91d…4a02", outHash: "7f3c…e910", artifact: "token_capture.pcap", provenance: "REAL (runtime sensor)", validation: "Validator V-031 PASS" },
  { id: "E-0442", step: "recon", source: "nmap", time: "09:47:03", tool: "nmap", inHash: "aa10…77bc", outHash: "2c44…019d", artifact: "nmap_443.txt", provenance: "REAL (tool output)", validation: "hash-match PASS" },
];

const FINDINGS = [
  { id: "F-007", title: "Session token replayable over plain HTTP", target: "webapp.lab.internal", claim: "Captured sid cookie is accepted over http:// (H-014 claim → verified)", evidence: ["E-0451"], repro: "replay_probe.py <host> <token>", validator: "V-031", result: "PASS", confidence: "HIGH", severity: "medium", status: "VERIFIED FINDING", artifacts: ["token_capture.pcap"] },
  { id: "F-006", title: "Session cookie missing Secure flag", target: "webapp.lab.internal", claim: "Set-Cookie on /login lacks Secure attribute (unverified claim)", evidence: [], repro: "curl -I https://…/login", validator: "—", result: "NOT RUN", confidence: "MEDIUM", severity: "low", status: "CLAIM (not verified)", artifacts: [] },
  { id: "F-005", title: "Unknown: token TTL drift source", target: "auth/session.py", claim: "—", evidence: [], repro: "—", validator: "—", result: "—", confidence: "—", severity: "—", status: "UNKNOWN", artifacts: [] },
];

const AUTH_SNAPSHOT = {
  target: "webapp.lab.internal/web/*", scope: "read + authorized active probes (replay only)",
  allowed: ["GET/POST within /web/*", "session replay test", "test-harness creation in workspace"],
  forbidden: ["data exfiltration beyond proof-of-replay", "modification of target state", "credential reuse outside scope"],
  tools: ["nmap", "curl", "custom-http", "pytest (workspace)"],
  window: "09:40–12:40 UTC (2026-09-22)", rate: "≤ 5 req/s; ≤ 600 req/min", network: "lab VLAN 10 only — no internet egress",
  data: "no PII persisted; pcap hashed and scoped", credentials: "ephemeral test session only — no real user creds",
  workspace: "mission/2041/ (rw); repo: read-only unless Owner-approved diff", approval: "Owner approved 09:40:02 (signature on file)", version: "auth-v3.2",
};

const GIT_CHANGES = {
  branch: "agent/MSN-2041-replay-probe", status: "3 changed, not merged to main",
  files: [
    { path: "tools/replay_probe.py", diff: "+64 −0", mod: true },
    { path: "auth/session.py", diff: "+1 −1", mod: true },
    { path: "tests/test_replay_probe.py", diff: "+31 −0", mod: true },
  ],
  commits: [
    { h: "a1b2c3d", msg: "feat(probe): session replay harness + tests", tests: "6/6 pass" },
    { h: "e4f5a6b", msg: "fix(config): TTL constant 3600 → 3660", tests: "6/6 pass" },
  ],
};

const SCHEDULES = [
  { id: "SCH-02", mission: "Dependency audit (payments-svc)", mode: "Recurring (daily)", next: "02:00 UTC", last: "02:00 UTC (success)", wake: "cron: 0 2 * * *", retry: "3 attempts, backoff 5m" },
  { id: "SCH-03", mission: "Perimeter host recon (MSN-2025 failed)", mode: "Run now (manual)", next: "on demand", last: "failed 06:45", wake: "owner trigger", retry: "exhausted" },
];

// ---------- design tokens ----------
const STATUS_COLOR = {
  running: "bg-emerald-500/15 text-emerald-300 border-emerald-500/40",
  paused: "bg-amber-500/15 text-amber-300 border-amber-500/40",
  scheduled: "bg-sky-500/15 text-sky-300 border-sky-500/40",
  needs_input: "bg-violet-500/15 text-violet-300 border-violet-500/40",
  completed: "bg-slate-500/15 text-slate-300 border-slate-500/40",
  failed: "bg-rose-500/15 text-rose-300 border-rose-500/40",
  cancelled: "bg-zinc-500/15 text-zinc-400 border-zinc-500/40",
};
const statusLabel = (s) => s.replace("_", " ").toUpperCase();

const Card = ({ title, children, className = "", right }) => (
  <div className={"rounded border border-slate-700/60 bg-slate-900/60 " + className}>
    {title && (
      <div className="flex items-center justify-between border-b border-slate-700/60 px-3 py-1.5">
        <span className="text-[11px] font-semibold uppercase tracking-wider text-slate-400">{title}</span>
        {right}
      </div>
    )}
    <div className="p-3">{children}</div>
  </div>
);

const Row = ({ k, v, mono }) => (
  <div className="flex gap-3 py-0.5 text-xs">
    <span className="w-36 shrink-0 text-slate-500">{k}</span>
    <span className={"text-slate-200 " + (mono ? "font-mono" : "")}>{v}</span>
  </div>
);

const MockTag = () => (
  <span className="rounded border border-amber-500/40 bg-amber-500/10 px-1.5 py-0.5 text-[10px] font-semibold text-amber-300">MOCK — backend not connected</span>
);

// ---------- app ----------
export default function App() {
  const [view, setView] = useState("missions"); // missions | workspace | timeline | terminal | evidence | findings | git | authorization | schedules
  const [selectedMission, setSelectedMission] = useState("MSN-2041");
  const [openFile, setOpenFile] = useState("tools/replay_probe.py");
  const [tabs, setTabs] = useState(["tools/replay_probe.py"]);
  const [search, setSearch] = useState("");
  const [confirm, setConfirm] = useState(null); // {action, mission}
  const [activityFilter, setActivityFilter] = useState("all");
  const [selEvent, setSelEvent] = useState(null);
  const [authCheck, setAuthCheck] = useState(false);
  const [reloadSim, setReloadSim] = useState(false);

  const mission = MISSIONS.find((m) => m.id === selectedMission);
  const flatFiles = useMemo(
    () => Object.entries(FILES).flatMap(([dir, fs]) => fs.filter((f) => f !== "(empty)").map((f) => dir + f)),
    []
  );
  const filteredFiles = flatFiles.filter((f) => f.includes(search));

  const openInTab = (f) => {
    setOpenFile(f);
    setTabs((t) => (t.includes(f) ? t : [...t, f]));
    setView("workspace");
  };

  const runControl = (action) => {
    setConfirm(null);
    // Product layer: control intent is shown; actual execution is backend's decision.
  };

  return (
    <div className="flex h-screen flex-col bg-slate-950 text-slate-200" style={{ fontFamily: "ui-sans-serif, system-ui" }}>
      {/* ============ top bar ============ */}
      <header className="flex items-center gap-4 border-b border-slate-800 bg-slate-900 px-4 py-2">
        <div className="flex items-center gap-2">
          <div className="h-4 w-4 rounded-sm bg-emerald-400" />
          <span className="text-sm font-bold tracking-tight">CyberSentinel <span className="text-emerald-400">X</span></span>
        </div>
        <nav className="flex gap-1 text-xs">
          {[
            ["missions", "Missions"], ["workspace", "Workspace"], ["timeline", "Timeline"],
            ["terminal", "Terminal"], ["evidence", "Evidence"], ["findings", "Findings"],
            ["git", "Git/Changes"], ["authorization", "Authorization"], ["schedules", "Scheduler"],
          ].map(([k, l]) => (
            <button key={k} onClick={() => setView(k)}
              className={"rounded px-2.5 py-1 " + (view === k ? "bg-slate-700 text-white" : "text-slate-400 hover:bg-slate-800")}>
              {l}
            </button>
          ))}
        </nav>
        <div className="ml-auto flex items-center gap-3 text-xs text-slate-400">
          <span>Target: <span className="font-mono text-slate-200">webapp.lab.internal</span></span>
          <span>Owner: <span className="text-slate-200">authenticated (server-side session)</span></span>
          <span className={"rounded border px-2 py-0.5 font-semibold " + STATUS_COLOR[mission.status]}>{statusLabel(mission.status)}</span>
          <MockTag />
        </div>
      </header>

      <div className="flex min-h-0 flex-1">
        {/* ============ left rail: missions ============ */}
        <aside className="w-60 shrink-0 overflow-y-auto border-r border-slate-800 bg-slate-900/50">
          <div className="px-3 py-2 text-[11px] font-semibold uppercase tracking-wider text-slate-500">Missions</div>
          {["running", "paused", "scheduled", "needs_input", "completed", "failed", "cancelled"].map((st) => (
            <div key={st}>
              <div className="px-3 pt-2 text-[10px] uppercase tracking-wider text-slate-500">{statusLabel(st)}</div>
              {MISSIONS.filter((m) => m.status === st).map((m) => (
                <button key={m.id} onClick={() => setSelectedMission(m.id)}
                  className={"block w-full px-3 py-1.5 text-left " + (m.id === selectedMission ? "bg-slate-800" : "hover:bg-slate-800/50")}>
                  <div className="flex items-center justify-between">
                    <span className="font-mono text-xs">{m.id}</span>
                    <span className={"h-1.5 w-1.5 rounded-full " + (st === "running" ? "animate-pulse bg-emerald-400" : st === "failed" ? "bg-rose-400" : st === "needs_input" ? "bg-violet-400" : "bg-slate-500")}></span>
                  </div>
                  <div className="truncate text-[11px] text-slate-400">{m.objective}</div>
                </button>
              ))}
            </div>
          ))}
        </aside>

        {/* ============ center: view content ============ */}
        <main className="min-w-0 flex-1 overflow-y-auto p-4">
          {view === "missions" && (
            <div className="space-y-4">
              {/* mission dashboard */}
              <Card title={"Mission Dashboard — " + mission.id} right={<span className="text-[10px] text-slate-500">reconnect-safe · checkpoint-backed</span>}>
                <div className="grid gap-x-8 gap-y-1 md:grid-cols-2">
                  <Row k="Mission ID" v={mission.id} mono />
                  <Row k="Status" v={statusLabel(mission.status)} />
                  <Row k="Objective" v={mission.objective} />
                  <Row k="Target" v={mission.target} mono />
                  <Row k="Authorization" v={<a className="cursor-pointer text-sky-300 underline" onClick={() => setView("authorization")}>auth-v3.2 → snapshot view</a>} />
                  <Row k="Current phase" v={mission.phase} />
                  <Row k="Start time" v={mission.started} mono />
                  <Row k="Current action" v={mission.action} />
                  <Row k="Elapsed" v={mission.elapsed} mono />
                  <Row k="Next planned action" v={mission.next} />
                  <Row k="Est. remaining" v={mission.eta} mono />
                  <Row k="Last checkpoint" v={mission.checkpoint} mono />
                  <Row k="Risk / Boundary state" v={<span className={mission.risk === "in-scope" ? "text-emerald-300" : "text-violet-300"}>{mission.risk}</span>} />
                </div>
                <div className="mt-3">
                  <div className="mb-1 flex justify-between text-[11px] text-slate-500"><span>Progress</span><span>{mission.progress}%</span></div>
                  <div className="h-1.5 overflow-hidden rounded bg-slate-800">
                    <div className="h-full rounded bg-emerald-500" style={{ width: mission.progress + "%" }} />
                  </div>
                </div>
              </Card>

              {/* mission controls */}
              <Card title="Mission Controls">
                <div className="flex flex-wrap gap-2 text-xs">
                  <button disabled={mission.status !== "running"} onClick={() => setConfirm({ action: "Pause", mission })} className="rounded border border-amber-500/40 bg-amber-500/10 px-3 py-1 text-amber-300 hover:bg-amber-500/20 disabled:opacity-30">⏸ Pause</button>
                  <button disabled={mission.status !== "paused"} onClick={() => setConfirm({ action: "Resume", mission })} className="rounded border border-emerald-500/40 bg-emerald-500/10 px-3 py-1 text-emerald-300 hover:bg-emerald-500/20 disabled:opacity-30">▶ Resume</button>
                  <button disabled={["completed", "cancelled"].includes(mission.status)} onClick={() => setConfirm({ action: "Cancel", mission })} className="rounded border border-rose-500/40 bg-rose-500/10 px-3 py-1 text-rose-300 hover:bg-rose-500/20 disabled:opacity-30">✕ Cancel mission</button>
                  <button onClick={() => setView("evidence")} className="rounded border border-slate-600 px-3 py-1 text-slate-300 hover:bg-slate-800">Evidence</button>
                  <button onClick={() => setView("terminal")} className="rounded border border-slate-600 px-3 py-1 text-slate-300 hover:bg-slate-800">Logs</button>
                  <button className="rounded border border-slate-600 px-3 py-1 text-slate-300 hover:bg-slate-800">Artifacts</button>
                </div>
                <p className="mt-2 text-[10px] text-slate-500">Sensitive operations require an explicit confirmation dialog. The backend authorization layer decides if a control is actually permitted — the UI only requests it.</p>
              </Card>

              {/* long-running UX */}
              <Card title="Long-Running Mission — Return State" right={
                <button onClick={() => setReloadSim(!reloadSim)} className="rounded border border-sky-500/40 px-2 py-0.5 text-[10px] text-sky-300">{reloadSim ? "hide" : "simulate page return"}</button>
              }>
                {reloadSim ? (
                  <div className="space-y-1 text-xs">
                    <div className="text-emerald-300">✓ Mission still running (restored from checkpoint ckpt-014)</div>
                    <Row k="While you were away" v="2 tool executions, 1 repair+retry, 1 verification PASS, 1 new finding (F-007)" />
                    <Row k="Current state" v={mission.action} />
                    <Row k="Recent activity" v="last event 10:12:44 — checkpoint written" />
                  </div>
                ) : (
                  <p className="text-xs text-slate-500">Missions survive page close/reload. Press “simulate page return” to preview the restore view.</p>
                )}
              </Card>
            </div>
          )}

          {view === "timeline" && (
            <Card title="Mission Timeline — " + mission.id>
              <div className="relative pl-4">
                <div className="absolute bottom-2 left-[7px] top-2 w-px bg-slate-700" />
                {TIMELINE.map((e, i) => (
                  <div key={i} className="relative py-1.5 pl-4">
                    <span className={"absolute left-[-1px] top-2.5 h-2.5 w-2.5 rounded-full border border-slate-900 " +
                      (["finding", "verification"].includes(e.type) ? "bg-emerald-400" : e.type === "failure" ? "bg-rose-400" : ["code", "test"].includes(e.type) ? "bg-sky-400" : "bg-slate-500")}></span>
                    <button onClick={() => setSelEvent(selEvent === i ? null : i)} className="block w-full text-left">
                      <span className="mr-2 font-mono text-[11px] text-slate-500">{e.t}</span>
                      <span className="text-xs text-slate-200">{e.label}</span>
                    </button>
                    {selEvent === i && <div className="mt-1 rounded border border-slate-700 bg-slate-800/60 p-2 text-[11px] text-slate-300">{e.detail}</div>}
                  </div>
                ))}
              </div>
            </Card>
          )}

          {view === "workspace" && (
            <div className="flex h-full min-h-[480px] gap-4">
              {/* explorer */}
              <div className="w-64 shrink-0 rounded border border-slate-700/60 bg-slate-900/60">
                <div className="border-b border-slate-700/60 px-2 py-1.5">
                  <input value={search} onChange={(e) => setSearch(e.target.value)} placeholder="Search files…"
                    className="w-full rounded bg-slate-800 px-2 py-1 text-[11px] outline-none placeholder:text-slate-500" />
                </div>
                <div className="max-h-[70vh] overflow-y-auto p-2 text-[11px]">
                  {Object.entries(FILES).map(([dir, fs]) => (
                    <div key={dir} className="mb-1">
                      <div className="font-mono text-slate-400">{dir}</div>
                      {fs.filter((f) => (dir + f).includes(search)).map((f) => (
                        <button key={f} onClick={() => openInTab(dir + f)}
                          className={"block w-full truncate rounded px-2 py-0.5 pl-3 text-left hover:bg-slate-800 " + (openFile === dir + f ? "bg-slate-800 text-white" : "text-slate-300")}>
                          {f}
                        </button>
                      ))}
                    </div>
                  ))}
                </div>
                <div className="border-t border-slate-700/60 px-2 py-1 text-[10px] text-slate-500">
                  permissions: read/write in mission workspace (backend-enforced)
                </div>
              </div>
              {/* editor */}
              <div className="min-w-0 flex-1 rounded border border-slate-700/60 bg-slate-900/60">
                <div className="flex overflow-x-auto border-b border-slate-700/60 text-[11px]">
                  {tabs.map((t) => (
                    <button key={t} onClick={() => setOpenFile(t)}
                      className={"whitespace-nowrap px-3 py-1.5 " + (openFile === t ? "bg-slate-800 text-white" : "text-slate-400")}>
                      {t.split("/").pop()}
                      <span className="ml-1.5 text-amber-400">●</span>
                      <span onClick={(e) => { e.stopPropagation(); setTabs(tabs.filter((x) => x !== t)); if (openFile === t && tabs.length > 1) setOpenFile(tabs.filter((x) => x !== t)[0]); }} className="ml-1.5 text-slate-500 hover:text-rose-400">✕</span>
                    </button>
                  ))}
                </div>
                <div className="border-b border-slate-700/40 bg-slate-800/40 px-3 py-1 text-[10px] text-slate-500">
                  <span className="mr-3">Ln 1, Col 1</span>
                  <span className="mr-3">space: 4</span>
                  <span className="mr-3">UTF-8</span>
                  <span className="mr-3">diff vs main: modified ●</span>
                  <span className="text-amber-400">1 diagnostic: finding-related line</span>
                </div>
                <div className="max-h-[60vh] overflow-auto font-mono text-[11.5px] leading-5">
                  {(FILE_CONTENTS[openFile] || "# no preview for this file type (mock)").split("\n").map((line, i) => (
                    <div key={i} className="flex px-0">
                      <span className="w-10 shrink-0 select-none pr-2 text-right text-slate-600">{i + 1}</span>
                      <span className={"whitespace-pre " + (/^\s*(#|""")/.test(line) ? "text-slate-500" : /(import|def|return|if)/.test(line) ? "text-sky-300" : /finding|patched/.test(line) ? "text-amber-300" : "text-slate-300")}>{line}</span>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          )}

          {view === "terminal" && (
            <Card title={"Terminal — bound to " + mission.id + " / Execution IDs"}>
              {TERMINAL.map((t, i) => (
                <div key={i} className="mb-3 rounded border border-slate-800 bg-black/50 p-2 font-mono text-[11px]">
                  <div className="text-emerald-300">$ {t.cmd}</div>
                  <pre className="mt-1 whitespace-pre-wrap text-slate-300">{t.out}</pre>
                  <div className="mt-1 flex gap-3 text-[10px] text-slate-500">
                    <span className={t.exit === 0 ? "text-emerald-400" : "text-rose-400"}>exit {t.exit}</span>
                    <span>duration {t.dur}</span>
                    <span>process: exited</span>
                    <span>execution {t.exec}</span>
                  </div>
                </div>
              ))}
              <p className="text-[10px] text-slate-500">Credentials are never exposed in the browser; the backend injects them at execution time.</p>
            </Card>
          )}

          {view === "evidence" && (
            <div className="space-y-4">
              <Card title="Evidence Viewer" right={<MockTag />}>
                {EVIDENCE.map((e) => (
                  <div key={e.id} className="mb-2 rounded border border-slate-800 p-2">
                    <div className="grid gap-x-8 md:grid-cols-2">
                      <Row k="Evidence ID" v={e.id} mono />
                      <Row k="Mission / Step" v={mission.id + " / " + e.step} mono />
                      <Row k="Source" v={e.source} mono />
                      <Row k="Timestamp" v={e.time} mono />
                      <Row k="Tool" v={e.tool} mono />
                      <Row k="Input hash (sha256)" v={e.inHash} mono />
                      <Row k="Output hash (sha256)" v={e.outHash} mono />
                      <Row k="Artifact" v={e.artifact} mono />
                      <Row k="Provenance" v={e.provenance} />
                      <Row k="Validation" v={<span className="text-emerald-300">{e.validation}</span>} />
                    </div>
                  </div>
                ))}
              </Card>
              <Card title="Evidence vs Claims — separation contract">
                <p className="text-xs text-slate-400">
                  Evidence rows are hash-anchored tool outputs. Model <span className="text-slate-200">claims</span> live only in Findings marked
                  <span className="mx-1 rounded border border-amber-500/40 bg-amber-500/10 px-1 text-amber-300">CLAIM (not verified)</span>
                  and are never rendered as established facts. Items the system could not resolve appear as
                  <span className="mx-1 rounded border border-zinc-500/40 bg-zinc-500/10 px-1 text-zinc-300">UNKNOWN</span>.
                </p>
              </Card>
            </div>
          )}

          {view === "findings" && (
            <div className="space-y-3">
              {FINDINGS.map((f) => (
                <Card key={f.id} title={f.id + " — " + f.title}>
                  <div className="grid gap-x-8 md:grid-cols-2">
                    <Row k="Target" v={f.target} mono />
                    <Row k="Status" v={
                      <span className={"rounded border px-1.5 py-0.5 text-[10px] font-semibold " +
                        (f.status.includes("VERIFIED") ? STATUS_COLOR.completed : f.status.includes("CLAIM") ? "border-amber-500/40 bg-amber-500/10 text-amber-300" : "border-zinc-500/40 bg-zinc-500/10 text-zinc-300")}>
                        {f.status}
                      </span>} />
                    <Row k="Claim" v={f.claim || "—"} />
                    <Row k="Evidence" v={f.evidence.length ? f.evidence.join(", ") : "none (claim only)"} mono />
                    <Row k="Reproduction" v={f.repro} mono />
                    <Row k="Validator / Result" v={f.validator + " → " + f.result} />
                    <Row k="Confidence" v={f.confidence} />
                    <Row k="Severity" v={f.severity} />
                    <Row k="Related artifacts" v={f.artifacts.join(", ") || "—"} mono />
                  </div>
                </Card>
              ))}
            </div>
          )}

          {view === "git" && (
            <Card title="Git / Changes — Owner review of agent work">
              <Row k="Branch" v={GIT_CHANGES.branch} mono />
              <Row k="Status" v={GIT_CHANGES.status + " — merge to main requires Owner approval"} />
              <div className="mt-2 space-y-1">
                {GIT_CHANGES.files.map((f) => (
                  <div key={f.path} className="flex items-center justify-between rounded border border-slate-800 px-3 py-1.5 text-xs">
                    <span className="font-mono text-slate-300">{f.path}</span>
                    <span className="font-mono"><span className="text-emerald-400">{f.diff.split(" ")[0]}</span> <span className="text-rose-400">{f.diff.split(" ")[1]}</span></span>
                  </div>
                ))}
              </div>
              <div className="mt-3 text-[11px]">
                {GIT_CHANGES.commits.map((c) => (
                  <div key={c.h} className="flex gap-3 py-0.5 font-mono text-slate-400">
                    <span className="text-amber-400">{c.h}</span><span>{c.msg}</span><span className="ml-auto text-emerald-400">{c.tests}</span>
                  </div>
                ))}
              </div>
            </Card>
          )}

          {view === "authorization" && (
            <Card title={"Mission Authorization Snapshot — " + AUTH_SNAPSHOT.version} right={<MockTag />}>
              <div className="grid gap-x-8 gap-y-1 md:grid-cols-2">
                <Row k="Target" v={AUTH_SNAPSHOT.target} mono />
                <Row k="Scope" v={AUTH_SNAPSHOT.scope} />
                <Row k="Allowed actions" v={AUTH_SNAPSHOT.allowed.join(" · ")} />
                <Row k="Forbidden actions" v={<span className="text-rose-300">{AUTH_SNAPSHOT.forbidden.join(" · ")}</span>} />
                <Row k="Tools" v={AUTH_SNAPSHOT.tools.join(", ")} mono />
                <Row k="Time window" v={AUTH_SNAPSHOT.window} />
                <Row k="Rate limits" v={AUTH_SNAPSHOT.rate} />
                <Row k="Network boundary" v={AUTH_SNAPSHOT.network} />
                <Row k="Data boundary" v={AUTH_SNAPSHOT.data} />
                <Row k="Credential boundary" v={AUTH_SNAPSHOT.credentials} />
                <Row k="Workspace boundary" v={AUTH_SNAPSHOT.workspace} />
                <Row k="Owner approval" v={AUTH_SNAPSHOT.approval} />
                <Row k="Authorization version" v={AUTH_SNAPSHOT.version} mono />
              </div>
              <p className="mt-3 text-[10px] text-slate-500">
                This view displays authorization state only. The backend Policy Engine / Scope Firewall decide enforcement —
                the frontend cannot bypass, redefine, or cache credentials. No OWNER_TOKEN or BRIDGE_TOKEN exists in this bundle or localStorage.
              </p>
              <label className="mt-2 flex items-center gap-2 text-[11px] text-slate-400">
                <input type="checkbox" checked={authCheck} onChange={(e) => setAuthCheck(e.target.checked)} />
                I have reviewed this snapshot (Owner acknowledgment — UI state only)
              </label>
            </Card>
          )}

          {view === "schedules" && (
            <div className="space-y-3">
              {SCHEDULES.map((s) => (
                <Card key={s.id} title={s.id + " — " + s.mission}>
                  <div className="grid gap-x-8 md:grid-cols-2">
                    <Row k="Mode" v={s.mode} />
                    <Row k="Next run" v={s.next} mono />
                    <Row k="Last run" v={s.last} mono />
                    <Row k="Wake condition" v={s.wake} mono />
                    <Row k="Retry policy" v={s.retry} />
                  </div>
                  <div className="mt-2 flex gap-2 text-xs">
                    <button className="rounded border border-emerald-500/40 bg-emerald-500/10 px-3 py-1 text-emerald-300">Run now</button>
                    <button className="rounded border border-sky-500/40 bg-sky-500/10 px-3 py-1 text-sky-300">Edit schedule</button>
                  </div>
                </Card>
              ))}
            </div>
          )}
        </main>

        {/* ============ right rail: agent activity ============ */}
        <aside className="w-64 shrink-0 overflow-y-auto border-l border-slate-800 bg-slate-900/50">
          <div className="flex items-center justify-between px-3 py-2">
            <span className="text-[11px] font-semibold uppercase tracking-wider text-slate-500">Agent Activity</span>
            <select value={activityFilter} onChange={(e) => setActivityFilter(e.target.value)} className="rounded bg-slate-800 px-1 py-0.5 text-[10px]">
              <option value="all">all phases</option>
              <option value="planning">planning</option>
              <option value="executing">executing</option>
              <option value="verifying">verifying</option>
            </select>
          </div>
          <div className="space-y-1 px-3 pb-4">
            {AGENT_ACTIVITY.filter((a) => activityFilter === "all" || a.s === activityFilter).map((a, i) => (
              <div key={i} className="rounded border border-slate-800 bg-slate-900 p-2 text-[11px]">
                <div className="mb-0.5 flex items-center gap-1.5">
                  <span className={"rounded px-1 text-[9px] font-bold uppercase " + (a.s === "executing" ? "bg-sky-500/20 text-sky-300" : a.s === "verifying" ? "bg-emerald-500/20 text-emerald-300" : a.s === "failure" ? "bg-rose-500/20 text-rose-300" : "bg-violet-500/20 text-violet-300")}>{a.s}</span>
                </div>
                <div className="text-slate-300">{a.text}</div>
              </div>
            ))}
            <p className="pt-2 text-[10px] leading-4 text-slate-500">
              Operational events only: actions, outputs, evidence, decisions, provenance.
              Model chain-of-thought is never displayed.
            </p>
          </div>
        </aside>
      </div>

      {/* ============ confirm dialog ============ */}
      {confirm && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60">
          <div className="w-96 rounded border border-slate-700 bg-slate-900 p-4">
            <div className="text-sm font-semibold text-slate-100">Confirm: {confirm.action} {confirm.mission}</div>
            <p className="mt-2 text-xs text-slate-400">
              {confirm.action === "Cancel"
                ? "This requests mission termination. Unfinished findings stay as CLAIM/UNKNOWN; evidence chain is preserved. The backend may require re-authorization."
                : confirm.action === "Pause"
                ? "The agent will stop at the next safe checkpoint. Evidence stays consistent."
                : "The agent will resume from the last checkpoint within the authorized time window."}
            </p>
            <div className="mt-4 flex justify-end gap-2 text-xs">
              <button onClick={() => setConfirm(null)} className="rounded border border-slate-600 px-3 py-1 text-slate-300">Dismiss</button>
              <button onClick={() => runControl(confirm.action)} className={"rounded px-3 py-1 " + (confirm.action === "Cancel" ? "bg-rose-600 text-white" : "bg-emerald-600 text-white")}>Confirm {confirm.action}</button>
            </div>
          </div>
        </div>
      )}

      {/* ============ bottom bar ============ */}
      <footer className="flex items-center gap-4 border-t border-slate-800 bg-slate-900 px-4 py-1 text-[10px] text-slate-500">
        <span>backend: NOT CONNECTED (mock data)</span>
        <span>secrets in bundle/localStorage: none</span>
        <span>authorization: backend-enforced</span>
        <span className="ml-auto">UI layer · does not modify Authorization Core / MissionRuntime semantics</span>
      </footer>
    </div>
  );
}
