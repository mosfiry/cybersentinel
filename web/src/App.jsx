import React, { useState, useMemo, useCallback } from "react";

/* ============================================================================
   CyberSentinel X — IDE Shell (Visual & UX Hardening, Product/UI Layer ONLY)
   - VS Code-class layout: Activity Bar / Sidebar / Tabs / Editor / Panel /
     Agent Panel / Status Bar — CyberSentinel identity, not a clone.
   - ALL DATA IS MOCK and marked "MOCK — BACKEND NOT CONNECTED".
   - No backend touched. No secrets in bundle. Authorization is display-only.
   ========================================================================== */

/* ------------------------------ mock data ------------------------------- */
const MISSIONS = [
  { id: "MSN-2041", status: "running", objective: "Audit auth surface of target web app", target: "webapp.lab.internal", started: "09:41:07", elapsed: "02:41:17", eta: "~00:18:00", phase: "Analysis", action: "Analyzing authentication flow", progress: 72, checkpoint: "02:39:55", next: "Fuzz session token expiry paths" },
  { id: "MSN-2039", status: "paused", objective: "Credentialed scan of staging API", target: "api.staging.lab", started: "08:02:11", elapsed: "00:47:03", eta: "—", phase: "Recon", action: "Paused by Owner at 08:49", progress: 31, checkpoint: "ckpt-006 (08:44:56)", next: "Await resume confirmation" },
  { id: "MSN-2036", status: "waiting", objective: "Recurring dependency audit", target: "repo: payments-svc", started: "—", elapsed: "—", eta: "next 02:00 UTC", phase: "—", action: "Waiting for wake condition", progress: 0, checkpoint: "—", next: "Wake on cron (daily 02:00)" },
  { id: "MSN-2033", status: "waiting", objective: "Exploit reproduction on snapshot VM", target: "vm.snapshot-07", started: "yesterday 21:14", elapsed: "—", eta: "—", phase: "Verification", action: "Owner input required: confirm VM snapshot id", progress: 64, checkpoint: "ckpt-021 (21:58:03)", next: "Blocked on Owner decision" },
  { id: "MSN-2028", status: "completed", objective: "Secret scan of CI pipeline", target: "ci-runner", started: "07:15:00", elapsed: "00:22:41", eta: "—", phase: "Report", action: "Report generated (3 findings)", progress: 100, checkpoint: "final", next: "—" },
  { id: "MSN-2025", status: "failed", objective: "Recon of perimeter host", target: "edge-01.lab", started: "06:40:00", elapsed: "00:05:12", eta: "—", phase: "Recon", action: "Tool failure: connectivity refused (exit 1)", progress: 12, checkpoint: "ckpt-002", next: "Retry policy: exhausted (3/3)" },
];

const STATUS = {
  running:   { label: "RUNNING",   dot: "bg-emerald-400", text: "text-emerald-300",  bar: "bg-emerald-400" },
  paused:    { label: "PAUSED",    dot: "bg-amber-400",    text: "text-amber-300",    bar: "bg-amber-400" },
  waiting:   { label: "WAITING",   dot: "bg-sky-400",      text: "text-sky-300",      bar: "bg-sky-400" },
  failed:    { label: "FAILED",    dot: "bg-rose-400",     text: "text-rose-300",     bar: "bg-rose-400" },
  completed: { label: "COMPLETED", dot: "bg-slate-400",    text: "text-slate-300",    bar: "bg-slate-400" },
};

const TREE = {
  "mission/": { "mission.json": 1, "auth_snapshot.json": 1 },
  "target/": { "scope.yaml": 1, "routes.txt": 1 },
  "recon/": { "nmap_443.txt": 1, "endpoint_inventory.md": 1, "subdir/": { "raw_output.txt": 1 } },
  "source/": { "auth/": { "session.py": 1, "tokens.py": 1 } },
  "tools/": { "scanner.py": 1, "replay_probe.py": 1 },
  "evidence/": { "E-0451.json": 1, "E-0442.json": 1 },
  "hypotheses/": { "H-014.json": 1 },
  "notes/": { "2026-09-22-session.md": 1 },
  "reports/": { "draft.md": 1 },
  "artifacts/": { "token_capture.pcap": 1 },
  "logs/": { "exec.log": 1 },
  "tests/": { "test_scanner.py": 1, "test_replay_probe.py": 1 },
  "exploits/": {},
};

const FILES = {
  "tools/scanner.py": [
    "# agent-authored scanner — pending Owner review",
    "import socket, sys",
    "",
    "def scan(host, ports=(80, 443)):",
    '    """Authorized-scope TCP connect scan (auth v3.2)."""',
    "    results = {}",
    "    for p in ports:",
    "        try:",
    "            s = socket.create_connection((host, p), timeout=2)",
    "            results[p] = 'open'",
    "            s.close()",
    "        except OSError:",
    "            results[p] = 'closed'",
    "    return results",
    "",
    'if __name__ == "__main__":',
    "    print(scan(sys.argv[1]))",
  ].join("\n"),
  "tools/replay_probe.py": [
    "# agent-authored probe — reviewed by Owner before merge",
    "import requests, sys",
    "",
    "def probe(base_url, token):",
    '    """Replay a captured session token over plain HTTP.',
    "    Scope: authorized target only (auth v3.2, MSN-2041).\"\"\"",
    '    r = requests.get(f"http://{base_url}/account", cookies={"sid": token}, timeout=5)',
    "    return r.status_code",
    "",
    'if __name__ == "__main__":',
    "    print(probe(sys.argv[1], sys.argv[2]))",
  ].join("\n"),
  "mission/mission.yaml": "id: MSN-2041\nobjective: audit-auth-surface\nstatus: running\nauthorization: auth-v3.2\n",
  "mission/auth_snapshot.json": '{ "version": "auth-v3.2", "target": "webapp.lab.internal/web/*" }\n',
  "target/scope.yaml": "target: webapp.lab.internal\nscope: /web/*\nread: allowed\nactive_probes: replay-only\n",
  "reports/draft.md": "# Draft report — MSN-2041\n\n1 verified finding, 1 unverified claim, 1 unknown.\n",
};

const DIRTY = new Set(["tools/scanner.py", "tests/test_scanner.py"]);

const TIMELINE = [
  { t: "09:41", type: "mission",  label: "Mission started", detail: "MSN-2041 created by Owner; authorization snapshot v3.2 attached." },
  { t: "09:42", type: "auth",     label: "Authorization validated", detail: "Scope: webapp.lab.internal/web/*; window 09:40–12:40 UTC; rate ≤5 req/s." },
  { t: "09:44", type: "workspace", label: "Workspace prepared", detail: "mission/2041/ mounted read-write; evidence dir hashed." },
  { t: "09:51", type: "recon",    label: "Repository indexed", detail: "42 files analyzed; 4 auth-relevant routes flagged." },
  { t: "10:03", type: "hypothesis", label: "Hypothesis created", detail: "H-014: session tokens may be replayable over plain HTTP. Status: CANDIDATE." },
  { t: "10:12", type: "tool",     label: "Tool executed", detail: "tools/replay_probe.py · exit 0 · 2.41s · execution ID exec-001." },
  { t: "10:13", type: "observation", label: "Observation received", detail: "Captured sid cookie accepted over http:// (obs-0031)." },
  { t: "10:16", type: "verify",   label: "Verification started", detail: "Validator V-031 running on evidence E-0451 (input/output hashes)." },
];

const EVIDENCE = [
  { id: "E-0451", step: "verification", source: "replay_probe.py", time: "10:07:55", tool: "custom-http", inHash: "b91d…4a02", outHash: "7f3c…e910", artifact: "token_capture.pcap", provenance: "REAL (runtime sensor)", validation: "Validator V-031 PASS" },
  { id: "E-0442", step: "recon", source: "nmap", time: "09:47:03", tool: "nmap", inHash: "aa10…77bc", outHash: "2c44…019d", artifact: "nmap_443.txt", provenance: "REAL (tool output)", validation: "hash-match PASS" },
];

const FINDINGS = [
  { id: "F-007", title: "Session token replayable over plain HTTP", target: "webapp.lab.internal", claim: "Captured sid cookie accepted over http:// (claim, verified by validator)", evidence: ["E-0451"], repro: "replay_probe.py <host> <token>", validator: "V-031", result: "PASS", confidence: "HIGH", severity: "medium", status: "VERIFIED", artifacts: ["token_capture.pcap"] },
  { id: "F-006", title: "Session cookie missing Secure flag", target: "webapp.lab.internal", claim: "Set-Cookie on /login lacks Secure attribute (unverified claim)", evidence: [], repro: "curl -I https://…/login", validator: "—", result: "NOT RUN", confidence: "MEDIUM", severity: "low", status: "CLAIM", artifacts: [] },
  { id: "F-005", title: "Token TTL drift source", target: "auth/session.py", claim: "—", evidence: [], repro: "—", validator: "—", result: "—", confidence: "—", severity: "—", status: "UNKNOWN", artifacts: [] },
];

const AUTH = {
  target: "webapp.lab.internal/web/*", scope: "read + authorized active probes (replay only)",
  allowed: ["GET/POST within /web/*", "session replay test", "test-harness creation in workspace"],
  forbidden: ["data exfiltration beyond proof-of-replay", "modification of target state", "credential reuse outside scope"],
  tools: ["nmap", "curl", "custom-http", "pytest (workspace)"],
  network: "lab VLAN 10 only — no internet egress",
  data: "no PII persisted; pcap hashed and scoped",
  credentials: "ephemeral test session only — no real user creds",
  window: "09:40–12:40 UTC (2026-09-22)", rate: "≤ 5 req/s; ≤ 600 req/min",
  approval: "Owner approved 09:40:02 (signature on file)", version: "auth-v3.2",
};

const GIT = {
  branch: "agent/MSN-2041-replay-probe", status: "3 changed — not merged to main",
  files: [
    { path: "tools/scanner.py", st: "M" }, { path: "tools/replay_probe.py", st: "A" }, { path: "tests/test_scanner.py", st: "M" },
  ],
  commits: [
    { h: "a1b2c3d", msg: "feat(probe): session replay harness + tests", tests: "6/6 pass" },
    { h: "e4f5a6b", msg: "fix(config): TTL constant 3600 → 3660", tests: "6/6 pass" },
  ],
};

const SCHEDULES = [
  { id: "SCH-02", mission: "Dependency audit (payments-svc)", mode: "Recurring (daily)", next: "02:00 UTC", last: "02:00 UTC (success)", status: "waiting", retry: "3 attempts, backoff 5m" },
  { id: "SCH-03", mission: "Perimeter host recon", mode: "Run now (manual)", next: "on demand", last: "failed 06:45", status: "failed", retry: "exhausted" },
];

const TERMINAL_SESSION = [
  { cmd: "python scanner.py", lines: ["[+] Initializing...", "[+] Loading target...", "[*] Running analysis...", "[+] Evidence collected"], exit: 0, dur: "2.41s", exec: "exec-001", time: "10:12:04" },
  { cmd: "pytest -q tests/test_replay_probe.py", lines: [".....F", "1 failed, 5 passed in 1.9s"], exit: 1, dur: "1.9s", exec: "exec-002", time: "10:13:11" },
  { cmd: "pytest -q tests/test_replay_probe.py (retry)", lines: ["......", "6 passed in 1.8s"], exit: 0, dur: "1.8s", exec: "exec-003", time: "10:16:40" },
];

const PROBLEMS = [
  { sev: "warning", file: "source/auth/session.py", line: 2, msg: "COOKIE_SECURE = False — related to finding F-007" },
  { sev: "info", file: "tools/scanner.py", line: 1, msg: "Agent-authored file pending Owner review" },
];

const OUTPUT_LINES = [
  "[10:07:55] evidence E-0451 recorded (sha256 in/out)",
  "[10:09:20] finding F-007 status: VERIFIED (validator V-031 PASS)",
  "[10:12:44] checkpoint ckpt-014 written",
  "[10:16:00] verification started for hypothesis H-014",
];

/* ------------------------------ UI atoms -------------------------------- */
const Icon = ({ d, size = 16, className = "" }) => (
  <svg width={size} height={size} viewBox="0 0 16 16" fill="none" stroke="currentColor"
    strokeWidth="1.4" strokeLinecap="round" strokeLinejoin="round" className={className} aria-hidden="true">
    <path d={d} />
  </svg>
);
const IC = {
  explorer: "M2 2h4l1.5 2H14v10H2V2z",
  missions: "M8 1.5 14 4v3c0 4-2.5 6.5-6 7.5C4.5 13.5 2 11 2 7V4l6-2.5z",
  search: "M7 2a5 5 0 1 0 0 10A5 5 0 0 0 7 2zM11 11l3 3",
  git: "M4 2v7m0 0a2 2 0 1 0 0 4 2 2 0 0 0 0-4zm8-7a2 2 0 1 0 0 4 2 2 0 0 0 0-4zm0 4c0 3-8 1-8 5",
  evidence: "M9 2H3v12h10V6L9 2zm0 0v4h4M5 9h6M5 11.5h4",
  findings: "M8 1 2 13h12L8 1zm0 5v3.5m0 2.2v.3",
  reports: "M3 1.5h7L13 5v9.5H3V1.5zM10 1.5V5h3M5 7h6M5 9h6M5 11h4",
  clock: "M8 2a6 6 0 1 0 0 12A6 6 0 0 0 8 2zm0 3v3.5l2.5 1.5",
  tools: "M14 3 7 10m-2.5 3.5a2 2 0 1 1-3-3l2-2 1 3 3 1-2 2z",
  gear: "M8 5.5A2.5 2.5 0 0 0 8 10.5 2.5 2.5 0 0 0 8 5.5zM8 1.5v2m0 9v2M1.5 8h2m9 0h2M3.4 3.4l1.4 1.4m6.4 6.4 1.4 1.4m0-9.2-1.4 1.4M4.8 11.2l-1.4 1.4",
  close: "M3 3l10 10M13 3 3 13",
  chevron: "M4 6l4 4 4-4",
  file: "M4 1.5h5L12 4.5V14.5H4V1.5zM9 1.5V4.5h3",
  play: "M4 2.5v11l8-5.5-8-5.5z",
  check: "M2.5 8.5 6 12l7.5-8",
};

const FILE_ICON_COLOR = { py: "text-sky-400", js: "text-amber-400", json: "text-amber-300", md: "text-slate-400", yaml: "text-violet-300", txt: "text-slate-400", log: "text-slate-500", pcap: "text-rose-300" };

const MockBadge = () => (
  <span title="All data in this view is mock fixture data; the backend is not connected"
    className="select-none whitespace-nowrap rounded border border-amber-500/50 bg-amber-500/10 px-1.5 py-0.5 text-[9px] font-semibold tracking-wide text-amber-300">
    MOCK — BACKEND NOT CONNECTED
  </span>
);

const View = ({ children, className = "" }) => (
  <div className={"min-h-0 min-w-0 overflow-auto p-4 " + className}>{children}</div>
);

const KV = ({ k, v, mono = true }) => (
  <div className="flex min-w-0 gap-3 py-[3px] text-xs leading-5">
    <span className="w-32 shrink-0 text-slate-500">{k}</span>
    <span className={"min-w-0 break-words text-slate-200 " + (mono ? "font-mono text-[11px]" : "")}>{v}</span>
  </div>
);

const SectionTitle = ({ children }) => (
  <div className="mb-2 text-[10px] font-semibold uppercase tracking-[0.14em] text-slate-500">{children}</div>
);

const Panel = ({ title, children, right }) => (
  <section className="rounded border border-slate-800 bg-slate-900/40">
    <header className="flex items-center justify-between border-b border-slate-800 px-3 py-1.5">
      <span className="text-[10px] font-semibold uppercase tracking-[0.14em] text-slate-400">{title}</span>
      {right}
    </header>
    <div className="p-3">{children}</div>
  </section>
);

/* --------------------------- code highlighter ---------------------------- */
function tokenize(line) {
  // deterministic, conservative coloring (keywords/types/strings/comments/numbers)
  const parts = [];
  const re = /("(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'|#.*$|\b(?:import|from|def|return|if|else|elif|for|while|try|except|with|as|in|not|and|or|class|raise|True|False|None)\b|\b\d+(?:\.\d+)?\b)/g;
  let last = 0, m;
  while ((m = re.exec(line))) {
    if (m.index > last) parts.push({ t: "plain", s: line.slice(last, m.index) });
    const tok = m[0];
    const t = tok.startsWith("#") ? "comment" : tok.startsWith('"') || tok.startsWith("'") ? "string"
      : /^\d/.test(tok) ? "number" : "keyword";
    parts.push({ t, s: tok });
    last = m.index + tok.length;
  }
  if (last < line.length) parts.push({ t: "plain", s: line.slice(last) });
  if (!parts.length) parts.push({ t: "plain", s: "" });
  return parts;
}
const TOK_COLOR = { plain: "text-slate-300", comment: "text-slate-500 italic", string: "text-amber-300", number: "text-orange-300", keyword: "text-sky-400" };

/* ------------------------------ components ------------------------------ */
function Editor({ path, content, dirty }) {
  const [cursorLine, setCursorLine] = useState(1);
  const lines = useMemo(() => content.split("\n"), [content]);
  return (
    <div className="flex min-h-0 min-w-0 flex-1">
      <div className="flex min-h-0 min-w-0 flex-1 flex-col">
        {/* breadcrumb */}
        <div className="flex shrink-0 items-center gap-1 border-b border-slate-800/70 px-3 py-1 text-[10px] text-slate-500">
          {path.split("/").map((seg, i, arr) => (
            <span key={i} className={i === arr.length - 1 ? "text-slate-300" : ""}>
              {seg}{i < arr.length - 1 && <span className="mx-1 text-slate-600">›</span>}
            </span>
          ))}
          {dirty && <span className="ml-2 text-amber-400" title="modified">●</span>}
        </div>
        {/* code area */}
        <div className="relative min-h-0 min-w-0 flex-1 overflow-auto" dir="ltr">
          <div className="flex min-h-full">
            {/* gutter */}
            <div className="sticky left-0 z-10 select-none border-r border-slate-800/70 bg-slate-950 py-2 pl-3 pr-2 text-right font-mono text-[11px] leading-[19px]">
              {lines.map((_, i) => (
                <div key={i} className={i + 1 === cursorLine ? "text-slate-300" : "text-slate-600"}>{i + 1}</div>
              ))}
            </div>
            {/* code */}
            <div className="relative min-w-0 flex-1 py-2 pr-4">
              <div className="pointer-events-none absolute inset-x-0" style={{ top: 2 + (cursorLine - 1) * 19, height: 19 }}>
                <div className="h-full w-full bg-slate-800/40" />
              </div>
              <pre className="relative font-mono text-[11px] leading-[19px]">
                {lines.map((line, i) => (
                  <div key={i} onMouseDown={() => setCursorLine(i + 1)} className="cursor-text whitespace-pre">
                    {tokenize(line).map((p, j) => (
                      <span key={j} className={TOK_COLOR[p.t]}>{p.s}</span>
                    ))}
                  </div>
                ))}
              </pre>
            </div>
          </div>
        </div>
      </div>
      {/* minimap */}
      <div className="hidden w-24 shrink-0 border-l border-slate-800/70 bg-slate-950 py-2 lg:block" title="minimap (structural preview)" aria-hidden="true">
        {lines.map((line, i) => (
          <div key={i} className="mx-1 mb-[2px] h-[2px] rounded-sm bg-slate-700"
            style={{ width: Math.min(80, Math.max(4, line.length)) }} />
        ))}
      </div>
    </div>
  );
}

function Tabs({ tabs, active, onSelect, onClose }) {
  return (
    <div className="flex min-w-0 shrink-0 items-stretch overflow-x-auto border-b border-slate-800 bg-slate-900/60" role="tablist">
      {tabs.map((t) => {
        const isSpecial = t.special;
        const dirty = DIRTY.has(t.path);
        const ext = t.path.split(".").pop();
        return (
          <div key={t.key} role="tab" aria-selected={t.key === active}
            onClick={() => onSelect(t.key)}
            className={"group flex shrink-0 cursor-pointer items-center gap-1.5 border-r border-slate-800 px-3 py-1.5 text-[11px] transition-colors " +
              (t.key === active ? "border-t-2 border-t-emerald-500 bg-slate-950 text-slate-100" : "border-t-2 border-t-transparent text-slate-400 hover:bg-slate-900")}>
            {!isSpecial && <Icon d={IC.file} size={11} className={FILE_ICON_COLOR[ext] || "text-slate-500"} />}
            <span className={"max-w-[10rem] truncate " + (isSpecial ? "font-semibold uppercase tracking-wide text-[10px]" : "font-mono")}>
              {t.label}
            </span>
            {dirty && <span className="text-amber-400" title="unsaved change (mock)">●</span>}
            <button title={"Close " + t.label} aria-label={"Close tab " + t.label}
              onClick={(e) => { e.stopPropagation(); onClose(t.key); }}
              className="rounded p-0.5 text-slate-500 opacity-0 transition-opacity hover:bg-slate-700 hover:text-slate-200 group-hover:opacity-100">
              <Icon d={IC.close} size={10} />
            </button>
          </div>
        );
      })}
    </div>
  );
}

function ExplorerTree({ onOpen }) {
  const [expanded, setExpanded] = useState({ "mission/": true, "tools/": true, "recon/": false });
  const [sel, setSel] = useState("tools/scanner.py");
  const [q, setQ] = useState("");
  const toggle = (dir) => setExpanded((e) => ({ ...e, [dir]: !e[dir] }));
  const match = (name) => !q || name.includes(q);

  const renderDir = (dir, node, depth) => (
    <div key={dir}>
      <button onClick={() => toggle(dir)} title={dir}
        className="flex w-full items-center gap-1 rounded px-1 py-[3px] text-left text-[11px] text-slate-300 hover:bg-slate-800/70"
        style={{ paddingLeft: 4 + depth * 12 }}>
        <Icon d={IC.chevron} size={10} className={"text-slate-500 transition-transform " + (expanded[dir] ? "rotate-0" : "-rotate-90")} />
        <span className="truncate font-medium">{dir}</span>
        {Object.keys(node).length === 0 && <span className="text-[9px] text-slate-600">(empty)</span>}
      </button>
      {expanded[dir] && Object.entries(node).map(([name, child]) =>
        typeof child === "object"
          ? match(name) && renderDir(name, child, depth + 1)
          : match(name) && (
            <button key={name}
              onClick={() => { setSel(dir + name); onOpen(dir + name); }}
              title={dir + name + (DIRTY.has(dir + name) ? " — modified" : "")}
              className={"flex w-full items-center gap-1.5 rounded px-1 py-[3px] text-left text-[11px] hover:bg-slate-800/70 " +
                (sel === dir + name ? "bg-slate-800 text-slate-100" : "text-slate-400")}
              style={{ paddingLeft: 16 + depth * 12 }}>
              <Icon d={IC.file} size={11} className={FILE_ICON_COLOR[name.split(".").pop()] || "text-slate-500"} />
              <span className="truncate">{name}</span>
              {DIRTY.has(dir + name) && <span className="ml-auto shrink-0 text-amber-400" title="modified">M</span>}
            </button>
          )
      )}
    </div>
  );

  return (
    <div className="flex min-h-0 flex-1 flex-col">
      <div className="border-b border-slate-800/70 p-2">
        <input value={q} onChange={(e) => setQ(e.target.value)} placeholder="Search files…"
          aria-label="Search files"
          className="w-full rounded border border-slate-700/60 bg-slate-900 px-2 py-1 text-[11px] text-slate-200 placeholder:text-slate-600 focus:border-emerald-600 focus:outline-none focus-visible:ring-1 focus-visible:ring-emerald-600" />
      </div>
      <div className="min-h-0 flex-1 overflow-auto p-1">
        {Object.entries(TREE).map(([dir, node]) => renderDir(dir, node, 0))}
      </div>
      <div className="shrink-0 border-t border-slate-800/70 px-2 py-1 text-[9px] text-slate-600">
        permissions: backend-enforced (read/write in mission workspace)
      </div>
    </div>
  );
}

function AgentPanel({ mission }) {
  const s = STATUS[mission.status];
  return (
    <div className="flex min-h-0 flex-1 flex-col overflow-y-auto p-3">
      <div className="mb-3 flex items-center justify-between">
        <span className="text-[10px] font-semibold uppercase tracking-[0.14em] text-slate-500">Agent Activity</span>
        <MockBadge />
      </div>

      <div className={"mb-3 rounded border border-slate-800 px-2.5 py-2 " + (mission.status === "running" ? "bg-emerald-500/5" : "bg-slate-900/50")}>
        <div className="flex items-center gap-2 text-[11px] font-semibold text-slate-200">
          <span className={"h-1.5 w-1.5 rounded-full " + s.dot + (mission.status === "running" ? " animate-pulse" : "")} />
          MISSION ACTIVE — {s.label}
        </div>
      </div>

      {[
        ["Current phase", mission.phase],
        ["Current action", mission.action],
      ].map(([k, v]) => (
        <div key={k} className="mb-3">
          <div className="mb-1 text-[9px] font-semibold uppercase tracking-[0.14em] text-slate-500">{k}</div>
          <div className="border-l-2 border-slate-700 pl-2 text-[11px] leading-4 text-slate-300">{v}</div>
        </div>
      ))}

      <SectionTitle>Recent activity</SectionTitle>
      <ul className="mb-3 space-y-1 text-[11px] leading-4">
        {["Repository indexed", "42 files analyzed", "Authentication surface found", "Building test hypothesis"].map((t, i) => (
          <li key={i} className="flex gap-1.5 text-slate-300">
            <span className={i === 3 ? "text-sky-400" : "text-emerald-400"}>{i === 3 ? "→" : "✓"}</span>{t}
          </li>
        ))}
      </ul>

      <SectionTitle>Evidence</SectionTitle>
      <div className="mb-3 flex items-center gap-2 text-[11px] text-slate-300">
        <Icon d={IC.evidence} size={12} className="text-slate-400" /> 12 artifacts
      </div>

      <SectionTitle>Verification</SectionTitle>
      <div className="mb-3 space-y-0.5 text-[11px]">
        <div className="flex items-center gap-1.5 text-emerald-300"><Icon d={IC.check} size={11} /> 3 verified</div>
        <div className="flex items-center gap-1.5 text-amber-300">● 1 pending</div>
      </div>

      <div className="mt-auto rounded border border-slate-800 bg-slate-900/50 p-2 text-[10px] leading-4 text-slate-500">
        Operational events only: actions, outputs, evidence, decisions, provenance.
        Model chain-of-thought is never displayed.
      </div>
    </div>
  );
}

function TerminalView() {
  return (
    <div className="min-h-0 flex-1 overflow-auto bg-slate-950/70 p-3 font-mono text-[11px] leading-[18px]" dir="ltr">
      {TERMINAL_SESSION.map((s, i) => (
        <div key={i} className="mb-4">
          <div className="flex flex-wrap items-center gap-2">
            <span className="text-slate-600">{s.time}</span>
            <span className="text-emerald-400">$</span>
            <span className="text-slate-200">{s.cmd}</span>
          </div>
          <div className="mt-1 pl-4">
            {s.lines.map((l, j) => (
              <div key={j} className={l.startsWith("[+]") ? "text-emerald-300" : l.startsWith("[*]") ? "text-sky-300" : l.includes("failed") ? "text-rose-300" : "text-slate-400"}>
                {l}
              </div>
            ))}
          </div>
          <div className="mt-1 flex flex-wrap gap-3 pl-4 text-[10px] text-slate-500">
            <span className={s.exit === 0 ? "text-emerald-400" : "text-rose-400"}>Process exited with code {s.exit}</span>
            <span>Duration: {s.dur}</span>
            <span>Execution ID: {s.exec}</span>
          </div>
        </div>
      ))}
      <div className="text-slate-500">$ <span className="ml-1 inline-block h-3 w-[7px] animate-pulse bg-slate-400 align-middle" /></div>
      <p className="mt-2 text-[9px] text-slate-600">Credentials are injected server-side at execution time and never reach the browser.</p>
    </div>
  );
}

/* ------------------------------ rich views ------------------------------ */
function MissionDashboard({ mission }) {
  return (
    <View>
      <div className="mx-auto max-w-3xl space-y-4">
        <div className="rounded border border-slate-800 bg-slate-900/40 p-4">
          <div className="mb-3 flex items-center gap-2">
            <span className={"h-2 w-2 rounded-full " + STATUS[mission.status].dot} />
            <span className="text-sm font-semibold text-slate-100">{mission.id}</span>
            <span className={"text-[10px] font-semibold tracking-wider " + STATUS[mission.status].text}>{STATUS[mission.status].label}</span>
          </div>
          <p className="text-xs text-slate-300">{mission.objective}</p>
          <div className="mt-3">
            <div className="mb-1 flex justify-between text-[10px] text-slate-500"><span>Progress</span><span>{mission.progress}%</span></div>
            <div className="h-1 overflow-hidden rounded bg-slate-800">
              <div className={"h-full rounded " + STATUS[mission.status].bar} style={{ width: mission.progress + "%" }} />
            </div>
          </div>
        </div>
        <div className="grid gap-4 md:grid-cols-2">
          <Panel title="State">
            <KV k="Target" v={mission.target} />
            <KV k="Current phase" v={mission.phase} />
            <KV k="Current action" v={mission.action} />
            <KV k="Next planned" v={mission.next} />
          </Panel>
          <Panel title="Authorization">
            <KV k="Version" v={AUTH.version} />
            <KV k="Window" v={AUTH.window} />
            <KV k="Scope" v={AUTH.scope} mono={false} />
          </Panel>
          <Panel title="Progress">
            <KV k="Elapsed" v={mission.elapsed} />
            <KV k="Checkpoint" v={mission.checkpoint} />
            <KV k="Est. remaining" v={mission.eta} />
          </Panel>
          <Panel title="Summary">
            <KV k="Evidence" v="12 artifacts (2 shown in Evidence view)" />
            <KV k="Findings" v="3 (1 VERIFIED · 1 CLAIM · 1 UNKNOWN)" />
            <KV k="Artifacts" v="4 in workspace" />
          </Panel>
        </div>
      </div>
    </View>
  );
}

function TimelineView({ onOpenEvidence }) {
  const [sel, setSel] = useState(null);
  return (
    <View>
      <div className="mx-auto max-w-2xl">
        <div className="relative pl-5">
          <div className="absolute bottom-2 left-[7px] top-2 w-px bg-slate-700" />
          {TIMELINE.map((e, i) => (
            <div key={i} className="relative py-2">
              <span className={"absolute left-[-9px] top-4 h-2.5 w-2.5 rounded-full border-2 border-slate-950 " +
                (e.type === "verify" ? "bg-emerald-400" : e.type === "tool" ? "bg-sky-400" : e.type === "hypothesis" ? "bg-violet-400" : "bg-slate-500")}></span>
              <button onClick={() => setSel(sel === i ? null : i)} title="Toggle event detail"
                className="block w-full text-left">
                <span className="mr-3 font-mono text-[10px] text-slate-500">{e.t}</span>
                <span className="text-xs text-slate-200">{e.label}</span>
              </button>
              {sel === i && (
                <div className="mt-1.5 rounded border border-slate-800 bg-slate-900/70 p-2 text-[11px] leading-4 text-slate-300 transition-all">
                  {e.detail}
                </div>
              )}
            </div>
          ))}
        </div>
      </div>
    </View>
  );
}

function EvidenceView() {
  return (
    <View>
      <div className="mx-auto max-w-3xl space-y-4">
        <div className="text-[11px] text-slate-400">
          Hierarchy: <span className="text-slate-200">Finding → Evidence → Source → Artifact → Verification</span>.
          Nothing here means “AI says confirmed” — every row is a hash-anchored tool output or is explicitly marked otherwise.
        </div>
        {EVIDENCE.map((e) => (
          <Panel key={e.id} title={e.id + " — " + e.step} right={<span className="text-[9px] text-emerald-300">{e.validation}</span>}>
            <div className="grid gap-x-8 md:grid-cols-2">
              <KV k="Mission / Step" v={"MSN-2041 / " + e.step} />
              <KV k="Timestamp" v={e.time} />
              <KV k="Source" v={e.source} />
              <KV k="Tool" v={e.tool} />
              <KV k="Input hash" v={"sha256:" + e.inHash} />
              <KV k="Output hash" v={"sha256:" + e.outHash} />
              <KV k="Artifact" v={e.artifact} />
              <KV k="Provenance" v={e.provenance} mono={false} />
            </div>
          </Panel>
        ))}
      </div>
    </View>
  );
}

function FindingsView() {
  const badge = (st) =>
    st === "VERIFIED" ? "border-emerald-500/50 bg-emerald-500/10 text-emerald-300"
    : st === "CLAIM" ? "border-amber-500/50 bg-amber-500/10 text-amber-300"
    : "border-slate-500/50 bg-slate-500/10 text-slate-300";
  return (
    <View>
      <div className="mx-auto max-w-3xl space-y-3">
        {FINDINGS.map((f) => (
          <Panel key={f.id} title={f.id + " — " + f.title} right={
            <span className={"rounded border px-1.5 py-0.5 text-[9px] font-semibold tracking-wider " + badge(f.status)}>{f.status}</span>
          }>
            <div className="grid gap-x-8 md:grid-cols-2">
              <KV k="Target" v={f.target} />
              <KV k="Claim" v={f.claim} mono={false} />
              <KV k="Evidence" v={f.evidence.length ? f.evidence.join(", ") : "none (claim only)"} />
              <KV k="Reproduction" v={f.repro} />
              <KV k="Validator" v={f.validator + " → " + f.result} />
              <KV k="Confidence / Severity" v={f.confidence + " / " + f.severity} mono={false} />
            </div>
          </Panel>
        ))}
        <p className="text-[10px] text-slate-500">
          Statuses rendered exactly as mock data states: VERIFIED / CLAIM / UNKNOWN. The word “CONFIRMED” is not used unless the underlying state is Verified.
        </p>
      </div>
    </View>
  );
}

function AuthorizationView() {
  return (
    <View>
      <div className="mx-auto max-w-3xl space-y-4">
        <Panel title={"Authorization Snapshot — " + AUTH.version} right={<MockBadge />}>
          <div className="grid gap-x-8 md:grid-cols-2">
            <KV k="TARGET" v={AUTH.target} />
            <KV k="SCOPE" v={AUTH.scope} mono={false} />
            <KV k="ALLOWED ACTIONS" v={AUTH.allowed.join(" · ")} mono={false} />
            <KV k="FORBIDDEN ACTIONS" v={<span className="text-rose-300">{AUTH.forbidden.join(" · ")}</span>} mono={false} />
            <KV k="TOOLS" v={AUTH.tools.join(", ")} />
            <KV k="NETWORK" v={AUTH.network} mono={false} />
            <KV k="DATA" v={AUTH.data} mono={false} />
            <KV k="CREDENTIALS" v={AUTH.credentials} mono={false} />
            <KV k="TIME WINDOW" v={AUTH.window} />
            <KV k="RATE LIMIT" v={AUTH.rate} />
            <KV k="OWNER APPROVAL" v={AUTH.approval} mono={false} />
          </div>
        </Panel>
        <p className="text-[10px] leading-4 text-slate-500">
          Display-only. No control on this page changes backend authorization state.
          Enforcement lives in the backend Policy Engine / Scope Firewall; this UI cannot bypass, redefine, or cache credentials.
        </p>
      </div>
    </View>
  );
}

function SchedulerView() {
  return (
    <View>
      <div className="mx-auto max-w-3xl space-y-3">
        {SCHEDULES.map((s) => (
          <Panel key={s.id} title={s.id + " — " + s.mission} right={
            <span className={"text-[9px] font-semibold " + STATUS[s.status].text}>{STATUS[s.status].label}</span>
          }>
            <div className="grid gap-x-8 md:grid-cols-2">
              <KV k="Schedule" v={s.mode} mono={false} />
              <KV k="Recurrence" v={s.mode} mono={false} />
              <KV k="Next run" v={s.next} />
              <KV k="Last run" v={s.last} />
              <KV k="Retry policy" v={s.retry} mono={false} />
            </div>
          </Panel>
        ))}
        <p className="text-[10px] text-slate-500">Calendar view intentionally deferred — not needed at this stage.</p>
      </div>
    </View>
  );
}

function SourceControlView() {
  const [selFile, setSelFile] = useState("tools/scanner.py");
  return (
    <View>
      <div className="mx-auto max-w-3xl space-y-4">
        <Panel title={"Source Control — " + GIT.branch} right={<span className="text-[9px] text-slate-400">{GIT.status}</span>}>
          <SectionTitle>Changes</SectionTitle>
          <div className="mb-4 space-y-1">
            {GIT.files.map((f) => (
              <button key={f.path} onClick={() => setSelFile(f.path)} title={"Review " + f.path}
                className={"flex w-full items-center gap-2 rounded px-2 py-1 text-left text-[11px] hover:bg-slate-800/60 " +
                  (selFile === f.path ? "bg-slate-800" : "")}>
                <span className={"w-3 shrink-0 text-center font-bold " + (f.st === "A" ? "text-emerald-400" : "text-amber-400")}>{f.st}</span>
                <span className="truncate font-mono text-slate-300">{f.path}</span>
              </button>
            ))}
          </div>
          <SectionTitle>Diff — {selFile}</SectionTitle>
          <div className="overflow-x-auto rounded border border-slate-800 bg-slate-950/60 p-2 font-mono text-[11px] leading-[18px]" dir="ltr">
            <div className="text-emerald-400">+ # agent-authored scanner — pending Owner review</div>
            <div className="text-emerald-400">+ def scan(host, ports=(80, 443)):</div>
            <div className="text-rose-400">- def scan(host):</div>
            <div className="text-emerald-400">+     results = {}</div>
          </div>
          <SectionTitle>Commits</SectionTitle>
          <div className="space-y-1">
            {GIT.commits.map((c) => (
              <div key={c.h} className="flex flex-wrap items-center gap-2 font-mono text-[11px] text-slate-400">
                <span className="text-amber-400">{c.h}</span>
                <span>{c.msg}</span>
                <span className="ml-auto text-emerald-400">{c.tests}</span>
              </div>
            ))}
          </div>
        </Panel>
        <p className="text-[10px] text-slate-500">Merge to main requires Owner approval — outside this UI layer’s authority.</p>
      </div>
    </View>
  );
}

function SearchView({ onOpen }) {
  const [q, setQ] = useState("auth");
  const results = useMemo(() => {
    if (!q) return [];
    return Object.entries(FILES).flatMap(([p, c]) =>
      c.split("\n").map((l, i) => l.toLowerCase().includes(q.toLowerCase()) ? { p, i: i + 1, l } : null)
    ).filter(Boolean).slice(0, 30);
  }, [q]);
  return (
    <div className="flex min-h-0 flex-1 flex-col p-2">
      <input value={q} onChange={(e) => setQ(e.target.value)} placeholder="Search in workspace…"
        aria-label="Search in workspace"
        className="mb-2 w-full rounded border border-slate-700/60 bg-slate-900 px-2 py-1 text-[11px] text-slate-200 placeholder:text-slate-600 focus:border-emerald-600 focus:outline-none" />
      <div className="min-h-0 flex-1 overflow-auto">
        {results.length === 0 && <div className="p-2 text-[11px] text-slate-500">No results.</div>}
        {results.map((r, k) => (
          <button key={k} onClick={() => onOpen(r.p)} title={"Open " + r.p}
            className="block w-full truncate rounded px-2 py-1 text-left text-[11px] hover:bg-slate-800/70">
            <span className="font-mono text-slate-300">{r.p}</span>
            <span className="text-slate-600">:{r.i}</span>
            <div className="truncate font-mono text-[10px] text-slate-500">{r.l.trim()}</div>
          </button>
        ))}
      </div>
    </div>
  );
}

function MissionsSidebar({ selected, onSelect }) {
  return (
    <div className="min-h-0 flex-1 overflow-auto p-1">
      {Object.keys(STATUS).map((st) => (
        <div key={st} className="mb-1">
          <div className="px-1 py-1 text-[9px] font-semibold uppercase tracking-[0.14em] text-slate-600">{STATUS[st].label}</div>
          {MISSIONS.filter((m) => m.status === st).map((m) => (
            <button key={m.id} onClick={() => onSelect(m.id)} title={m.objective}
              className={"block w-full rounded px-2 py-1 text-left text-[11px] hover:bg-slate-800/70 " +
                (m.id === selected ? "bg-slate-800 text-slate-100" : "text-slate-400")}>
              <span className="font-mono">{m.id}</span>
              <div className="truncate text-[10px] text-slate-500">{m.objective}</div>
            </button>
          ))}
        </div>
      ))}
    </div>
  );
}

/* --------------------------------- app ---------------------------------- */
const ACTIVITY = [
  { id: "explorer", label: "Explorer", icon: IC.explorer },
  { id: "missions", label: "Missions", icon: IC.missions },
  { id: "search", label: "Search", icon: IC.search },
  { id: "scm", label: "Source Control", icon: IC.git },
  { id: "evidence", label: "Evidence", icon: IC.evidence },
  { id: "findings", label: "Findings", icon: IC.findings },
  { id: "reports", label: "Reports", icon: IC.reports },
  { id: "scheduler", label: "Scheduler", icon: IC.clock },
  { id: "tools", label: "Tools", icon: IC.tools },
  { id: "settings", label: "Settings", icon: IC.gear },
];

export default function App() {
  const [section, setSection] = useState("explorer");
  const [missionId, setMissionId] = useState("MSN-2041");
  const [tabs, setTabs] = useState([
    { key: "dashboard", special: true, label: "Mission Dashboard" },
    { key: "tools/scanner.py", path: "tools/scanner.py", label: "scanner.py" },
  ]);
  const [active, setActive] = useState("tools/scanner.py");
  const [panelOpen, setPanelOpen] = useState(true);
  const [panelTab, setPanelTab] = useState("terminal");
  const [rtl, setRtl] = useState(false);

  const mission = MISSIONS.find((m) => m.id === missionId);

  const openFile = useCallback((path) => {
    setTabs((t) => (t.some((x) => x.key === path) ? t : [...t, { key: path, path, label: path.split("/").pop() }]));
    setActive(path);
    setSection("explorer");
  }, []);

  const openView = useCallback((key, label) => {
    setTabs((t) => (t.some((x) => x.key === key) ? t : [...t, { key, special: true, label }]));
    setActive(key);
  }, []);

  const closeTab = (key) => {
    setTabs((t) => {
      const next = t.filter((x) => x.key !== key);
      if (active === key && next.length) setActive(next[next.length - 1].key);
      else if (!next.length) setActive(null);
      return next;
    });
  };

  const selectSection = (id) => {
    setSection(id);
    if (id === "missions") openView("dashboard", "Mission Dashboard");
    else if (id === "scm") openView("scm", "Source Control");
    else if (id === "evidence") openView("evidence", "Evidence");
    else if (id === "findings") openView("findings", "Findings");
    else if (id === "scheduler") openView("scheduler", "Scheduler");
    else if (id === "reports") openFile("reports/draft.md");
  };

  const activeTab = tabs.find((t) => t.key === active);
  const s = STATUS[mission.status];

  const editorContent = () => {
    if (!activeTab) return <View><div className="p-8 text-center text-xs text-slate-500">No editor open — select a file from the Explorer.</div></View>;
    if (activeTab.special) {
      const V = { dashboard: MissionDashboard, scm: SourceControlView, evidence: EvidenceView, findings: FindingsView, scheduler: SchedulerView }[activeTab.key];
      if (V) return <V mission={mission} />;
      return <View><div className="p-8 text-center text-xs text-slate-500">View not yet implemented (placeholder).</div></View>;
    }
    const content = FILES[activeTab.path];
    if (content === undefined) return <View><div className="p-8 text-center text-xs text-slate-500">No preview available for this file (binary or mock-empty).</div></View>;
    return <Editor path={activeTab.path} content={content} dirty={DIRTY.has(activeTab.path)} />;
  };

  return (
    <div dir={rtl ? "rtl" : "ltr"} className="flex h-screen min-h-0 flex-col overflow-hidden bg-slate-950 text-slate-200 antialiased"
      style={{ fontFamily: "ui-sans-serif, system-ui, 'Segoe UI', sans-serif" }}>

      {/* ================= top bar ================= */}
      <header className="flex h-9 shrink-0 items-center gap-3 border-b border-slate-800 bg-slate-900 px-3">
        <div className="flex items-center gap-2" title="CyberSentinel X">
          <div className="h-3.5 w-3.5 rounded-[3px] bg-emerald-400" />
          <span className="text-xs font-bold tracking-tight">CyberSentinel <span className="text-emerald-400">X</span></span>
        </div>
        <div className="hidden min-w-0 items-center gap-3 border-l border-slate-800 pl-3 text-[10px] text-slate-400 md:flex">
          <span>Mission <span className="font-mono text-slate-200">{mission.id}</span></span>
          <span className={"flex items-center gap-1 font-semibold " + s.text}>
            <span className={"h-1.5 w-1.5 rounded-full " + s.dot} />{s.label}
          </span>
          <span>Target <span className="font-mono text-slate-300">{mission.target}</span></span>
        </div>
        <div className="ml-auto flex shrink-0 items-center gap-2">
          <button onClick={() => setRtl(!rtl)} title="Toggle RTL (Arabic layout smoke test)" aria-label="Toggle RTL"
            className="rounded border border-slate-700 px-2 py-0.5 text-[10px] text-slate-300 hover:bg-slate-800 focus-visible:ring focus-visible:ring-emerald-500">
            {rtl ? "LTR" : "RTL"}
          </button>
          <MockBadge />
        </div>
      </header>

      <div className="flex min-h-0 flex-1">
        {/* ================= activity bar ================= */}
        <nav className="flex w-11 shrink-0 flex-col items-center gap-0.5 border-r border-slate-800 bg-slate-900/80 py-1" aria-label="Activity bar">
          {ACTIVITY.map((a) => (
            <button key={a.id} onClick={() => selectSection(a.id)} title={a.label} aria-label={a.label}
              aria-current={section === a.id}
              className={"relative flex h-9 w-9 items-center justify-center rounded transition-colors focus-visible:outline focus-visible:outline-emerald-500 " +
                (section === a.id ? "text-slate-100" : "text-slate-500 hover:text-slate-300")}>
              {section === a.id && <span className="absolute left-0 h-6 w-[2px] rounded-r bg-emerald-400" />}
              <Icon d={a.icon} size={19} />
            </button>
          ))}
        </nav>

        {/* ================= sidebar ================= */}
        <aside className="flex w-56 shrink-0 flex-col border-r border-slate-800 bg-slate-900/40 xl:w-64" aria-label="Side bar">
          <div className="flex h-8 shrink-0 items-center justify-between px-3 text-[10px] font-semibold uppercase tracking-[0.14em] text-slate-400">
            {ACTIVITY.find((a) => a.id === section)?.label || section}
            {section === "explorer" && <span className="text-[9px] font-normal text-slate-600">MISSION-2041</span>}
          </div>
          {section === "explorer" && <ExplorerTree onOpen={openFile} />}
          {section === "missions" && <MissionsSidebar selected={missionId} onSelect={setMissionId} />}
          {section === "search" && <SearchView onOpen={openFile} />}
          {section === "evidence" && (
            <div className="min-h-0 flex-1 overflow-auto p-2">
              {EVIDENCE.map((e) => (
                <button key={e.id} onClick={() => openView("evidence", "Evidence")} title={e.id + " — " + e.provenance}
                  className="mb-1 block w-full rounded border border-slate-800 px-2 py-1.5 text-left hover:bg-slate-800/60">
                  <div className="font-mono text-[11px] text-slate-200">{e.id}</div>
                  <div className="truncate text-[10px] text-slate-500">{e.source} · {e.step}</div>
                </button>
              ))}
            </div>
          )}
          {section === "findings" && (
            <div className="min-h-0 flex-1 overflow-auto p-2">
              {FINDINGS.map((f) => (
                <button key={f.id} onClick={() => openView("findings", "Findings")} title={f.title}
                  className="mb-1 block w-full rounded border border-slate-800 px-2 py-1.5 text-left hover:bg-slate-800/60">
                  <div className="flex items-center justify-between gap-2">
                    <span className="font-mono text-[11px] text-slate-200">{f.id}</span>
                    <span className={"text-[9px] font-semibold " + (f.status === "VERIFIED" ? "text-emerald-300" : f.status === "CLAIM" ? "text-amber-300" : "text-slate-400")}>{f.status}</span>
                  </div>
                  <div className="truncate text-[10px] text-slate-500">{f.title}</div>
                </button>
              ))}
            </div>
          )}
          {["scm", "reports", "scheduler", "tools", "settings"].includes(section) && (
            <div className="p-2 text-[10px] leading-4 text-slate-500">
              {section === "scm" && "Source Control review opens in the editor area →"}
              {section === "reports" && "Report files open from the Explorer (reports/)."}
              {section === "scheduler" && "Scheduler view opens in the editor area →"}
              {section === "tools" && "Tool inventory requires a backend endpoint (see WEB_API_REQUIREMENTS.md #16)."}
              {section === "settings" && "Settings are UI-local only (e.g. RTL toggle in top bar). No backend state is changed."}
            </div>
          )}
        </aside>

        {/* ================= editor column ================= */}
        <div className="flex min-w-0 flex-1 flex-col">
          {/* tabs */}
          <Tabs tabs={tabs} active={active} onSelect={setActive} onClose={closeTab} />

          {/* editor / view */}
          <div className="flex min-h-0 flex-1 flex-col">{editorContent()}</div>

          {/* ================= bottom panel ================= */}
          <div className="shrink-0 border-t border-slate-800 bg-slate-900/60" style={{ height: panelOpen ? 208 : 32 }}>
            <div className="flex h-8 items-center gap-1 px-2">
              {["terminal", "problems", "output", "evidence", "logs"].map((t) => (
                <button key={t} onClick={() => { setPanelTab(t); setPanelOpen(true); }} title={t[0].toUpperCase() + t.slice(1)}
                  className={"rounded px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wider transition-colors " +
                    (panelOpen && panelTab === t ? "text-slate-100" : "text-slate-500 hover:text-slate-300")}>
                  {t}
                </button>
              ))}
              <button onClick={() => setPanelOpen(!panelOpen)} title={panelOpen ? "Collapse panel" : "Expand panel"}
                aria-label="Toggle bottom panel"
                className="ml-auto rounded p-1 text-slate-500 hover:bg-slate-800 hover:text-slate-200 focus-visible:ring focus-visible:ring-emerald-500">
                <Icon d={IC.chevron} size={12} className={"transition-transform " + (panelOpen ? "" : "rotate-180")} />
              </button>
            </div>
            {panelOpen && (
              <div className="flex h-[176px] flex-col overflow-hidden border-t border-slate-800/70">
                {panelTab === "terminal" && <TerminalView />}
                {panelTab === "problems" && (
                  <div className="min-h-0 flex-1 overflow-auto p-2 text-[11px]">
                    {PROBLEMS.map((p, i) => (
                      <div key={i} className="mb-1 flex items-start gap-2">
                        <span className={p.sev === "warning" ? "text-amber-400" : "text-sky-400"}>●</span>
                        <span className="font-mono text-slate-300">{p.file}:{p.line}</span>
                        <span className="text-slate-400">{p.msg}</span>
                      </div>
                    ))}
                  </div>
                )}
                {panelTab === "output" && (
                  <div className="min-h-0 flex-1 overflow-auto bg-slate-950/70 p-2 font-mono text-[11px] leading-[18px] text-slate-400" dir="ltr">
                    {OUTPUT_LINES.map((l, i) => <div key={i}>{l}</div>)}
                  </div>
                )}
                {panelTab === "evidence" && (
                  <div className="min-h-0 flex-1 overflow-auto p-2 text-[11px]">
                    {EVIDENCE.map((e) => (
                      <div key={e.id} className="mb-1 flex flex-wrap gap-2 text-slate-300">
                        <span className="font-mono text-emerald-300">{e.id}</span>
                        <span className="text-slate-500">{e.step}</span>
                        <span className="font-mono text-slate-400">{e.inHash} → {e.outHash}</span>
                        <span className="text-slate-500">{e.validation}</span>
                      </div>
                    ))}
                  </div>
                )}
                {panelTab === "logs" && (
                  <div className="min-h-0 flex-1 overflow-auto p-2 font-mono text-[10px] leading-4 text-slate-500" dir="ltr">
                    {OUTPUT_LINES.concat(["[mock] log stream requires backend endpoint (WEB_API_REQUIREMENTS.md #9)"]).map((l, i) => <div key={i}>{l}</div>)}
                  </div>
                )}
              </div>
            )}
          </div>
        </div>

        {/* ================= agent panel ================= */}
        <aside className="hidden w-60 shrink-0 flex-col border-l border-slate-800 bg-slate-900/40 lg:flex" aria-label="Agent activity">
          <AgentPanel mission={mission} />
        </aside>
      </div>

      {/* ================= status bar ================= */}
      <footer className="flex h-6 shrink-0 items-center gap-4 overflow-x-auto border-t border-slate-800 bg-slate-900 px-3 text-[10px] text-slate-500" dir="ltr">
        <span className={"flex items-center gap-1 font-semibold " + s.text}>
          <span className={"h-1.5 w-1.5 rounded-full " + s.dot} />{mission.id} — {s.label}
        </span>
        <span>Phase: <span className="text-slate-300">{mission.phase}</span></span>
        <span>Elapsed: <span className="font-mono text-slate-300">{mission.elapsed}</span></span>
        <span>Checkpoint: <span className="font-mono text-slate-300">{mission.checkpoint}</span></span>
        <span className="ml-auto shrink-0">backend: not connected · secrets in bundle: none · authorization: backend-enforced</span>
      </footer>
    </div>
  );
}
