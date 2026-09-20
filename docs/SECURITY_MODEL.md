# CyberSentinel X 4.7.0 — Security Model

## Trust
The local bridge authenticates the channel with `BRIDGE_TOKEN`; only requests that also carry the separate `OWNER_TOKEN` are instruction authority.
CISA, RSS, CVE records, and any other external content are evidence only.

## Network
The bridge binds exclusively to `127.0.0.1`. It is not a LAN service.

## Execution
The final build has an explicit allowlist:
- status
- latest_intel
- refresh_intel
- local_security_check
- local_system_info
- search
- watch
- unwatch

There is no arbitrary shell endpoint, remote scanner, exploit runner, credential dumper,
malware deployer, persistence mechanism, or authentication bypass tool.

## Planner
`AgentRuntime` is the only planner path. A deterministic planner is always available. An optional OpenAI-compatible endpoint can
be configured, but its JSON output is validated and the returned tool names and arguments are checked by deterministic authorization code.
The model cannot create a new executable tool through its response.

## Audit
Requests receive a UUID and plans, authentication, policy, authorization, execution, failures, provenance, and responses are stored in SQLite. Failed collection is recorded as a warning and represented as failed evidence rather than success.

## Honest execution
The UI displays actual tool results. It does not claim that a tool ran when it did not.
