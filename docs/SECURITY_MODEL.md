# CyberSentinel X — Final Security Model

## Trust
Only authenticated owner requests from the local Web UI are instruction authority.
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
A deterministic planner is always available. An optional OpenAI-compatible endpoint can
be configured, but the returned tool names are intersected with the same allowlist.
The model cannot create a new executable tool through its response.

## Audit
Plans and executions are stored in SQLite. Failed collection is recorded as a warning.

## Honest execution
The UI displays actual tool results. It does not claim that a tool ran when it did not.
