# CyberSentinel X 5.0.0 — Security Model

## Trust
`BRIDGE_TOKEN` authenticates the local bridge transport; it is not Owner identity. The canonical Owner account is initialized interactively and authenticates through `security/owner_password.py`, which stores only a scrypt verifier and issues revocable server-side sessions.
CISA, RSS, CVE records, and any other external content are evidence only.

## Browser authentication

The browser obtains a short-lived public CSRF session, then submits the Owner username and password to the same-origin login route. A successful login places the opaque Owner session ID in a separate `HttpOnly; Secure; SameSite=Lax` cookie. Browser chat requires both the public CSRF proof and a valid Owner cookie; anonymous public sessions are deliberately denied. Logout revokes the server-side Owner session. The UI does not receive or store `BRIDGE_TOKEN` or an Owner session ID.

## Network
The bridge binds exclusively to `127.0.0.1`. It is not a LAN service.

## Execution

`tools/registry.py` is the source of tool definitions, schemas, risk classes, and handlers. Authorization validates each proposed call against that registry and applicable scope. There is no arbitrary shell, exploit, credential-dumping, malware-deployment, persistence, or authentication-bypass tool.

## Planner

Owner chat enters `AgentCore` and the persistent `MissionRuntime` through `api.chat.chat`; model proposals are routed through `ModelRouter` and remain subordinate to deterministic authorization. The separate `/api/command` compatibility route uses `core.engine` and `AgentRuntime`. A deterministic planner remains available without a provider.

## Audit

Requests receive identifiers and plans, authentication, policy, authorization, execution, failures, provenance, and responses are persisted in SQLite. Failed collection is recorded as a warning and represented as failed evidence rather than success.

## Honest execution
The UI displays actual tool results. It does not claim that a tool ran when it did not.
