# CyberSentinel X 5.0.0 — Local operation

1. Create `.env` from `.env.example` and replace `BRIDGE_TOKEN` with a random transport secret.
2. Install dependencies with `python -m pip install -r requirements.txt`.
3. Create the Owner account interactively with `python -m security.owner_password_bootstrap`. The password is not echoed and only its scrypt verifier is persisted.
4. Keep `PUBLIC_WEB_ENABLED=true` to use the shipped browser UI. `BRIDGE_HOST` must remain `127.0.0.1`; the service refuses other bind addresses.
5. Run `python -m compileall -q .` and `pytest -q`.
6. Run `python bridge.py`, then open `http://127.0.0.1:8787/` on the same device and sign in with the Owner username and password.

The browser first obtains a short-lived public session and CSRF token. Owner login verifies the account using the canonical password-authentication module and sets a separate `HttpOnly; Secure; SameSite=Lax` Owner-session cookie. The cookie refers to the server-side Owner session and is never returned to JavaScript or stored in browser storage. Anonymous public sessions remain unable to use chat. Internal clients use `X-CyberSentinel-Token` for transport and `X-CyberSentinel-Owner-Session` for Owner-authenticated routes; the two credentials are not interchangeable.

`PUBLIC_WEB_ORIGIN` may be set to the exact browser origin. If it is blank, browser API requests with an `Origin` header must match the request host. `PUBLIC_SESSION_TTL_SECONDS` controls the CSRF session lifetime; Owner sessions expire after eight hours and can be revoked through logout. Optional OpenAI-compatible configuration uses `LLM_BASE_URL`, `LLM_API_KEY`, and `LLM_MODEL`; with no provider configured, the deterministic local planner remains available.

Useful defensive commands include:

- `حدّث استخبارات التهديدات`
- `افحص الجهاز محليًا`
- `اعرض أحدث الثغرات`
- `ابحث عن CVE-`
- `راقب nginx`
`PUBLIC_WEB_ORIGIN` may be set to an exact allowed browser origin. If it is blank, browser API requests with an `Origin` header must match the request host. The shipped UI is same-origin; the service does not enable cross-origin CORS or preflight. `PUBLIC_SESSION_TTL_SECONDS` controls the CSRF session lifetime; Owner sessions expire after eight hours and can be revoked through logout. Optional OpenAI-compatible configuration uses `LLM_BASE_URL`, `LLM_API_KEY`, and `LLM_MODEL`; with no provider configured, the deterministic local planner remains available.
