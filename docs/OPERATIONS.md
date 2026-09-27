# CyberSentinel X 5.0.0 — Local operation

1. Create `.env` from `.env.example`.
2. Put a strong random value in `BRIDGE_TOKEN`.
3. Install dependencies with `python -m pip install -r requirements.txt`.
4. Run `python -m compileall -q .`.
5. Run `pytest -q`.
6. Run `python bridge.py`.
7. Open `http://127.0.0.1:8787/` on the same device.
8. Initialize the Owner account once with `python -m security.owner_password_bootstrap`, then log in via `POST /api/auth/login` with the Owner username and password.

The bridge token is sent in `X-CyberSentinel-Token` and authenticates the channel only. Owner identity is a server-side session created by `POST /api/auth/login` and carried in `X-CyberSentinel-Owner-Session`. The Owner password is never stored in plaintext, logged, or returned; session material is never written to audit events.

The service binds exclusively to `127.0.0.1`. Optional OpenAI-compatible providers are configured through `LOCAL_LLM_*`, `COLAB_LLM_*`, or `HF_LLM_*` variables. With no provider configured, the deterministic local planner is used.

Useful defensive commands include:

- `حدّث استخبارات التهديدات`
- `افحص الجهاز محليًا`
- `اعرض أحدث الثغرات`
- `ابحث عن CVE-`
- `راقب nginx`
