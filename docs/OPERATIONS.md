# CyberSentinel X 5.0.0 — Local operation

1. Create `.env` from `.env.example`.
2. Put a strong random value in `BRIDGE_TOKEN` (transport channel only).
3. Install dependencies with `python -m pip install -r requirements.txt`.
4. Run `python -m compileall -q .`.
5. Run `pytest -q`.
6. Run `python bridge.py`.
7. Open `http://127.0.0.1:8787/` on the same device.
8. When prompted, enter the bridge token, then sign in as Owner with username and password (`python -m security.owner_password_bootstrap` creates the account locally).

The bridge token is sent in `X-CyberSentinel-Token` and authenticates the local channel only. Owner identity comes exclusively from a server-side session created by `POST /api/auth/login` (username+password) and is sent as `X-CyberSentinel-Owner-Session`. The password is stored only as a scrypt verifier and never appears in API responses, audit events, or source control.

The service binds exclusively to `127.0.0.1`. Optional OpenAI-compatible providers are configured through `LOCAL_LLM_*`, `COLAB_LLM_*`, or `HF_LLM_*` variables. With no provider configured, the deterministic local planner is used.

Useful defensive commands include:

- `حدّث استخبارات التهديدات`
- `افحص الجهاز محليًا`
- `اعرض أحدث الثغرات`
- `ابحث عن CVE-`
- `راقب nginx`
