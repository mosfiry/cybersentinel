# CyberSentinel X 4.8.0 — Local operation

1. Create `.env` from `.env.example`.
2. Put two different strong random values in `BRIDGE_TOKEN` and `OWNER_TOKEN`.
3. Install dependencies with `python -m pip install -r requirements.txt`.
4. Run `python -m compileall -q .`.
5. Run `pytest -q`.
6. Run `python bridge.py`.
7. Open `http://127.0.0.1:8787/` on the same device.
8. When prompted, enter the bridge token and then the Owner token.

The bridge token is sent in `X-CyberSentinel-Token`. Owner authority is sent separately in `X-CyberSentinel-Owner-Token`. Neither token is returned in API responses or audit events.

The service binds exclusively to `127.0.0.1`. Optional OpenAI-compatible providers are configured through `LOCAL_LLM_*`, `COLAB_LLM_*`, or `HF_LLM_*` variables. With no provider configured, the deterministic local planner is used.

Useful defensive commands include:

- `حدّث استخبارات التهديدات`
- `افحص الجهاز محليًا`
- `اعرض أحدث الثغرات`
- `ابحث عن CVE-`
- `راقب nginx`
