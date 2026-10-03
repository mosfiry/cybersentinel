# CyberSentinel X 5.0.0 — Operations

## Local development

1. Create `.env` from `.env.example` and set `BRIDGE_TOKEN` to a private random value of at least 32 characters. Keep `.env` untracked.
2. Install dependencies with `python -m pip install -r requirements.txt`.
3. Initialize the Owner username/password account once with `python -m security.owner_password_bootstrap`. The password is entered interactively and stored as a verifier.
4. Run `python -m compileall -q .` and `pytest -q`.
5. Start the bridge with `python bridge.py` and open `http://127.0.0.1:8787/` on the same device.

`BRIDGE_TOKEN` is transport authentication sent in `X-CyberSentinel-Token`; it does not establish Owner identity. Owner login uses the existing username/password flow and returns a server-side session. There is no runtime `OWNER_TOKEN` credential. The bridge binds exclusively to `127.0.0.1` by default; Compose uses the explicit non-loopback bind opt-in inside its private container network while keeping host publishing on loopback. Do not enable that opt-in for an ordinary host process.

Optional OpenAI-compatible providers may be configured through `LLM_*`, `LOCAL_LLM_*`, `COLAB_LLM_*`, or `HF_LLM_*` environment variables. Provider keys are runtime credentials; never place them in a source file, image build argument, or public frontend asset.

## Single-host container runtime (loopback only)

The repository includes a Docker Compose target for the source-compatible runtime: one HTTP bridge and one supervised mission worker sharing a single local named `cybersentinel-state` volume for database/policy state and workspace files. This is a single-host configuration; it is not a public internet deployment and does not claim high availability. SQLite state must remain on a local filesystem, with one configured worker.

Requirements are Docker Engine **28.0.0 or newer** and the Docker Compose plugin. Docker documents a same-layer-2 exposure caveat for localhost-published ports on earlier Engine releases; see [port publishing](https://docs.docker.com/engine/network/port-publishing/). Confirm the server version with `docker version --format '{{.Server.Version}}'`. From the repository root:

```bash
cp .env.example .env
# Replace BRIDGE_TOKEN with a private random value of at least 32 characters.
docker compose config --quiet
docker compose build
docker compose run --rm bridge python -m security.owner_password_bootstrap
docker compose up -d
docker compose ps
curl -fsS http://127.0.0.1:8787/api/health
docker compose logs --tail=100
docker compose restart mission-worker
docker compose stop
docker compose start
docker compose down
```

Compose requires a non-placeholder `BRIDGE_TOKEN` and opts the bridge into `0.0.0.0` **inside the container only**. Its published host port defaults to `127.0.0.1:8787`; an alternate local port can be selected with `BRIDGE_PUBLISHED_PORT`. The Engine 28+ requirement matters: Docker warns that earlier releases can expose localhost-published ports to peers on the same layer-2 segment. Do not change the host address in `ports` to `0.0.0.0`, enable public-web mode, or add a public proxy/domain without a separate security/authority review. `GET /api/health` is a process liveness check, not proof of Owner, provider, or production readiness. The worker health check verifies the exact configured live worker process; queue recovery and generation behavior still require the runtime tests.

The single named `cybersentinel-state` volume stores all SQLite databases, mutable Owner policy state, and scoped workspace files at the existing `/var/lib/cybersentinel/workspace` path. A non-root, read-only `workspace-init` service runs to completion before either long-running service; it creates the workspace directory once when absent, preserves existing files in place, and refuses a symlinked path. No workspace copy/migration is needed when upgrading from the earlier V12 Compose layout. Use the same Compose project name so Compose reattaches the existing named volume, stop the services before upgrade, and back up the whole volume first. `docker compose down` preserves it. **Do not run `docker compose down --volumes` unless permanent deletion is explicitly intended and a verified backup exists.** Use approved host backup tooling for the stopped volume and rehearse restoration. Do not copy a single live SQLite file or place the state volume on an unverified network filesystem. No ignored local database is copied into the image or automatically migrated into this volume.

The image is non-root, uses a read-only container root plus the writable state volume and `/tmp` tmpfs, and receives optional provider settings only at runtime. Owner account bootstrap writes to the persistent state volume. The sample `OWNER_TOKEN` was removed because the current application does not consume it; Owner authority is the existing username/password session boundary. The worker health check requires the full Compose command (`python -m scripts.run_mission_worker --worker-id cybersentinel-worker --poll-interval 1`) as a live direct child of container init and rejects changed/extra arguments and stopped/traced/zombie states, but remains a process-liveness signal rather than proof of queue recovery. `workspace-init` rejects static symlink substitution and checks the resolved path, but these startup shell checks are not race-free isolation against a concurrent same-UID writer with access to the state volume. Do not share that volume with unrelated containers or users; request-level scope remains enforced by the runtime/tool boundary.

## Deployment boundary

`firebase.json` remains the existing static-hosting configuration; it has no backend rewrite. The current bridge, durable worker process, and SQLite storage are not deployed to Cloudflare Workers. No public backend host, domain, TLS ingress, Firebase/Cloudflare routing change, production credentials, or production database is selected by this configuration. Keep production deployment blocked until the exact target and authority are known and the later M3 cutover gates pass.
