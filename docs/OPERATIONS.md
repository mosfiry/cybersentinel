# CyberSentinel X 5.0.0 — Operations

## Local development

1. Create `.env` from `.env.example`, set `BRIDGE_TOKEN` to a private random value of at least 32 characters, and keep the file untracked with mode `0600`.
2. Install dependencies with `python -m pip install -r requirements.txt`.
3. Initialize the Owner username/password account once with `python -m security.owner_password_bootstrap`. The password is entered interactively and stored as a verifier.
4. Run `python -m compileall -q .` and `pytest -q`.
5. Start the bridge with `python bridge.py` and open `http://127.0.0.1:8787/` on the same device.

`BRIDGE_TOKEN` is transport authentication sent in `X-CyberSentinel-Token`; it does not establish Owner identity. Owner login uses the existing username/password flow and returns a server-side session. There is no runtime `OWNER_TOKEN` credential. The bridge binds exclusively to `127.0.0.1` by default; Compose uses the explicit non-loopback bind opt-in inside its private container network while keeping host publishing on loopback. Do not enable that opt-in for an ordinary host process.

Optional OpenAI-compatible providers may be configured through `LLM_*`, `LOCAL_LLM_*`, `COLAB_LLM_*`, or `HF_LLM_*` settings. For a direct host process, credentials may be supplied through its private environment. In Compose, provider keys are mounted as file-backed secrets and must not be put in `.env`, a source file, an image build argument, or a public frontend asset.

### Health and readiness

`GET /api/health` remains the backward-compatible, unauthenticated process-liveness probe; `GET /api/health/live` reports the same liveness explicitly. `GET /api/health/ready` requires the transport-only `X-CyberSentinel-Token` header and returns `200` only when the core SQLite store passes a read-only integrity/schema check and an active Owner account has been initialized. It returns `503` while the database or Owner setup is unavailable; the probe does not create a database, run migrations, expose paths, or establish Owner identity. Provider configuration is reported as unverified without making a network request, and worker health remains an independent Compose process check; neither is inferred from bridge readiness.

### Owner-scoped mission reports

`GET /api/missions/{mission_id}/report` uses the existing bridge transport token and live Owner-session checks; it is not a public report endpoint. It reads mission evidence and the durable evidence chain without running a tool, contacting a provider, or modifying either SQLite database. `VERIFIED` requires the persisted completed state, recorded runtime verification, required criteria supported by deterministic tool/observation provenance, and a valid evidence chain when one is present. Model proposals and legacy evidence without the deterministic provenance marker remain explicitly unverified; invalid or unreadable chain state withholds a verified outcome. The report's Owner-approval field reflects only the mission authorization snapshot and does not assert current authority or action-level approval.

## Single-host container runtime (loopback only)

The supported self-hosted target is Docker Compose on Linux: one HTTP bridge and one supervised mission worker share a single local named `cybersentinel-state` volume for SQLite databases, policy state, and workspace files. This is a single-host configuration, not a public-internet deployment or high-availability claim. SQLite state must remain on a local filesystem with one configured worker.

Requirements: Docker Engine **28.0.0 or newer**, Docker Compose plugin, and Linux containers. The Engine 28+ requirement matters because Docker documents a same-layer-2 exposure caveat for localhost-published ports on earlier Engine releases; see [port publishing](https://docs.docker.com/engine/network/port-publishing/). Compose file-backed secrets are Linux-only; see [Docker Compose secrets](https://docs.docker.com/compose/how-tos/use-secrets/). This deployment has been designed for a rootful Docker Engine and the numeric container UID/GID `10001:10001`; rootless Docker and user-namespace remapping are not validated by this release target.

From the repository root:

```bash
cp .env.example .env
chmod 600 .env
sudo python3 scripts/prepare_compose_secrets.py
# Optional: edit the provider-key file(s) as root; leave unused ones empty.
sudoedit secrets/llm_api_key
# If a file was replaced, restore root:10001 ownership and mode 0440.
sudo chown root:10001 secrets/llm_api_key
sudo chmod 0440 secrets/llm_api_key
docker compose config --quiet
docker compose build --pull
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

The setup command generates the bridge transport token once and never prints it. It creates blank files for optional provider keys and preserves existing files on later runs. Secret files are root-owned, group-readable only by GID `10001`, mode `0440`, and mounted read-only under `/run/secrets/`. The bridge receives its transport token and configured provider keys; the worker receives only provider keys and does not receive the bridge token. The application reads secrets from `*_FILE` paths using no-follow, bounded regular-file reads; direct environment variables remain supported for non-Compose development, but Compose does not pass credential values in its container environment. Use `sudo cat secrets/bridge_token` only when an authorized client must be provisioned with the transport credential. Keep the directory and secret files out of backups or archives unless those artifacts are separately encrypted and access-controlled.

To rotate a provider key, stop or recreate the relevant service after changing its file: `docker compose up -d --force-recreate bridge mission-worker`. The file-based Compose secret is a read-only bind mount; replacing a host file does not guarantee that an already-running container sees the new inode. Do not put secret values on a command line or in shell history.

The Compose file defines a dedicated bridge network shared only by the bridge and mission worker; provider egress remains available, and the one-shot workspace initializer has no network. Only the bridge publishes a port, bound to `127.0.0.1:${BRIDGE_PUBLISHED_PORT:-8787}` on the host. The worker has no published port. Compose requires a non-placeholder bridge token and opts the bridge into `0.0.0.0` **inside its container only**. Do not change the host address in `ports` to `0.0.0.0`, enable public-web mode, or add a public proxy/domain without a separate security/authority review. `GET /api/health` is a process liveness check, not proof of Owner, provider, or production readiness. The worker health check verifies the exact configured live worker process; queue recovery and generation behavior still require the runtime tests.

The image uses the Python 3.12 slim Bookworm base, installs only runtime dependencies, runs as numeric UID/GID `10001:10001`, and keeps application files root-owned. Long-running services use a read-only container root, dropped capabilities, `no-new-privileges`, a bounded `/tmp` tmpfs, rotating `json-file` logs (10 MiB × 5), and `unless-stopped` restart policy. The workspace initializer is non-root, read-only, network-isolated, and runs once before the bridge or worker; it creates the workspace directory when absent, preserves existing files, and refuses a symlinked path.

The named state volume stores all SQLite databases, mutable Owner policy state, and scoped workspace files at `/var/lib/cybersentinel/workspace`. Use the same Compose project name so Compose reattaches the existing volume; stop services before upgrading and back up the whole volume first. `docker compose down` preserves it. **Do not run `docker compose down --volumes` unless permanent deletion is explicitly intended and a verified backup exists.** Use approved host backup tooling for the stopped volume and rehearse restoration. Do not copy a single live SQLite file or place the state volume on an unverified network filesystem. No ignored local database is copied into the image or automatically migrated into this volume. The M3 cutover rehearsal's explicit test cleanup may remove only its isolated CI volume.

### State backup, restore, and upgrade

The image includes `/app/scripts/state_archive.py`. It writes a gzip tar archive with a versioned manifest and per-file SHA-256 hashes. It refuses symlinks and non-regular files, verifies the full archive before restore, and restores only into an empty state directory; it never overwrites an existing volume. Restored files are owned by the process performing restore (UID/GID `10001:10001` in the production container), and basic POSIX mode bits are preserved; ownership, ACLs, extended attributes, and timestamps are not. The archive covers the complete state volume (SQLite files and workspace), but **does not include `.env`, Compose secret files, provider credentials, or bridge-token files**. State archives can still contain sensitive Owner, mission, and workspace data: store them access-controlled and encrypted outside the host, and manage the separate deployment secrets securely.

Create and verify a consistent backup while both stateful services are stopped:

```bash
set -euo pipefail
umask 077
backup_dir=/secure/backup/cybersentinel
install -d -m 700 "$backup_dir"
backup="$backup_dir/state-$(date -u +%Y%m%dT%H%M%SZ)-$$.tar.gz"
temporary="$backup.tmp"
if [[ -e "$backup" || -e "$backup.sha256" || -e "$temporary" ]]; then
  echo "Refusing to overwrite an existing backup path" >&2
  exit 1
fi
running_services="$(docker compose ps --status running --services)"
resume_services=()
for service in bridge mission-worker; do
  if grep -Fxq "$service" <<<"$running_services"; then
    resume_services+=("$service")
  fi
done
resume_services_now() {
  rm -f -- "$temporary"
  if ((${#resume_services[@]})); then
    docker compose start "${resume_services[@]}" >/dev/null
  fi
}
trap resume_services_now EXIT
docker compose stop bridge mission-worker
docker compose run --rm --no-deps -T --entrypoint python workspace-init \
  /app/scripts/state_archive.py backup > "$temporary"
docker compose run --rm --no-deps -T --entrypoint python workspace-init \
  /app/scripts/state_archive.py verify < "$temporary"
chmod 600 "$temporary"
mv "$temporary" "$backup"
sha256sum "$backup" > "$backup.sha256"
chmod 600 "$backup.sha256"
if ((${#resume_services[@]})); then
  docker compose start "${resume_services[@]}"
fi
trap - EXIT
```

Before restore, check the outer checksum with `sha256sum -c "$backup.sha256"`. Use a **new Compose project name** so the restore mounts a new empty named volume; do not point the restore at the live project or an existing state directory. The example uses loopback port `18789`, leaving the current project and its data untouched:

```bash
restore_project=cybersentinel-restore
export BRIDGE_PUBLISHED_PORT=18789
docker compose -p "$restore_project" run --rm --no-deps -T --entrypoint python workspace-init \
  /app/scripts/state_archive.py verify < "$backup"
docker compose -p "$restore_project" run --rm --no-deps -T --entrypoint python workspace-init \
  /app/scripts/state_archive.py restore < "$backup"
docker compose -p "$restore_project" up -d bridge
docker compose -p "$restore_project" ps
```

The restored project uses the current `.env` and separate host secret files, so validate those before starting it. Log in as the Owner on `http://127.0.0.1:18789/` and confirm the expected mission/state before any cutover. `restore` does not promote the recovered project or change the original project's volume; choose and execute any production cutover separately. To upgrade in place, stop services, create and verify a backup first, then rebuild and start the same Compose project so it reuses the named volume. SQLite stores apply their component-specific additive/idempotent schema migrations at startup. Do not roll back an image against a database already migrated by a newer image; recover into a separate project from the pre-upgrade backup instead.

### Unpublished release bundle

A successful push to the dedicated release branch runs a separate CI packaging job only after the full tests, container smoke checks, and M3 rehearsal pass. It uploads an unpublished workflow artifact named `cybersentinel-release-candidate-<commit-sha>` containing the versioned Docker image tar, Compose bundle, `.env.example`, installation/backup/restore scripts, version metadata, release notes, and SHA-256 manifests. This workflow does not create a GitHub Release, publish to a registry, deploy to a public host, or create a Git tag.

After downloading the workflow artifact, verify and extract the archive before use:

```bash
sha256sum --check --strict cybersentinel-5.0.0-release.tar.gz.sha256
tar -xzf cybersentinel-5.0.0-release.tar.gz
cd cybersentinel-5.0.0
sha256sum --check --strict SHA256SUMS
python3 scripts/package_release.py verify ../cybersentinel-5.0.0-release.tar.gz
./scripts/install_compose.sh
```

The installer requires Linux, Docker Engine 28+, Docker Compose, `sudo` for secret-file preparation, and an interactive terminal for one-time Owner account initialization. It loads the included image, preserves existing `.env` files (or creates one from the template), validates the archive hashes, creates/preserves file-backed secrets without printing their values, and starts the bridge only on loopback. Review `.env` and configure any provider endpoints before relying on provider-backed missions.

Use `./scripts/backup_state.sh /secure/backup/cybersentinel` to stop stateful services, create and internally verify a whole-volume archive, write a SHA-256 sidecar, then restore only services that were running. Store backups access-controlled and encrypted off-host. Restore with `./scripts/restore_state.sh /secure/backup/<archive>.tar.gz <new-unique-project-name>`; it verifies the sidecar and archive, refuses the current project or an existing restore volume, restores to a separate empty volume, and deliberately leaves the restored services stopped. Review `.env`/secrets, select an unused loopback port, verify the restored Owner and mission state, and start that project only when ready.

### Deployment boundary

`firebase.json` remains the existing static-hosting configuration; it has no backend rewrite. The bridge, durable worker, and SQLite storage are not deployed to a public platform. This Compose configuration has no Cloudflare dependency and does not select a public backend host, domain, TLS ingress, production credentials, or production database. Keep production deployment blocked until the exact target and authority are known and the later M3 cutover gates pass.
