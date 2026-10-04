#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
cd "$ROOT"
version="$(tr -d '\r\n' < VERSION)"
if [[ ! "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  echo "invalid release VERSION file" >&2
  exit 2
fi

if [[ "$(uname -s)" != "Linux" ]]; then
  echo "this release bundle supports Linux containers on Linux hosts only" >&2
  exit 2
fi
for command_name in docker python3 sha256sum curl; do
  command -v "$command_name" >/dev/null 2>&1 || {
    echo "required command is unavailable: $command_name" >&2
    exit 2
  }
done

engine_version="$(docker version --format '{{.Server.Version}}' 2>/dev/null || true)"
engine_major="${engine_version%%.*}"
if [[ ! "$engine_major" =~ ^[0-9]+$ ]] || ((engine_major < 28)); then
  echo "Docker Engine 28.0.0 or newer is required (detected: ${engine_version:-unavailable})" >&2
  exit 2
fi
docker compose version --short >/dev/null

image_ref="cybersentinel-runtime:${version}"
image_archive="$ROOT/images/cybersentinel-runtime-${version}.tar"
if [[ ! -f "$image_archive" || -L "$image_archive" ]]; then
  echo "release image archive is missing or not a regular file: $image_archive" >&2
  exit 2
fi
if [[ ! -f "$ROOT/SHA256SUMS" ]]; then
  echo "release SHA256SUMS is missing" >&2
  exit 2
fi
sha256sum --check --strict "$ROOT/SHA256SUMS"

if [[ ! -f "$ROOT/.env" ]]; then
  install -m 0600 "$ROOT/.env.example" "$ROOT/.env"
else
  chmod 0600 "$ROOT/.env"
fi

secrets_dir="${CYBERSENTINEL_SECRETS_DIR:-}"
if [[ -z "$secrets_dir" ]]; then
  secrets_dir="$(python3 - "$ROOT/.env" <<'PY'
from pathlib import Path
import sys
value = "./secrets"
for raw in Path(sys.argv[1]).read_text(encoding="utf-8").splitlines():
    line = raw.strip()
    if not line or line.startswith("#") or "=" not in line:
        continue
    key, candidate = line.split("=", 1)
    if key.strip() == "CYBERSENTINEL_SECRETS_DIR":
        value = candidate.strip().strip("'\"")
        break
print(value)
PY
  )"
fi
if [[ -z "$secrets_dir" ]]; then
  echo "CYBERSENTINEL_SECRETS_DIR must not be empty" >&2
  exit 2
fi

export CYBERSENTINEL_VERSION="$version"
export CYBERSENTINEL_IMAGE="$image_ref"
if [[ "$(id -u)" -eq 0 ]]; then
  python3 "$ROOT/scripts/prepare_compose_secrets.py" --directory "$secrets_dir"
else
  command -v sudo >/dev/null 2>&1 || {
    echo "sudo is required to prepare root-owned Compose secret files" >&2
    exit 2
  }
  sudo python3 "$ROOT/scripts/prepare_compose_secrets.py" --directory "$secrets_dir"
fi

compose=(docker compose --project-directory "$ROOT" -f "$ROOT/compose.yaml")
"${compose[@]}" config --quiet
docker load --input "$image_archive"
actual_version="$(docker image inspect --format '{{index .Config.Labels "org.opencontainers.image.version"}}' "$image_ref")"
if [[ "$actual_version" != "$version" ]]; then
  echo "loaded image version label mismatch: expected $version, found $actual_version" >&2
  exit 1
fi

# Owner setup is interactive. Compose's workspace-init dependency runs before it.
"${compose[@]}" run --rm bridge python -m security.owner_password_bootstrap
"${compose[@]}" up --detach --no-build
curl --fail --silent --show-error --max-time 10 http://127.0.0.1:"${BRIDGE_PUBLISHED_PORT:-8787}"/api/health
printf '\nCyberSentinel %s is running on loopback. Verify Owner login before using missions.\n' "$version"
