#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
if [[ "$#" -ne 2 ]]; then
  echo "usage: $0 BACKUP_ARCHIVE.tar.gz UNIQUE_RESTORE_PROJECT" >&2
  exit 2
fi
archive_input="$1"
restore_project="$2"
if [[ -L "$archive_input" || ! -f "$archive_input" ]]; then
  echo "backup must be a regular, non-symlink file" >&2
  exit 2
fi
command -v realpath >/dev/null 2>&1 || { echo "realpath is required" >&2; exit 2; }
archive="$(realpath -e -- "$archive_input")"
if [[ ! "$restore_project" =~ ^[a-z0-9][a-z0-9_-]{0,62}$ ]]; then
  echo "restore project must be 1-63 lowercase letters, digits, '-' or '_'" >&2
  exit 2
fi

version="$(tr -d '\r\n' < "$ROOT/VERSION")"
image_ref="cybersentinel-runtime:${version}"
export CYBERSENTINEL_VERSION="$version"
export CYBERSENTINEL_IMAGE="$image_ref"
compose=(docker compose --project-directory "$ROOT" -f "$ROOT/compose.yaml")
if [[ ! -f "$ROOT/.env" ]]; then
  echo "missing .env; install/configure the Compose bundle first" >&2
  exit 2
fi
command -v docker >/dev/null 2>&1 || { echo "docker is required" >&2; exit 2; }
command -v sha256sum >/dev/null 2>&1 || { echo "sha256sum is required" >&2; exit 2; }
"${compose[@]}" config --quiet
current_project="$("${compose[@]}" config --format json | python3 -c 'import json,sys; print(json.load(sys.stdin)["name"])')"
if [[ "$restore_project" == "$current_project" ]]; then
  echo "refusing to restore into the active Compose project" >&2
  exit 2
fi

checksum="${archive}.sha256"
if [[ ! -f "$checksum" || -L "$checksum" ]]; then
  echo "required backup checksum sidecar is missing or unsafe: $checksum" >&2
  exit 2
fi
(cd "$(dirname -- "$archive")" && sha256sum --check --strict "$(basename -- "$checksum")")
volume="${restore_project}_cybersentinel-state"
if docker volume inspect "$volume" >/dev/null 2>&1; then
  echo "refusing to use an existing restore volume: $volume" >&2
  exit 2
fi

docker image inspect "$image_ref" >/dev/null 2>&1 || {
  echo "release image is not loaded: $image_ref (run install_compose.sh first)" >&2
  exit 2
}
restore_compose=(docker compose -p "$restore_project" --project-directory "$ROOT" -f "$ROOT/compose.yaml")
"${restore_compose[@]}" run --rm --no-deps -T --entrypoint python workspace-init \
  /app/scripts/state_archive.py verify < "$archive"
"${restore_compose[@]}" run --rm --no-deps -T --entrypoint python workspace-init \
  /app/scripts/state_archive.py restore < "$archive"
printf 'Verified state restored into new volume %s; the original project was not changed.\n' "$volume"
printf 'After reviewing .env/secrets and choosing an unused loopback port, start with:\n'
printf '  BRIDGE_PUBLISHED_PORT=18789 docker compose -p %q --project-directory %q -f %q up -d bridge mission-worker\n' \
  "$restore_project" "$ROOT" "$ROOT/compose.yaml"
