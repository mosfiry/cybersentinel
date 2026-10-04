#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
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

backup_dir="${1:-$ROOT/backups}"
if [[ "$backup_dir" != /* ]]; then
  backup_dir="$ROOT/$backup_dir"
fi
mkdir -p -- "$backup_dir"
chmod 0700 -- "$backup_dir"
archive="$backup_dir/cybersentinel-state-$(date -u +%Y%m%dT%H%M%SZ)-$$.tar.gz"
checksum="$archive.sha256"
if [[ -e "$archive" || -L "$archive" || -e "$checksum" || -L "$checksum" ]]; then
  echo "refusing to overwrite an existing backup path" >&2
  exit 2
fi
umask 077
temporary="$(mktemp "$backup_dir/.cybersentinel-state.XXXXXX")"
checksum_temporary=""
running_services="$("${compose[@]}" ps --status running --services)"
resume_services=()
for service in bridge mission-worker; do
  if grep -Fxq "$service" <<<"$running_services"; then
    resume_services+=("$service")
  fi
done

restore_service_state() {
  status=$?
  rm -f -- "$temporary"
  if [[ -n "$checksum_temporary" ]]; then
    rm -f -- "$checksum_temporary"
  fi
  if ((${#resume_services[@]})); then
    "${compose[@]}" start "${resume_services[@]}" >/dev/null || status=1
  fi
  exit "$status"
}
trap restore_service_state EXIT

"${compose[@]}" stop bridge mission-worker
"${compose[@]}" run --rm --no-deps -T --entrypoint python workspace-init \
  /app/scripts/state_archive.py backup > "$temporary"
"${compose[@]}" run --rm --no-deps -T --entrypoint python workspace-init \
  /app/scripts/state_archive.py verify < "$temporary"
chmod 0600 "$temporary"
mv -- "$temporary" "$archive"
checksum_temporary="$(mktemp "$backup_dir/.cybersentinel-checksum.XXXXXX")"
(cd "$backup_dir" && sha256sum "$(basename -- "$archive")") > "$checksum_temporary"
chmod 0600 "$checksum_temporary"
mv -- "$checksum_temporary" "$checksum"
checksum_temporary=""

if ((${#resume_services[@]})); then
  "${compose[@]}" start "${resume_services[@]}"
fi
trap - EXIT
printf 'Verified state backup: %s\n' "$archive"
printf 'Checksum: %s\n' "$(cut -d' ' -f1 "$checksum")"
