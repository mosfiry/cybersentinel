#!/bin/sh
set -eu

if [ "$#" -eq 0 ]; then
    echo "container entrypoint requires an application command" >&2
    exit 2
fi

state_dir=${CYBERSENTINEL_STATE_DIR:-/var/lib/cybersentinel}
workspace_dir="$state_dir/workspace"
if [ -L "$workspace_dir" ] || [ ! -d "$workspace_dir" ]; then
    echo "workspace is missing or symlinked; the workspace-init service must complete first" >&2
    exit 1
fi

state_real=$(cd "$state_dir" && pwd -P)
workspace_real=$(cd "$workspace_dir" && pwd -P)
if [ "$workspace_real" != "$state_real/workspace" ]; then
    echo "workspace path resolves outside the configured state directory" >&2
    exit 1
fi

cd "$workspace_dir"
exec "$@"
