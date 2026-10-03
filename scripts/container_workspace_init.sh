#!/bin/sh
set -eu

if [ "$#" -ne 1 ] || [ "$1" != "--once" ]; then
    echo "container_workspace_init requires the --once guard" >&2
    exit 2
fi

state_dir=${CYBERSENTINEL_STATE_DIR:-/var/lib/cybersentinel}
case "$state_dir" in
    /*) ;;
    *) echo "CYBERSENTINEL_STATE_DIR must be an absolute path" >&2; exit 2 ;;
esac

if [ ! -d "$state_dir" ]; then
    echo "persistent state directory is not mounted: $state_dir" >&2
    exit 1
fi

workspace_dir="$state_dir/workspace"
if [ -L "$workspace_dir" ]; then
    echo "refusing symlinked workspace path: $workspace_dir" >&2
    exit 1
fi

# This one-shot service is ordered before either long-running service. It is
# the only first-start creator of the legacy workspace path in the volume.
mkdir -p "$workspace_dir"
state_real=$(cd "$state_dir" && pwd -P)
workspace_real=$(cd "$workspace_dir" && pwd -P)
if [ "$workspace_real" != "$state_real/workspace" ]; then
    echo "workspace path resolves outside the configured state directory" >&2
    exit 1
fi
if [ ! -w "$workspace_dir" ]; then
    echo "workspace path is not writable by the container user" >&2
    exit 1
fi
