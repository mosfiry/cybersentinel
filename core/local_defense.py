from __future__ import annotations

import json
import os
import platform
import socket
import sys
from pathlib import Path
from typing import Any

from .db import add_event


def _has_android_runtime_marker() -> bool:
    """Detect Android itself; Termux-specific environment variables alone are insufficient."""
    release = platform.release().casefold()
    return bool(
        sys.platform.casefold() == "android"
        or callable(getattr(sys, "getandroidapilevel", None))
        or "android" in release
        or Path("/system/build.prop").is_file()
        or Path("/system/bin/getprop").is_file()
    )


def _runtime_identity() -> dict[str, str | None]:
    system_name = platform.system() or "Unknown"
    normalized_system = system_name.casefold()
    android = _has_android_runtime_marker()
    prefix = os.environ.get("PREFIX", "").casefold()
    termux_prefixes = (
        "/data/data/com.termux/files/usr",
        "/data/user/0/com.termux/files/usr",
    )
    is_termux = android and bool(
        os.environ.get("TERMUX_VERSION")
        or os.environ.get("TERMUX_APP_PID")
        or prefix.startswith(termux_prefixes)
    )

    distribution: str | None = None
    if is_termux:
        environment = "Termux"
    elif android:
        environment = "Android"
    elif normalized_system == "linux":
        try:
            release = platform.freedesktop_os_release()
        except (AttributeError, OSError, ValueError):
            release = {}
        distribution = str(release.get("PRETTY_NAME") or release.get("NAME") or "").strip() or None
        environment = distribution or system_name
    elif normalized_system == "darwin":
        environment = "macOS"
    else:
        environment = system_name

    return {
        "platform": system_name,
        "environment": environment,
        "distribution": distribution,
    }


def _current_uid() -> int | None:
    getuid = getattr(os, "getuid", None)
    return int(getuid()) if callable(getuid) else None


def _tcp_listeners() -> list[dict[str, Any]] | None:
    """Return listeners from Linux procfs, or None when this source is unavailable."""
    path = Path("/proc/net/tcp")
    if not path.is_file():
        return None
    out: list[dict[str, Any]] = []
    for row in path.read_text(errors="replace").splitlines()[1:]:
        parts = row.split()
        if len(parts) < 4 or parts[3] != "0A":
            continue
        try:
            ip_hex, port_hex = parts[1].split(":")
            ip = socket.inet_ntoa(bytes.fromhex(ip_hex)[::-1])
            port = int(port_hex, 16)
            out.append({"protocol": "tcp", "ip": ip, "port": port})
        except Exception:
            continue
    return out


def local_security_check() -> dict[str, Any]:
    listeners = _tcp_listeners()
    findings = []
    for item in listeners or ():
        scope = "loopback" if item["ip"] == "127.0.0.1" else "non-loopback"
        findings.append({**item, "scope": scope})
    supported = listeners is not None
    identity = _runtime_identity()
    result: dict[str, Any] = {
        **identity,
        "device_scope": "this host only",
        "uid": _current_uid(),
        "listener_scan_status": "completed" if supported else "unsupported",
        "listener_scan_supported": supported,
        "tcp_listener_source": "/proc/net/tcp",
        "tcp_listeners": findings,
        "count": len(findings) if supported else None,
    }
    severity = "warning" if not supported or any(item["scope"] == "non-loopback" for item in findings) else "info"
    add_event(
        "local_check",
        "Local TCP listener check",
        json.dumps(result, ensure_ascii=False),
        "local:/proc/net/tcp",
        severity,
        True,
        result,
    )
    return result


def local_system_info() -> dict[str, Any]:
    identity = _runtime_identity()
    info: dict[str, Any] = {
        **identity,
        "kernel": platform.release() or "unknown",
        "machine": platform.machine() or "unknown",
        "python": sys.version.split()[0],
        "cwd": os.getcwd(),
        "uid": _current_uid(),
    }
    add_event(
        "local_check",
        "Local system information",
        json.dumps(info, ensure_ascii=False),
        "local:runtime",
        "info",
        True,
        info,
    )
    return info
