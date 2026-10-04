from __future__ import annotations

import os
import platform
import shutil
import subprocess
from pathlib import Path
from typing import Any

from .catalog import ModelSpec

GIB = 1024**3


def _physical_memory_bytes() -> int | None:
    if os.name == "nt":
        try:
            import ctypes

            class MemoryStatus(ctypes.Structure):
                _fields_ = [
                    ("dwLength", ctypes.c_ulong),
                    ("dwMemoryLoad", ctypes.c_ulong),
                    ("ullTotalPhys", ctypes.c_ulonglong),
                    ("ullAvailPhys", ctypes.c_ulonglong),
                    ("ullTotalPageFile", ctypes.c_ulonglong),
                    ("ullAvailPageFile", ctypes.c_ulonglong),
                    ("ullTotalVirtual", ctypes.c_ulonglong),
                    ("ullAvailVirtual", ctypes.c_ulonglong),
                    ("ullAvailExtendedVirtual", ctypes.c_ulonglong),
                ]

            status = MemoryStatus()
            status.dwLength = ctypes.sizeof(status)
            if ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(status)):
                return int(status.ullTotalPhys)
        except Exception:
            return None
    try:
        return int(os.sysconf("SC_PHYS_PAGES")) * int(os.sysconf("SC_PAGE_SIZE"))
    except (AttributeError, OSError, ValueError):
        return None


def _nvidia_devices() -> list[dict[str, Any]]:
    executable = shutil.which("nvidia-smi")
    if not executable:
        return []
    try:
        completed = subprocess.run(
            [
                executable,
                "--query-gpu=name,memory.total",
                "--format=csv,noheader,nounits",
            ],
            capture_output=True,
            text=True,
            timeout=2,
            check=False,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        if completed.returncode != 0:
            return []
        result = []
        for line in completed.stdout.splitlines()[:16]:
            name, separator, memory = line.partition(",")
            if not separator:
                continue
            try:
                vram = int(memory.strip()) * 1024**2
            except ValueError:
                vram = 0
            result.append({"name": name.strip()[:160], "vram_bytes": vram})
        return result
    except (OSError, subprocess.TimeoutExpired):
        return []


def detect_hardware(storage_root: str | Path | None = None) -> dict[str, Any]:
    root = Path(storage_root or Path.home()).expanduser()
    root.mkdir(parents=True, exist_ok=True)
    try:
        free_disk = int(shutil.disk_usage(root).free)
    except OSError:
        free_disk = 0
    total_memory = _physical_memory_bytes()
    gpu_devices = _nvidia_devices()
    total_vram = sum(max(0, int(item.get("vram_bytes", 0))) for item in gpu_devices)
    cpu_model = (platform.processor() or platform.machine() or "unknown").strip()[:160]
    return {
        "os": platform.system().lower(),
        "architecture": platform.machine().lower(),
        "cpu_model": cpu_model,
        "cpu_count": max(1, int(os.cpu_count() or 1)),
        "ram_bytes": total_memory,
        "ram_gib": round(total_memory / GIB, 1) if total_memory else None,
        "free_disk_bytes": free_disk,
        "free_disk_gib": round(free_disk / GIB, 1),
        "gpu_devices": gpu_devices,
        "vram_bytes": total_vram,
        "vram_gib": round(total_vram / GIB, 1),
        "vram_detection": "nvidia-smi" if gpu_devices else "not_detected",
        "inference_backend": "llama.cpp CPU runtime",
        "gpu_acceleration_available": False,
    }


def assess_compatibility(spec: ModelSpec, hardware: dict[str, Any]) -> dict[str, Any]:
    reasons: list[str] = []
    warnings: list[str] = []
    ram_bytes = hardware.get("ram_bytes")
    if not isinstance(ram_bytes, int) or ram_bytes < spec.min_ram_gib * GIB:
        reasons.append("insufficient_system_memory")
    elif ram_bytes < spec.recommended_ram_gib * GIB:
        warnings.append("memory_below_recommended")
    free_disk = hardware.get("free_disk_bytes")
    required_disk = spec.size_bytes + GIB
    if not isinstance(free_disk, int) or free_disk < required_disk:
        reasons.append("insufficient_free_disk")
    if hardware.get("os") == "windows" and hardware.get("architecture") not in {"amd64", "x86_64"}:
        reasons.append("unsupported_windows_architecture")
    if hardware.get("os") not in {"windows", "linux"}:
        reasons.append("unsupported_runtime_platform")
    cpu_count = hardware.get("cpu_count")
    if isinstance(cpu_count, int) and not isinstance(cpu_count, bool) and cpu_count < spec.min_cpu_cores:
        warnings.append("cpu_below_recommended")
    vram_bytes = hardware.get("vram_bytes")
    if spec.min_vram_gib and (
        not isinstance(vram_bytes, int) or vram_bytes < spec.min_vram_gib * GIB
    ):
        reasons.append("insufficient_vram")
    if spec.recommended_vram_gib and isinstance(vram_bytes, int) and vram_bytes < spec.recommended_vram_gib * GIB:
        warnings.append("vram_below_recommended")
    compatible = not reasons
    ram_recommended = isinstance(ram_bytes, int) and ram_bytes >= spec.recommended_ram_gib * GIB
    vram_recommended = (
        not spec.recommended_vram_gib
        or isinstance(vram_bytes, int) and vram_bytes >= spec.recommended_vram_gib * GIB
    )
    recommended = compatible and ram_recommended and vram_recommended and not warnings
    return {
        "compatible": compatible,
        "recommended": recommended,
        "too_large": "insufficient_system_memory" in reasons or "insufficient_vram" in reasons,
        "reasons": reasons,
        "warnings": warnings,
        "required_disk_bytes": required_disk,
        "runtime_backend": "llama.cpp CPU runtime",
    }
