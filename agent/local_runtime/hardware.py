from __future__ import annotations

import csv
import json
import os
import platform
import shutil
import subprocess
from pathlib import Path
from typing import Any

from .catalog import ModelSpec

GIB = 1024**3
_SUPPORTED_ARCHITECTURES = {"amd64", "x86_64"}
_SUPPORTED_PLATFORMS = {"windows", "linux"}
_CPU_FLAGS = {
    "sse2", "sse3", "ssse3", "sse4_1", "sse4_2", "avx", "avx2",
    "avx512f", "fma", "f16c", "neon", "sve",
}
_WINDOWS_PROCESSOR_FEATURES = {
    "sse": 6,       # PF_XMMI_INSTRUCTIONS_AVAILABLE
    "sse2": 10,     # PF_XMMI64_INSTRUCTIONS_AVAILABLE
    "sse3": 13,     # PF_SSE3_INSTRUCTIONS_AVAILABLE
    "avx": 39,      # PF_AVX_INSTRUCTIONS_AVAILABLE
    "avx2": 40,     # PF_AVX2_INSTRUCTIONS_AVAILABLE
    "avx512f": 41,  # PF_AVX512F_INSTRUCTIONS_AVAILABLE
}


def _memory_snapshot() -> tuple[int | None, int | None, str]:
    """Return physical and currently available RAM without changing the host."""
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
                return int(status.ullTotalPhys), int(status.ullAvailPhys), "GlobalMemoryStatusEx"
        except Exception:
            pass
        return None, None, "unavailable"

    total = None
    available = None
    try:
        total = int(os.sysconf("SC_PHYS_PAGES")) * int(os.sysconf("SC_PAGE_SIZE"))
    except (AttributeError, OSError, ValueError, TypeError):
        pass
    if platform.system().lower() == "linux":
        try:
            for line in Path("/proc/meminfo").read_text(encoding="ascii").splitlines():
                if line.startswith("MemAvailable:"):
                    available = int(line.split()[1]) * 1024
                    break
        except (OSError, ValueError, IndexError):
            pass
    if available is None:
        try:
            if hasattr(os, "sysconf"):
                available = int(os.sysconf("SC_AVPHYS_PAGES")) * int(os.sysconf("SC_PAGE_SIZE"))
        except (AttributeError, OSError, ValueError, TypeError):
            pass
    return total, available, "sysconf/procfs" if total is not None or available is not None else "unavailable"


def _physical_memory_bytes() -> int | None:
    return _memory_snapshot()[0]


def _available_memory_bytes() -> int | None:
    return _memory_snapshot()[1]


def _logical_cpu_count() -> int | None:
    try:
        affinity = getattr(os, "sched_getaffinity", None)
        if callable(affinity):
            count = len(affinity(0))
            if count > 0:
                return count
        count = os.cpu_count()
        return int(count) if count and count > 0 else None
    except (OSError, TypeError, ValueError):
        return None


def _windows_physical_core_count() -> int | None:
    """Count RelationProcessorCore records using the Windows kernel API."""
    try:
        import ctypes

        kernel32 = ctypes.windll.kernel32
        query = kernel32.GetLogicalProcessorInformationEx
        query.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.POINTER(ctypes.c_ulong)]
        query.restype = ctypes.c_bool
        required = ctypes.c_ulong(0)
        query(0, None, ctypes.byref(required))
        if not required.value:
            return None
        buffer = (ctypes.c_ubyte * required.value)()
        if not query(0, ctypes.cast(buffer, ctypes.c_void_p), ctypes.byref(required)):
            return None
        offset = 0
        count = 0
        while offset + 8 <= required.value:
            relationship = int.from_bytes(bytes(buffer[offset:offset + 4]), "little")
            size = int.from_bytes(bytes(buffer[offset + 4:offset + 8]), "little")
            if size < 8 or offset + size > required.value:
                return None
            if relationship == 0:  # RelationProcessorCore
                count += 1
            offset += size
        return count or None
    except Exception:
        return None


def _linux_physical_core_count() -> int | None:
    cpu_root = Path("/sys/devices/system/cpu")
    pairs: set[tuple[str, str]] = set()
    try:
        for cpu_dir in cpu_root.glob("cpu[0-9]*"):
            topology = cpu_dir / "topology"
            core = (topology / "core_id").read_text(encoding="ascii").strip()
            package = (topology / "physical_package_id").read_text(encoding="ascii").strip()
            pairs.add((package, core))
    except (OSError, ValueError):
        return None
    return len(pairs) or None


def _physical_core_count() -> int | None:
    system = platform.system().lower()
    if system == "windows":
        return _windows_physical_core_count()
    if system == "linux":
        return _linux_physical_core_count()
    return None


def _cpu_model() -> str:
    system = platform.system().lower()
    if system == "linux":
        try:
            for line in Path("/proc/cpuinfo").read_text(encoding="ascii", errors="ignore").splitlines():
                key, separator, value = line.partition(":")
                if separator and key.strip().lower() in {"model name", "hardware"} and value.strip():
                    return value.strip()[:160]
        except OSError:
            pass
    if system == "windows" or os.name == "nt":
        try:
            import winreg

            with winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                r"HARDWARE\DESCRIPTION\System\CentralProcessor\0",
            ) as key:
                value, _kind = winreg.QueryValueEx(key, "ProcessorNameString")
                if isinstance(value, str) and value.strip():
                    return value.strip()[:160]
        except (ImportError, OSError):
            pass
    value = (platform.processor() or "").strip()
    if value and value.lower() not in {"amd64", "x86_64", "arm64", "aarch64"}:
        return value[:160]
    fallback = getattr(platform.uname(), "processor", "") or platform.machine() or "unknown"
    return str(fallback).strip()[:160] or "unknown"


def _cpu_instruction_sets() -> tuple[list[str], str]:
    system = platform.system().lower()
    if system == "windows":
        try:
            import ctypes

            check = ctypes.windll.kernel32.IsProcessorFeaturePresent
            check.argtypes = [ctypes.c_uint]
            check.restype = ctypes.c_bool
            return sorted(name for name, feature in _WINDOWS_PROCESSOR_FEATURES.items() if check(feature)), "IsProcessorFeaturePresent"
        except Exception:
            return [], "unavailable"
    if system == "linux":
        try:
            for line in Path("/proc/cpuinfo").read_text(encoding="ascii", errors="ignore").splitlines():
                key, separator, value = line.partition(":")
                if separator and key.strip().lower() in {"flags", "features"}:
                    flags = {item.lower() for item in value.split()}
                    return sorted(flags & _CPU_FLAGS), "/proc/cpuinfo"
        except OSError:
            pass
    return [], "unavailable"


def _nvidia_devices() -> tuple[list[dict[str, Any]], str]:
    executable = shutil.which("nvidia-smi")
    if not executable:
        return [], "discovery_tool_not_available"
    try:
        completed = subprocess.run(
            [
                executable,
                "--query-gpu=name,memory.total,memory.free,driver_version,compute_cap",
                "--format=csv,noheader,nounits",
            ],
            capture_output=True,
            text=True,
            timeout=3,
            check=False,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        if completed.returncode != 0:
            return [], "nvidia_smi_failed"
        rows = csv.reader(completed.stdout.splitlines(), skipinitialspace=True)
        devices: list[dict[str, Any]] = []
        for row in rows:
            if len(row) < 5:
                continue
            try:
                total = int(row[1]) * 1024**2
            except (TypeError, ValueError):
                total = None
            try:
                free = int(row[2]) * 1024**2
            except (TypeError, ValueError):
                free = None
            devices.append({
                "name": row[0].strip()[:160] or "NVIDIA GPU",
                "vram_bytes": total,
                "free_vram_bytes": free,
                "shared_memory_bytes": None,
                "driver_version": row[3].strip()[:80] or None,
                "compute_capability": row[4].strip()[:40] or None,
                "memory_source": "nvidia-smi",
                "backend_supported": False,
            })
        if devices:
            return devices[:16], "nvidia-smi"
        return [], "nvidia_smi_no_devices"
    except (OSError, subprocess.TimeoutExpired):
        return [], "nvidia_smi_failed"


def _windows_video_controllers() -> list[dict[str, Any]]:
    """Best-effort WMI names/driver only; WMI AdapterRAM is intentionally not trusted."""
    executable = shutil.which("powershell.exe") or shutil.which("powershell") or shutil.which("pwsh")
    if not executable:
        return []
    script = (
        "$ProgressPreference='SilentlyContinue'; "
        "Get-CimInstance -ClassName Win32_VideoController | "
        "Select-Object -Property Name,DriverVersion | ConvertTo-Json -Compress"
    )
    try:
        completed = subprocess.run(
            [executable, "-NoProfile", "-NonInteractive", "-Command", script],
            capture_output=True,
            text=True,
            timeout=3,
            check=False,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        if completed.returncode != 0 or not completed.stdout.strip():
            return []
        payload = json.loads(completed.stdout)
        rows = payload if isinstance(payload, list) else [payload]
        result = []
        for item in rows[:16]:
            if not isinstance(item, dict):
                continue
            name = item.get("Name")
            if isinstance(name, str) and name.strip():
                driver = item.get("DriverVersion")
                result.append({
                    "name": name.strip()[:160],
                    "vram_bytes": None,
                    "free_vram_bytes": None,
                    "shared_memory_bytes": None,
                    "driver_version": str(driver)[:80] if driver else None,
                    "compute_capability": None,
                    "memory_source": None,
                    "backend_supported": False,
                })
        return result
    except (OSError, subprocess.TimeoutExpired, json.JSONDecodeError, TypeError):
        return []


def _gpu_inventory() -> tuple[list[dict[str, Any]], str]:
    devices, status = _nvidia_devices()
    if devices or platform.system().lower() != "windows":
        return devices, status
    windows_devices = _windows_video_controllers()
    if windows_devices:
        return windows_devices, "windows_wmi_model_driver_only"
    if status == "discovery_tool_not_available":
        return [], "not_detected_or_unavailable"
    return [], status


def _storage_probe_path(storage_root: str | Path | None) -> Path:
    candidate = Path(storage_root or Path.home()).expanduser()
    while not candidate.exists() and candidate != candidate.parent:
        candidate = candidate.parent
    return candidate if candidate.exists() else Path.cwd()


def _safe_memory_budget(total: int | None, available: int | None) -> tuple[int | None, int | None]:
    if total is None or total <= 0:
        return None, None
    observed_available = min(total, available) if isinstance(available, int) and available >= 0 else total
    reserve = max(2 * GIB, int(total * 0.10))
    return max(0, observed_available - reserve), reserve


def detect_hardware(storage_root: str | Path | None = None) -> dict[str, Any]:
    """Read-only best-effort inventory; unknown measurements remain ``None``."""
    root = Path(storage_root or Path.home()).expanduser()
    probe_path = _storage_probe_path(root)
    try:
        free_disk: int | None = int(shutil.disk_usage(probe_path).free)
        disk_status = "measured"
    except (OSError, ValueError):
        free_disk = None
        disk_status = "unavailable"

    total_memory, available_memory, memory_source = _memory_snapshot()
    budget, reserve = _safe_memory_budget(total_memory, available_memory)
    logical = _logical_cpu_count()
    physical = _physical_core_count()
    gpu_devices, gpu_status = _gpu_inventory()
    known_vram = [item.get("vram_bytes") for item in gpu_devices if isinstance(item.get("vram_bytes"), int) and item.get("vram_bytes") >= 0]
    total_vram = sum(known_vram) if known_vram else None
    cpu_model = _cpu_model()
    architecture = platform.machine().lower() or "unknown"
    system = platform.system().lower() or "unknown"
    supported_platform = system in _SUPPORTED_PLATFORMS and architecture in _SUPPORTED_ARCHITECTURES
    cpu_features, cpu_feature_source = _cpu_instruction_sets()
    return {
        "os": system,
        "architecture": architecture,
        "cpu_model": cpu_model,
        "cpu_count": logical,
        "logical_cpu_count": logical,
        "physical_core_count": physical,
        "cpu_instruction_sets": cpu_features,
        "cpu_feature_source": cpu_feature_source,
        "cpu_detection_status": "measured" if cpu_model != "unknown" or logical is not None else "unavailable",
        "ram_bytes": total_memory,
        "ram_gib": round(total_memory / GIB, 1) if total_memory is not None else None,
        "available_ram_bytes": available_memory,
        "available_ram_gib": round(available_memory / GIB, 1) if available_memory is not None else None,
        "memory_source": memory_source,
        "inference_memory_budget_bytes": budget,
        "inference_memory_budget_gib": round(budget / GIB, 1) if budget is not None else None,
        "memory_safety_reserve_bytes": reserve,
        "free_disk_bytes": free_disk,
        "free_disk_gib": round(free_disk / GIB, 1) if free_disk is not None else None,
        "disk_detection_status": disk_status,
        "storage_root": str(root),
        "storage_volume_probe": str(probe_path),
        "gpu_devices": gpu_devices,
        "vram_bytes": total_vram,
        "vram_gib": round(total_vram / GIB, 1) if total_vram is not None else None,
        "shared_gpu_memory_bytes": None,
        "shared_gpu_memory_status": "not_available_from_verified_discovery_source",
        "vram_detection": gpu_status,
        "gpu_detection_status": gpu_status,
        "inference_backend": "llama.cpp CPU runtime",
        "supported_model_formats": ["GGUF"],
        "supported_backends": ["llama.cpp-cpu"] if supported_platform else [],
        "runtime_platform_supported": supported_platform,
        "gpu_acceleration_available": False,
        "hardware_facts_are_benchmarks": False,
    }


def assess_compatibility(spec: ModelSpec, hardware: dict[str, Any]) -> dict[str, Any]:
    reasons: list[str] = []
    warnings: list[str] = []
    if "inference_memory_budget_bytes" in hardware:
        ram_bytes = hardware.get("inference_memory_budget_bytes")
    else:  # compatibility for older/test hardware payloads
        ram_bytes = hardware.get("ram_bytes")
    valid_ram = isinstance(ram_bytes, int) and not isinstance(ram_bytes, bool) and ram_bytes >= 0
    if not valid_ram:
        reasons.append("system_memory_unavailable")
    elif ram_bytes < spec.min_ram_gib * GIB:
        reasons.append("insufficient_system_memory")
    elif ram_bytes < spec.recommended_ram_gib * GIB:
        warnings.append("memory_below_recommended")

    free_disk = hardware.get("free_disk_bytes")
    required_disk = spec.size_bytes + GIB
    if not isinstance(free_disk, int) or isinstance(free_disk, bool):
        reasons.append("disk_space_unavailable")
    elif free_disk < required_disk:
        reasons.append("insufficient_free_disk")

    system = str(hardware.get("os") or "").lower()
    architecture = str(hardware.get("architecture") or "").lower()
    if system not in _SUPPORTED_PLATFORMS:
        reasons.append("unsupported_runtime_platform")
    elif architecture not in _SUPPORTED_ARCHITECTURES:
        reasons.append("unsupported_runtime_architecture")
    if hardware.get("runtime_platform_supported") is False and "unsupported_runtime_architecture" not in reasons and "unsupported_runtime_platform" not in reasons:
        reasons.append("unsupported_runtime_platform")

    supported_backends = hardware.get("supported_backends")
    if isinstance(supported_backends, list) and supported_backends and not any(
        item in supported_backends for item in spec.backend_compatibility
    ):
        reasons.append("unsupported_runtime_backend")

    cpu_count = hardware.get("logical_cpu_count", hardware.get("cpu_count"))
    if isinstance(cpu_count, int) and not isinstance(cpu_count, bool) and cpu_count < spec.min_cpu_cores:
        warnings.append("cpu_below_recommended")
    elif cpu_count is None:
        warnings.append("cpu_count_unavailable")

    vram_bytes = hardware.get("vram_bytes")
    if spec.min_vram_gib and (
        not isinstance(vram_bytes, int) or isinstance(vram_bytes, bool) or vram_bytes < spec.min_vram_gib * GIB
    ):
        reasons.append("insufficient_vram")
    if spec.recommended_vram_gib and isinstance(vram_bytes, int) and not isinstance(vram_bytes, bool) and vram_bytes < spec.recommended_vram_gib * GIB:
        warnings.append("vram_below_recommended")

    compatible = not reasons
    ram_recommended = valid_ram and ram_bytes >= spec.recommended_ram_gib * GIB
    vram_recommended = (
        not spec.recommended_vram_gib
        or isinstance(vram_bytes, int) and not isinstance(vram_bytes, bool) and vram_bytes >= spec.recommended_vram_gib * GIB
    )
    recommended = compatible and ram_recommended and vram_recommended and not warnings
    return {
        "compatible": compatible,
        "recommended": recommended,
        "too_large": "insufficient_system_memory" in reasons or "insufficient_vram" in reasons,
        "reasons": reasons,
        "warnings": warnings,
        "required_disk_bytes": required_disk,
        "assessed_memory_bytes": ram_bytes if valid_ram else None,
        "estimated_minimum_memory_bytes": spec.min_ram_gib * GIB,
        "estimated_recommended_memory_bytes": spec.recommended_ram_gib * GIB,
        "memory_estimates_are_benchmarks": False,
        "runtime_backend": "llama.cpp CPU runtime",
    }
