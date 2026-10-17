"""Fixed-size, broker-only Windows VHD workspace primitive.

This module is deliberately not wired to MissionRuntime or process launch. A
trusted privileged broker is a prerequisite; this is not an agent-callable
mount API. The configured root must be a pre-existing local NTFS directory
whose ACL excludes untrusted users. ACL isolation and protection from hostile
concurrent actors are deployment responsibilities and are not established here.

Only fixed VHD is implemented (rather than VHDX): it is supported directly by
Windows' Virtual Disk API and FULL_PHYSICAL_ALLOCATION gives an explicit
up-front host allocation bound. Paths are generated internally and passed to
PowerShell only as structured JSON on stdin; its script is a module constant.
"""
from __future__ import annotations

import base64
import ctypes
import json
import os
import subprocess
import uuid
from pathlib import Path
from typing import Any

MIN_CAPACITY_BYTES = 64 * 1024 * 1024
MAX_CAPACITY_BYTES = 4 * 1024 * 1024 * 1024
_CAPACITY_ALIGNMENT = 1024 * 1024

# These scripts are intentionally static. No input is interpolated into script
# text or argv; paths and scalar values are supplied through JSON stdin.
_FORMAT_SCRIPT = r'''
$ErrorActionPreference = 'Stop'
$phase = 'image_lookup'
try {
  $r = [Console]::In.ReadToEnd() | ConvertFrom-Json
  $image = Get-DiskImage -ImagePath ([string]$r.image_path) -ErrorAction Stop
  if (@($image).Count -ne 1 -or -not $image.Attached -or
      [string]$image.DevicePath -ine [string]$r.disk_path) { throw 'IMAGE_IDENTITY' }
  $phase = 'disk_association'
  $d = $image | Get-Disk -ErrorAction Stop
  if (@($d).Count -ne 1) { throw 'DISK_IDENTITY' }
  $d = @($d)[0]
  if ($d.Number -ne [uint32]$r.disk_number -or
      [uint64]$d.Size -ne [uint64]$r.capacity_bytes -or
      [string]$d.BusType -notin @('File Backed Virtual', 'FileBackedVirtual') -or
      [bool]$d.IsSystem -or [bool]$d.IsBoot -or
      [string]$d.PartitionStyle -ne 'RAW' -or
      [bool]$d.IsOffline -or [bool]$d.IsReadOnly) { throw 'DISK_IDENTITY' }
  $phase = 'initialize'
  $disk = Initialize-Disk -InputObject $d -PartitionStyle GPT -PassThru -ErrorAction Stop
  $phase = 'partition'
  $p = New-Partition -InputObject $disk -UseMaximumSize -AssignDriveLetter:$false -ErrorAction Stop
  $phase = 'partition_flags'
  Set-Partition -InputObject $p -NoDefaultDriveLetter $true -ErrorAction Stop | Out-Null
  $phase = 'format'
  $v = Format-Volume -Partition $p -FileSystem NTFS -NewFileSystemLabel 'CSWS' -AllocationUnitSize 4096 -Confirm:$false -Force -ErrorAction Stop
  $phase = 'mount'
  Add-PartitionAccessPath -InputObject $p -AccessPath ([string]$r.mount_path) -ErrorAction Stop | Out-Null
  $phase = 'mount_verify'
  $p2 = @(Get-Partition -Disk $disk -ErrorAction Stop | Where-Object { $_.ObjectId -eq $p.ObjectId })
  if ($p2.Count -ne 1 -or -not (@($p2[0].AccessPaths) -contains [string]$r.mount_path)) { throw 'MOUNT_VERIFY' }
  if ([string]$v.FileSystem -ne 'NTFS') { throw 'FORMAT_VERIFY' }
  @{ok=$true} | ConvertTo-Json -Compress
  exit 0
} catch {
  @{ok=$false;code=$phase} | ConvertTo-Json -Compress
  exit 1
}
'''

_UNMOUNT_SCRIPT = r'''
$ErrorActionPreference = 'Stop'
$phase = 'image_lookup'
try {
  $r = [Console]::In.ReadToEnd() | ConvertFrom-Json
  $image = Get-DiskImage -ImagePath ([string]$r.image_path) -ErrorAction Stop
  if (@($image).Count -ne 1 -or -not $image.Attached -or
      [string]$image.DevicePath -ine [string]$r.disk_path) { throw 'IMAGE_IDENTITY' }
  $phase = 'disk_association'
  $d = $image | Get-Disk -ErrorAction Stop
  if (@($d).Count -ne 1) { throw 'DISK_IDENTITY' }
  $d = @($d)[0]
  if ($d.Number -ne [uint32]$r.disk_number -or
      [uint64]$d.Size -ne [uint64]$r.capacity_bytes -or
      [string]$d.BusType -notin @('File Backed Virtual', 'FileBackedVirtual') -or
      [bool]$d.IsSystem -or [bool]$d.IsBoot) { throw 'DISK_IDENTITY' }
  if ([uint32]$d.NumberOfPartitions -eq 0) {
    @{ok=$true} | ConvertTo-Json -Compress
    exit 0
  }
  $phase = 'unmount_lookup'
  $p = @(Get-Partition -Disk $d -ErrorAction Stop | Where-Object { @($_.AccessPaths) -contains [string]$r.mount_path })
  if ($p.Count -gt 1) { throw 'MOUNT_IDENTITY' }
  if ($p.Count -eq 1) {
    $phase = 'unmount'
    Remove-PartitionAccessPath -InputObject $p[0] -AccessPath ([string]$r.mount_path) -ErrorAction Stop | Out-Null
  }
  $phase = 'unmount_verify'
  $left = @(Get-Partition -Disk $d -ErrorAction Stop | Where-Object { @($_.AccessPaths) -contains [string]$r.mount_path })
  if ($left.Count -ne 0) { throw 'MOUNT_VERIFY' }
  @{ok=$true} | ConvertTo-Json -Compress
  exit 0
} catch {
  @{ok=$false;code=$phase} | ConvertTo-Json -Compress
  exit 1
}
'''


class VhdWorkspaceError(RuntimeError):
    """Sanitized lifecycle error; cleanup_required means cleanup is unconfirmed."""

    def __init__(self, code: str, *, cleanup_required: bool = False, system_error: int | None = None) -> None:
        self.code = code
        self.cleanup_required = cleanup_required
        self.system_error = system_error
        self.workspace: WindowsVhdWorkspace | None = None
        suffix = "" if system_error is None else f"; system_error={system_error}"
        super().__init__(f"Windows VHD workspace operation failed ({code}); cleanup_required={cleanup_required}{suffix}")


class _Guid(ctypes.Structure):
    _fields_ = [("Data1", ctypes.c_uint32), ("Data2", ctypes.c_uint16), ("Data3", ctypes.c_uint16), ("Data4", ctypes.c_ubyte * 8)]


class _StorageType(ctypes.Structure):
    _fields_ = [("DeviceId", ctypes.c_uint32), ("VendorId", _Guid)]


class _CreateV1(ctypes.Structure):
    _fields_ = [
        ("UniqueId", _Guid), ("MaximumSize", ctypes.c_uint64),
        ("BlockSizeInBytes", ctypes.c_uint32), ("SectorSizeInBytes", ctypes.c_uint32),
        ("ParentPath", ctypes.c_wchar_p), ("SourcePath", ctypes.c_wchar_p),
    ]


class _CreateUnion(ctypes.Union):
    _fields_ = [("Version1", _CreateV1)]


class _CreateParams(ctypes.Structure):
    _fields_ = [("Version", ctypes.c_uint32), ("_padding", ctypes.c_uint32), ("u", _CreateUnion)]


class _NativeVhd:
    """Small private ctypes seam: replaceable by unit tests, not a public backend API."""

    _ERROR_SUCCESS = 0
    _ERROR_INSUFFICIENT_BUFFER = 122
    _VIRTUAL_DISK_ACCESS_ATTACH_RW = 0x00020000
    _VIRTUAL_DISK_ACCESS_DETACH = 0x00040000
    _VIRTUAL_DISK_ACCESS_GET_INFO = 0x00080000
    _VIRTUAL_DISK_ACCESS_CREATE = 0x00100000
    _CREATE_FULL_PHYSICAL_ALLOCATION = 0x00000001
    _ATTACH_NO_DRIVE_LETTER = 0x00000002
    _GET_INFO_SIZE = 1
    _GET_INFO_IS_LOADED = 13
    _VHD_DEVICE_ID = 2

    GUID = _Guid
    _StorageType = _StorageType
    _CreateParams = _CreateParams

    def __init__(self) -> None:
        if os.name != "nt":
            raise VhdWorkspaceError("windows_only")
        if ctypes.sizeof(ctypes.c_void_p) != 8:
            raise VhdWorkspaceError("requires_64bit_broker")
        self._dll = ctypes.WinDLL("virtdisk.dll", use_last_error=True)
        self._kernel = ctypes.WinDLL("kernel32.dll", use_last_error=True)
        self._configure()

    def _configure(self) -> None:
        h = ctypes.c_void_p
        u32 = ctypes.c_uint32
        wstr = ctypes.c_wchar_p
        self._dll.CreateVirtualDisk.argtypes = [ctypes.POINTER(self._StorageType), wstr, u32, ctypes.c_void_p, u32, u32, ctypes.POINTER(self._CreateParams), ctypes.c_void_p, ctypes.POINTER(h)]
        self._dll.CreateVirtualDisk.restype = u32
        self._dll.AttachVirtualDisk.argtypes = [h, ctypes.c_void_p, u32, u32, ctypes.c_void_p, ctypes.c_void_p]
        self._dll.AttachVirtualDisk.restype = u32
        self._dll.DetachVirtualDisk.argtypes = [h, u32, u32]
        self._dll.DetachVirtualDisk.restype = u32
        self._dll.GetVirtualDiskPhysicalPath.argtypes = [h, ctypes.POINTER(u32), ctypes.c_wchar_p]
        self._dll.GetVirtualDiskPhysicalPath.restype = u32
        self._dll.GetVirtualDiskInformation.argtypes = [h, ctypes.POINTER(u32), ctypes.c_void_p, ctypes.POINTER(u32)]
        self._dll.GetVirtualDiskInformation.restype = u32
        self._kernel.CloseHandle.argtypes = [h]
        self._kernel.CloseHandle.restype = ctypes.c_int

    @classmethod
    def _guid(cls, data: bytes) -> "_NativeVhd.GUID":
        return cls.GUID.from_buffer_copy(data)

    @classmethod
    def _storage_type(cls) -> "_NativeVhd._StorageType":
        # Microsoft Virtual Disk vendor ID: EC984AEC-A0F9-47E9-901F-71415A66345B.
        vendor = cls._guid(uuid.UUID("ec984aec-a0f9-47e9-901f-71415a66345b").bytes_le)
        return cls._StorageType(cls._VHD_DEVICE_ID, vendor)

    def _check(self, status: int, op: str) -> None:
        if status != self._ERROR_SUCCESS:
            # A numeric Win32 result is useful evidence, unlike raw error text/paths.
            raise VhdWorkspaceError(op, system_error=int(status))

    def create(self, path: Path, capacity: int) -> Any:
        params = self._CreateParams()
        params.Version = 1  # CREATE_VIRTUAL_DISK_VERSION_1
        params.u.Version1.UniqueId = self._guid(uuid.uuid4().bytes_le)
        params.u.Version1.MaximumSize = capacity
        params.u.Version1.BlockSizeInBytes = 0
        params.u.Version1.SectorSizeInBytes = 512
        params.u.Version1.ParentPath = None
        params.u.Version1.SourcePath = None
        handle = ctypes.c_void_p()
        access = self._VIRTUAL_DISK_ACCESS_CREATE | self._VIRTUAL_DISK_ACCESS_ATTACH_RW | self._VIRTUAL_DISK_ACCESS_DETACH | self._VIRTUAL_DISK_ACCESS_GET_INFO
        status = self._dll.CreateVirtualDisk(ctypes.byref(self._storage_type()), str(path), access, None, self._CREATE_FULL_PHYSICAL_ALLOCATION, 0, ctypes.byref(params), None, ctypes.byref(handle))
        if status != self._ERROR_SUCCESS:
            raise VhdWorkspaceError("create_failed", system_error=int(status))
        return handle

    def attach(self, handle: Any) -> None:
        self._check(self._dll.AttachVirtualDisk(handle, None, self._ATTACH_NO_DRIVE_LETTER, 0, None, None), "attach_failed")

    def physical_path(self, handle: Any) -> str:
        size = ctypes.c_uint32(0)
        status = self._dll.GetVirtualDiskPhysicalPath(handle, ctypes.byref(size), None)
        if status != self._ERROR_INSUFFICIENT_BUFFER or size.value < 4 or size.value > 65536:
            raise VhdWorkspaceError("physical_identity_failed")
        buf = ctypes.create_unicode_buffer(size.value // ctypes.sizeof(ctypes.c_wchar))
        self._check(self._dll.GetVirtualDiskPhysicalPath(handle, ctypes.byref(size), buf), "physical_identity_failed")
        path = buf.value
        if not path.startswith("\\\\.\\PhysicalDrive") or not path[len("\\\\.\\PhysicalDrive"):].isdigit():
            raise VhdWorkspaceError("physical_identity_failed")
        return path

    def verify_capacity(self, handle: Any, capacity: int) -> None:
        buf = ctypes.create_string_buffer(64)
        ctypes.cast(buf, ctypes.POINTER(ctypes.c_uint32))[0] = self._GET_INFO_SIZE
        size = ctypes.c_uint32(len(buf))
        version = ctypes.c_uint32(self._GET_INFO_SIZE)
        self._check(self._dll.GetVirtualDiskInformation(handle, ctypes.byref(size), buf, ctypes.byref(version)), "virtual_disk_info_failed")
        virtual_size = ctypes.cast(ctypes.byref(buf, 8), ctypes.POINTER(ctypes.c_uint64))[0]
        if virtual_size != capacity:
            raise VhdWorkspaceError("capacity_mismatch")

    def is_loaded(self, handle: Any) -> bool:
        buf = ctypes.create_string_buffer(64)
        ctypes.cast(buf, ctypes.POINTER(ctypes.c_uint32))[0] = self._GET_INFO_IS_LOADED
        size = ctypes.c_uint32(len(buf))
        version = ctypes.c_uint32(self._GET_INFO_IS_LOADED)
        self._check(self._dll.GetVirtualDiskInformation(handle, ctypes.byref(size), buf, ctypes.byref(version)), "detach_verify_failed")
        loaded = ctypes.cast(ctypes.byref(buf, 8), ctypes.POINTER(ctypes.c_int32))[0]
        if loaded not in (0, 1):
            raise VhdWorkspaceError("detach_verify_failed")
        return bool(loaded)

    def detach(self, handle: Any) -> None:
        self._check(self._dll.DetachVirtualDisk(handle, 0, 0), "detach_failed")

    def close_handle(self, handle: Any) -> None:
        if handle and not self._kernel.CloseHandle(handle):
            raise VhdWorkspaceError("handle_close_failed")


def _powershell_executable() -> Path:
    if os.name != "nt":
        raise VhdWorkspaceError("powershell_unavailable")
    kernel = ctypes.WinDLL("kernel32.dll", use_last_error=True)
    kernel.GetSystemDirectoryW.argtypes = [ctypes.c_wchar_p, ctypes.c_uint32]
    kernel.GetSystemDirectoryW.restype = ctypes.c_uint32
    buffer = ctypes.create_unicode_buffer(32768)
    length = kernel.GetSystemDirectoryW(buffer, len(buffer))
    if not length or length >= len(buffer):
        raise VhdWorkspaceError("powershell_unavailable")
    path = Path(buffer.value) / "WindowsPowerShell" / "v1.0" / "powershell.exe"
    if not path.is_absolute() or not path.is_file():
        raise VhdWorkspaceError("powershell_unavailable")
    return path


def _run_storage_script(script: str, payload: dict[str, Any], stage: str) -> None:
    encoded_script = base64.b64encode(script.encode("utf-16-le")).decode("ascii")
    try:
        executable = _powershell_executable()
        env = os.environ.copy()
        env["PSModulePath"] = str(executable.parent / "Modules")
        result = subprocess.run(
            [str(executable), "-NoLogo", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-EncodedCommand", encoded_script],
            input=json.dumps(payload, separators=(",", ":")), text=True,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=False, env=env,
            timeout=180, check=False,
        )
    except (OSError, subprocess.SubprocessError, VhdWorkspaceError):
        raise VhdWorkspaceError(stage) from None
    try:
        response = json.loads(result.stdout)
    except (TypeError, ValueError):
        raise VhdWorkspaceError(stage) from None
    if result.returncode != 0 or not isinstance(response, dict) or response.get("ok") is not True:
        phases = {"image_lookup", "disk_association", "initialize", "partition", "partition_flags", "format", "mount", "mount_verify", "unmount_lookup", "unmount", "unmount_verify"}
        phase = response.get("code") if isinstance(response, dict) else None
        safe_stage = f"{stage}_{phase}" if isinstance(phase, str) and phase in phases else stage
        raise VhdWorkspaceError(safe_stage)


def _validate_root(root: Path) -> Path:
    if os.name != "nt":
        raise VhdWorkspaceError("windows_only")
    candidate = Path(root)
    if not candidate.is_absolute() or not candidate.anchor or candidate.anchor.startswith("\\\\"):
        raise VhdWorkspaceError("invalid_root")
    # Inspect every existing component before resolution so junctions/symlinks
    # are not hidden by Path.resolve(). The configured root must already exist.
    current = Path(candidate.anchor)
    try:
        anchor_stat = current.lstat()
    except OSError:
        raise VhdWorkspaceError("invalid_root") from None
    if getattr(anchor_stat, "st_file_attributes", 0) & 0x400:
        raise VhdWorkspaceError("reparse_root")
    for part in candidate.parts[1:]:
        current = current / part
        try:
            st = current.lstat()
        except OSError:
            raise VhdWorkspaceError("invalid_root") from None
        attrs = getattr(st, "st_file_attributes", 0)
        if current.is_symlink() or attrs & 0x400:  # FILE_ATTRIBUTE_REPARSE_POINT
            raise VhdWorkspaceError("reparse_root")
    if not candidate.is_dir():
        raise VhdWorkspaceError("invalid_root")
    kernel = ctypes.WinDLL("kernel32.dll", use_last_error=True)
    kernel.GetDriveTypeW.argtypes = [ctypes.c_wchar_p]
    kernel.GetDriveTypeW.restype = ctypes.c_uint32
    if kernel.GetDriveTypeW(candidate.anchor) != 3:  # DRIVE_FIXED
        raise VhdWorkspaceError("root_not_local_fixed")
    kernel.GetVolumeInformationW.argtypes = [
        ctypes.c_wchar_p, ctypes.c_wchar_p, ctypes.c_uint32,
        ctypes.POINTER(ctypes.c_uint32), ctypes.POINTER(ctypes.c_uint32),
        ctypes.POINTER(ctypes.c_uint32), ctypes.c_wchar_p, ctypes.c_uint32,
    ]
    kernel.GetVolumeInformationW.restype = ctypes.c_int
    fs_name = ctypes.create_unicode_buffer(64)
    if not kernel.GetVolumeInformationW(candidate.anchor, None, 0, None, None, None, fs_name, len(fs_name)):
        raise VhdWorkspaceError("root_volume_check_failed")
    if fs_name.value.upper() != "NTFS":
        raise VhdWorkspaceError("root_not_ntfs")
    return candidate.resolve(strict=True)


class WindowsVhdWorkspace:
    """One generated, fixed-size NTFS VHD workspace.

    Use ``WindowsVhdWorkspace.create(root, capacity_bytes)``. Successful
    creation returns only after the VHD has been attached, identified by its
    physical-device path, verified as the exact-size raw virtual disk, formatted
    NTFS, and mounted at a generated directory. ``close``/``destroy`` are
    idempotent; context-manager exit invokes close. There is intentionally no
    finalizer: callers must observe and handle cleanup errors explicitly.

    Provisioning errors with ambiguous cleanup expose ``error.workspace`` so
    the broker can retry ``close`` using the retained run/image identity.
    """

    def __init__(self, root: Path, capacity_bytes: int, native: Any | None = None) -> None:
        self._root = root
        self.capacity_bytes = capacity_bytes
        self.run_id = str(uuid.uuid4())
        self._run_dir = root / self.run_id
        self._image_path = self._run_dir / "workspace.vhd"
        self._mount_path = self._run_dir / "mount"
        self._native = native or _NativeVhd()
        self._handle: Any | None = None
        self._disk_path: str | None = None
        self._attach_attempted = False
        self._attached = False
        self._mounted = False
        self._closed = False
        self._created = False
        self._mount_dir_created = False

    @classmethod
    def create(cls, root: Path, capacity_bytes: int) -> "WindowsVhdWorkspace":
        if isinstance(capacity_bytes, bool) or not isinstance(capacity_bytes, int):
            raise VhdWorkspaceError("invalid_capacity")
        if capacity_bytes < MIN_CAPACITY_BYTES or capacity_bytes > MAX_CAPACITY_BYTES or capacity_bytes % _CAPACITY_ALIGNMENT:
            raise VhdWorkspaceError("invalid_capacity")
        safe_root = _validate_root(Path(root))
        instance = cls(safe_root, capacity_bytes)
        try:
            instance._run_dir.mkdir(mode=0o700, exist_ok=False)
            instance._created = True
            instance._handle = instance._native.create(instance._image_path, capacity_bytes)
            # Mark before crossing the attach boundary: failures can be ambiguous.
            instance._attach_attempted = True
            instance._native.attach(instance._handle)
            instance._attached = True
            instance._disk_path = instance._native.physical_path(instance._handle)
            instance._native.verify_capacity(instance._handle, capacity_bytes)
            # Always check the mount path begins as an ordinary empty directory.
            instance._mount_path.mkdir(mode=0o700, exist_ok=False)
            instance._mount_dir_created = True
            disk_number = int(instance._disk_path.rsplit("PhysicalDrive", 1)[1])
            data = {
                "disk_path": instance._disk_path,
                "disk_number": disk_number,
                "capacity_bytes": capacity_bytes,
                "image_path": str(instance._image_path),
                "mount_path": str(instance._mount_path) + "\\",
            }
            # Formatting may fail after Add-PartitionAccessPath succeeded.
            instance._mounted = True
            _run_storage_script(_FORMAT_SCRIPT, data, "format_or_mount_failed")
            return instance
        except BaseException as exc:
            try:
                instance.close()
            except BaseException:
                error = VhdWorkspaceError("provision_failed", cleanup_required=True)
                error.workspace = instance
                raise error from None
            if isinstance(exc, VhdWorkspaceError):
                raise VhdWorkspaceError(exc.code, system_error=exc.system_error) from None
            raise VhdWorkspaceError("provision_failed") from None

    @property
    def image_path(self) -> Path:
        return self._image_path

    @property
    def mount_path(self) -> Path:
        return self._mount_path

    @property
    def cleanup_required(self) -> bool:
        return not self._closed

    def __enter__(self) -> "WindowsVhdWorkspace":
        if self._closed:
            raise VhdWorkspaceError("workspace_closed")
        return self

    def __exit__(self, exc_type: Any, exc: Any, tb: Any) -> None:
        self.close()

    def close(self) -> None:
        try:
            self._close_impl()
        except VhdWorkspaceError as exc:
            if exc.cleanup_required:
                exc.workspace = self
            raise

    def _close_impl(self) -> None:
        """Unmount, detach and verify, then delete only the owned empty image/run dir.

        Uncertain unmount/detach/close retains the image and run ID for visible
        retry. A later deletion failure also remains visible, even if a prior
        deletion step already succeeded. Never uses recursive deletion.
        """
        if self._closed:
            return
        if not self._created:
            # mkdir failed (for example, a UUID collision); this instance owns
            # no directory and must not touch an existing path.
            self._closed = True
            return
        if self._mounted:
            if self._disk_path is None:
                raise VhdWorkspaceError("unmount_identity_missing", cleanup_required=True)
            number = int(self._disk_path.rsplit("PhysicalDrive", 1)[1])
            try:
                _run_storage_script(_UNMOUNT_SCRIPT, {
                    "disk_path": self._disk_path, "disk_number": number,
                    "image_path": str(self._image_path),
                    "capacity_bytes": self.capacity_bytes, "mount_path": str(self._mount_path) + "\\",
                }, "unmount_failed")
            except VhdWorkspaceError as exc:
                raise VhdWorkspaceError(exc.code, cleanup_required=True, system_error=exc.system_error) from None
            self._mounted = False
        if self._attach_attempted:
            if self._handle is None:
                raise VhdWorkspaceError("detach_handle_missing", cleanup_required=True)
            try:
                self._native.detach(self._handle)
            except BaseException:
                # An ambiguous attach failure is safe to release only when the
                # native loaded-state query explicitly proves that it is detached.
                try:
                    if self._native.is_loaded(self._handle):
                        raise VhdWorkspaceError("detach_verify_failed")
                except BaseException:
                    raise VhdWorkspaceError("detach_failed", cleanup_required=True) from None
            else:
                try:
                    if self._native.is_loaded(self._handle):
                        raise VhdWorkspaceError("detach_verify_failed")
                except BaseException:
                    raise VhdWorkspaceError("detach_verify_failed", cleanup_required=True) from None
            self._attached = False
            self._attach_attempted = False
        if self._handle is not None:
            try:
                self._native.close_handle(self._handle)
            except BaseException:
                raise VhdWorkspaceError("handle_close_failed", cleanup_required=True) from None
            self._handle = None
        # The mount path is an expected mount-point reparse point only while
        # mounted. Once detached it must be an ordinary empty directory.
        if self._mount_dir_created and (self._mount_path.exists() or self._mount_path.is_symlink()):
            try:
                st = self._mount_path.lstat()
            except OSError:
                raise VhdWorkspaceError("mount_dir_check_failed", cleanup_required=True) from None
            if getattr(st, "st_file_attributes", 0) & 0x400 or self._mount_path.is_symlink():
                raise VhdWorkspaceError("unexpected_mount_reparse", cleanup_required=True)
            try:
                self._mount_path.rmdir()
                self._mount_dir_created = False
            except OSError:
                raise VhdWorkspaceError("mount_dir_not_empty", cleanup_required=True) from None
        try:
            # Do not delete the backing image if this generated directory has
            # acquired anything other than its own image (broker-root ACLs are
            # still required to rule out hostile concurrent mutation).
            if any(child != self._image_path for child in self._run_dir.iterdir()):
                raise VhdWorkspaceError("run_dir_not_empty", cleanup_required=True)
            self._image_path.unlink(missing_ok=True)
            self._run_dir.rmdir()
        except VhdWorkspaceError:
            raise
        except OSError:
            raise VhdWorkspaceError("image_delete_failed", cleanup_required=True) from None
        self._closed = True

    def destroy(self) -> None:
        """Alias for explicit, idempotent destruction via :meth:`close`."""
        self.close()


def create_windows_vhd_workspace(root: Path, capacity_bytes: int) -> WindowsVhdWorkspace:
    """Functional convenience wrapper for :meth:`WindowsVhdWorkspace.create`."""
    return WindowsVhdWorkspace.create(root, capacity_bytes)
