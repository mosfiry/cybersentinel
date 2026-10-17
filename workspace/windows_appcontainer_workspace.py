"""Profileless, per-run AppContainer workspace provisioning for Windows.

This allocates an AppContainer SID only; it deliberately never calls
CreateAppContainerProfile and therefore does not provision a profile directory
or registry state. The supplied root and every ancestor must satisfy the
validated NTFS, local-disk, and broad-principal ACL prerequisites. This
experimental native primitive is not a supported backend and does not guarantee
that a process or external actor cannot write outside or into the workspace.
The caller must stop all sandbox processes before close().
"""
from __future__ import annotations

import ctypes
import os
import uuid
from pathlib import Path
from typing import Optional


_BROAD_PRINCIPAL_SIDS = frozenset({
    "S-1-1-0",             # Everyone
    "S-1-5-11",            # Authenticated Users
    "S-1-5-32-545",        # Builtin Users
    "S-1-15-2-1",          # All Application Packages
    "S-1-15-2-2",          # All Restricted Application Packages
})
_ROOT_RISKY_MASK = 0x10000000 | 0x40000000 | 0x00000002 | 0x00000004 | 0x10 | 0x40 | 0x100 | 0x10000 | 0x40000 | 0x80000
_PARENT_RISKY_MASK = 0x00000040 | 0x00010000 | 0x00040000 | 0x00080000 | 0x10000000 | 0x40000000 | 0x10 | 0x100

def _broad_acl_grants_write(sid_text: str, mask: int, *, is_root: bool, ace_flags: int = 0) -> bool:
    """Return whether a non-inherit-only allow ACE is risky for a broad SID."""
    if ace_flags & 0x08:  # INHERIT_ONLY_ACE: does not apply to this directory.
        return False
    # Ordinary ancestor create-only grants cannot replace the existing protected
    # root. Package-wide create grants, however, are known out-of-workspace LPAC
    # write authority and are rejected even on ancestors.
    package_wide = sid_text in {"S-1-15-2-1", "S-1-15-2-2"}
    risky = _ROOT_RISKY_MASK if is_root or package_wide else _PARENT_RISKY_MASK
    return sid_text in _BROAD_PRINCIPAL_SIDS and bool(mask & risky)

def _system_error(exc):
    return getattr(exc, "winerror", None) or getattr(exc, "errno", None)


class AppContainerWorkspaceError(RuntimeError):
    """A workspace operation failed; fields are stable for programmatic handling."""

    def __init__(self, code: str, message: str, *, system_error: Optional[int] = None,
                 cleanup_required: bool = False, workspace_path: Optional[Path] = None, workspace=None):
        super().__init__(message)
        self.code = code
        self.system_error = system_error
        self.cleanup_required = cleanup_required
        self.workspace_path = workspace_path
        self.recovery_reference = str(workspace_path) if workspace_path is not None else None
        self.workspace = workspace


class _WindowsNative:
    """Small ctypes boundary kept replaceable for portable unit tests."""

    def _require_windows(self):
        if os.name != "nt":
            raise AppContainerWorkspaceError("unsupported_platform", "AppContainer workspaces require Windows")

    @staticmethod
    def _last_error():
        return ctypes.get_last_error()

    @staticmethod
    def _sid_string(sid):
        advapi = ctypes.WinDLL("advapi32", use_last_error=True)
        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel.LocalFree.argtypes = [ctypes.c_void_p]
        kernel.LocalFree.restype = ctypes.c_void_p
        text = ctypes.c_wchar_p()
        advapi.ConvertSidToStringSidW.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_wchar_p)]
        advapi.ConvertSidToStringSidW.restype = ctypes.c_int
        if not advapi.ConvertSidToStringSidW(sid, ctypes.byref(text)):
            raise ctypes.WinError(ctypes.get_last_error())
        try:
            return text.value
        finally:
            kernel.LocalFree.argtypes = [ctypes.c_void_p]
            kernel.LocalFree.restype = ctypes.c_void_p
            kernel.LocalFree(ctypes.cast(text, ctypes.c_void_p))

    def derive_sid(self, name):
        self._require_windows()
        userenv = ctypes.WinDLL("userenv", use_last_error=True)
        sid = ctypes.c_void_p()
        fn = userenv.DeriveAppContainerSidFromAppContainerName
        fn.argtypes = [ctypes.c_wchar_p, ctypes.POINTER(ctypes.c_void_p)]
        fn.restype = ctypes.c_long
        result = fn(name, ctypes.byref(sid))
        if result != 0:
            raise AppContainerWorkspaceError("sid_allocation_failed", "Could not derive AppContainer SID",
                                             system_error=result & 0xFFFFFFFF)
        try:
            return sid, self._sid_string(sid)
        except Exception:
            self.free_sid(sid)
            raise

    def free_sid(self, sid):
        if sid:
            advapi = ctypes.WinDLL("advapi32", use_last_error=True)
            advapi.FreeSid.argtypes = [ctypes.c_void_p]
            advapi.FreeSid.restype = ctypes.c_void_p
            advapi.FreeSid(sid)

    @staticmethod
    def _security_descriptor(sddl):
        advapi = ctypes.WinDLL("advapi32", use_last_error=True)
        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel.LocalFree.argtypes = [ctypes.c_void_p]
        kernel.LocalFree.restype = ctypes.c_void_p
        ptr, size = ctypes.c_void_p(), ctypes.c_ulong()
        fn = advapi.ConvertStringSecurityDescriptorToSecurityDescriptorW
        fn.argtypes = [ctypes.c_wchar_p, ctypes.c_ulong, ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(ctypes.c_ulong)]
        fn.restype = ctypes.c_int
        if not fn(sddl, 1, ctypes.byref(ptr), ctypes.byref(size)):
            raise ctypes.WinError(ctypes.get_last_error())
        return ptr

    @staticmethod
    def _broker_sid():
        advapi = ctypes.WinDLL("advapi32", use_last_error=True)
        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel.GetCurrentProcess.argtypes = []
        kernel.GetCurrentProcess.restype = ctypes.c_void_p
        kernel.CloseHandle.argtypes = [ctypes.c_void_p]
        kernel.CloseHandle.restype = ctypes.c_int
        advapi.OpenProcessToken.argtypes = [ctypes.c_void_p, ctypes.c_ulong, ctypes.POINTER(ctypes.c_void_p)]
        advapi.OpenProcessToken.restype = ctypes.c_int
        advapi.GetTokenInformation.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_void_p,
                                               ctypes.c_ulong, ctypes.POINTER(ctypes.c_ulong)]
        advapi.GetTokenInformation.restype = ctypes.c_int
        token = ctypes.c_void_p()
        if not advapi.OpenProcessToken(kernel.GetCurrentProcess(), 0x0008, ctypes.byref(token)):
            raise ctypes.WinError(ctypes.get_last_error())
        try:
            needed = ctypes.c_ulong()
            advapi.GetTokenInformation(token, 1, None, 0, ctypes.byref(needed))
            buf = ctypes.create_string_buffer(needed.value)
            if not advapi.GetTokenInformation(token, 1, buf, needed, ctypes.byref(needed)):
                raise ctypes.WinError(ctypes.get_last_error())
            sid = ctypes.cast(buf, ctypes.POINTER(ctypes.c_void_p))[0]
            return _WindowsNative._sid_string(sid)
        finally:
            kernel.CloseHandle(token)

    @staticmethod
    def _descriptor_sddl(app_sid, broker_sid):
        # Direct root access lacks DELETE, WRITE_DAC and WRITE_OWNER. Explicit
        # READ_CONTROL supports generic read/write mappings; inherited file and
        # directory grants differ so ordinary files are not executable.
        root = 0x001201FF
        files = 0x0013019F
        dirs = 0x001201FF
        return (f"O:{broker_sid}D:P(A;OICI;RC;;;OW)(A;OICI;FA;;;SY)(A;OICI;FA;;;{broker_sid})"
                f"(A;;0x{root:08X};;;{app_sid})(A;OIIO;0x{files:08X};;;{app_sid})"
                f"(A;CIIO;0x{dirs:08X};;;{app_sid})S:(ML;OICI;NW;;;LW)")

    @staticmethod
    def _set_path_security(path, sddl, include_label=True):
        advapi = ctypes.WinDLL("advapi32", use_last_error=True)
        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel.LocalFree.argtypes = [ctypes.c_void_p]
        kernel.LocalFree.restype = ctypes.c_void_p
        advapi.GetSecurityDescriptorDacl.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_int),
                                                      ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(ctypes.c_int)]
        advapi.GetSecurityDescriptorDacl.restype = ctypes.c_int
        advapi.GetSecurityDescriptorSacl.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_int),
                                                      ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(ctypes.c_int)]
        advapi.GetSecurityDescriptorSacl.restype = ctypes.c_int
        descriptor = _WindowsNative._security_descriptor(sddl)
        try:
            dacl, dacl_present, dacl_defaulted = ctypes.c_void_p(), ctypes.c_int(), ctypes.c_int()
            if not advapi.GetSecurityDescriptorDacl(descriptor, ctypes.byref(dacl_present),
                                                     ctypes.byref(dacl), ctypes.byref(dacl_defaulted)):
                raise ctypes.WinError(ctypes.get_last_error())
            # DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION.
            info = 0x4 | 0x80000000
            sacl = ctypes.c_void_p()
            if include_label:
                sp, present, defaulted = ctypes.c_void_p(), ctypes.c_int(), ctypes.c_int()
                if not advapi.GetSecurityDescriptorSacl(descriptor, ctypes.byref(present),
                                                         ctypes.byref(sp), ctypes.byref(defaulted)):
                    raise ctypes.WinError(ctypes.get_last_error())
                if present.value:
                    sacl = sp
                    info |= 0x10  # LABEL_SECURITY_INFORMATION
            fn = advapi.SetNamedSecurityInfoW
            fn.argtypes = [ctypes.c_wchar_p, ctypes.c_int, ctypes.c_ulong, ctypes.c_void_p,
                           ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p]
            fn.restype = ctypes.c_ulong
            status = fn(str(path), 1, info, None, None, dacl if dacl_present.value else None, sacl)
            if status:
                raise OSError(status, "SetNamedSecurityInfoW failed")
        finally:
            kernel.LocalFree(descriptor)

    def set_acl(self, path, sddl):
        """Apply a protected DACL and any mandatory label in SDDL (native harness hook)."""
        self._require_windows()
        self._set_path_security(path, sddl, include_label=True)

    def revoke(self, path, broker_sid):
        sddl = f"D:P(A;OICI;RC;;;OW)(A;OICI;FA;;;SY)(A;OICI;FA;;;{broker_sid})"

        def revoke_node(item):
            if _is_reparse(item):
                raise OSError(f"refusing reparse point during ACL revocation: {item}")
            self._set_path_security(item, sddl, include_label=False)
            if item.is_dir():
                with os.scandir(item) as children:
                    for child in children:
                        child_path = Path(child.path)
                        if _is_reparse(child_path):
                            raise OSError(f"refusing reparse child during ACL revocation: {child.name}")
                        revoke_node(child_path)

        revoke_node(Path(path))

    def create_directory(self, path, app_sid, on_created=None):
        self._require_windows()
        broker_sid = self._broker_sid()
        sddl = self._descriptor_sddl(app_sid, broker_sid)
        descriptor = self._security_descriptor(sddl)
        try:
            class SECURITY_ATTRIBUTES(ctypes.Structure):
                _fields_ = [("nLength", ctypes.c_ulong), ("lpSecurityDescriptor", ctypes.c_void_p),
                            ("bInheritHandle", ctypes.c_int)]
            attrs = SECURITY_ATTRIBUTES(ctypes.sizeof(SECURITY_ATTRIBUTES), descriptor, 0)
            kernel = ctypes.WinDLL("kernel32", use_last_error=True)
            fn = kernel.CreateDirectoryW
            fn.argtypes = [ctypes.c_wchar_p, ctypes.POINTER(SECURITY_ATTRIBUTES)]
            fn.restype = ctypes.c_int
            if not fn(str(path), ctypes.byref(attrs)):
                raise ctypes.WinError(ctypes.get_last_error())
            # The successful exclusive CreateDirectoryW call is the ownership
            # boundary; tell the transaction before any subsequent Python work.
            if on_created is not None:
                on_created(broker_sid)
            return broker_sid
        finally:
            kernel.LocalFree.argtypes = [ctypes.c_void_p]
            kernel.LocalFree.restype = ctypes.c_void_p
            kernel.LocalFree(descriptor)

    def validate_root(self, root):
        self._require_windows()
        path = Path(root)
        raw = str(path)
        if not path.is_absolute() or raw.startswith(("\\\\?\\", "\\\\.\\", "\\\\")):
            raise AppContainerWorkspaceError("invalid_root", "Root must be an absolute local filesystem directory")
        if not path.is_dir():
            raise AppContainerWorkspaceError("invalid_root", "Root must already exist and be a directory")
        # Reject every reparse point along the path, including a junction ancestor.
        current = Path(path.anchor)
        for part in path.parts[1:]:
            current = current / part
            try:
                if os.lstat(current).st_file_attributes & 0x400:
                    raise AppContainerWorkspaceError("reparse_root", "Root path contains a reparse point")
            except AttributeError:  # Some Python builds omit st_file_attributes.
                if current.is_symlink():
                    raise AppContainerWorkspaceError("reparse_root", "Root path contains a reparse point")
        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        volume = ctypes.create_unicode_buffer(32768)
        kernel.GetVolumePathNameW.argtypes = [ctypes.c_wchar_p, ctypes.c_wchar_p, ctypes.c_ulong]
        kernel.GetVolumePathNameW.restype = ctypes.c_int
        kernel.GetDriveTypeW.argtypes = [ctypes.c_wchar_p]
        kernel.GetDriveTypeW.restype = ctypes.c_uint
        kernel.GetVolumeInformationW.argtypes = [ctypes.c_wchar_p, ctypes.c_wchar_p, ctypes.c_ulong,
                                                  ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p,
                                                  ctypes.c_wchar_p, ctypes.c_ulong]
        kernel.GetVolumeInformationW.restype = ctypes.c_int
        if not kernel.GetVolumePathNameW(str(path), volume, len(volume)):
            raise ctypes.WinError(ctypes.get_last_error())
        if kernel.GetDriveTypeW(volume.value) != 3:
            raise AppContainerWorkspaceError("nonlocal_volume", "Root must be on a local fixed disk")
        fsname = ctypes.create_unicode_buffer(64)
        if not kernel.GetVolumeInformationW(volume.value, None, 0, None, None, None, fsname, len(fsname)):
            raise ctypes.WinError(ctypes.get_last_error())
        if fsname.value.upper() != "NTFS":
            raise AppContainerWorkspaceError("unsupported_filesystem", "Root must be on NTFS")
        if os.path.normcase(os.path.abspath(path)) == os.path.normcase(os.path.abspath(volume.value)):
            raise AppContainerWorkspaceError("invalid_root", "A volume root cannot be used as the workspace root")
        # Writable broad principals can replace or tamper with broker-created entries.
        cur = path
        while True:
            self._reject_broad_writable_acl(cur, is_root=(cur == path))
            if cur.parent == cur:
                break
            cur = cur.parent

    def _reject_broad_writable_acl(self, path, *, is_root):
        advapi = ctypes.WinDLL("advapi32", use_last_error=True)
        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel.LocalFree.argtypes = [ctypes.c_void_p]
        kernel.LocalFree.restype = ctypes.c_void_p
        dacl, owner, group = ctypes.c_void_p(), ctypes.c_void_p(), ctypes.c_void_p()
        # GetNamedSecurityInfoW returns a Win32 status code and allocates descriptor parts.
        fn = advapi.GetNamedSecurityInfoW
        fn.argtypes = [ctypes.c_wchar_p, ctypes.c_int, ctypes.c_ulong, ctypes.c_void_p,
                       ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p), ctypes.c_void_p,
                       ctypes.POINTER(ctypes.c_void_p)]
        fn.restype = ctypes.c_ulong
        status = fn(str(path), 1, 0x4, None, None, ctypes.byref(dacl), None, ctypes.byref(owner))
        if status:
            raise OSError(status, "Could not inspect root ACL")
        try:
            if not dacl.value:
                raise AppContainerWorkspaceError("null_root_dacl", "Root or ancestor has a NULL DACL")
            # These principals can include unrelated interactive or app-container users.
            class ACL_SIZE(ctypes.Structure):
                _fields_ = [("AclRevision", ctypes.c_ubyte), ("Sbz1", ctypes.c_ubyte),
                            ("AclSize", ctypes.c_ushort), ("AceCount", ctypes.c_ushort), ("Sbz2", ctypes.c_ushort)]
            acl = ctypes.cast(dacl, ctypes.POINTER(ACL_SIZE)).contents
            for index in range(acl.AceCount):
                ace = ctypes.c_void_p()
                advapi.GetAce.argtypes = [ctypes.c_void_p, ctypes.c_ulong, ctypes.POINTER(ctypes.c_void_p)]
                advapi.GetAce.restype = ctypes.c_int
                if not advapi.GetAce(dacl, index, ctypes.byref(ace)):
                    raise ctypes.WinError(ctypes.get_last_error())
                raw = ctypes.string_at(ace, 8)
                ace_type, ace_flags = raw[0], raw[1]
                if ace_flags & 0x08:
                    continue
                if ace_type not in (0, 5, 9, 11):  # allow, object allow, callback allow variants
                    continue
                mask = int.from_bytes(raw[4:8], "little")
                sid_offset = 8
                if ace_type in (5, 11):
                    object_flags = int.from_bytes(ctypes.string_at(ace.value + 8, 4), "little")
                    sid_offset = 12
                    if object_flags & 1:
                        sid_offset += 16
                    if object_flags & 2:
                        sid_offset += 16
                sid_text = self._sid_string(ctypes.c_void_p(ace.value + sid_offset))
                if _broad_acl_grants_write(sid_text, mask, is_root=is_root, ace_flags=ace_flags):
                    raise AppContainerWorkspaceError("broad_root_acl", "Root or ancestor grants write access to a broad principal")
        finally:
            if owner.value:
                kernel.LocalFree(owner)

    def remove_tree(self, path):
        _remove_without_reparse(path)


_native = _WindowsNative()


def _is_reparse(path: Path) -> bool:
    try:
        return bool(os.lstat(path).st_file_attributes & 0x400)
    except AttributeError:
        return path.is_symlink()


def _remove_without_reparse(path: Path):
    """Refuse reparse descendants rather than following them during cleanup."""
    if _is_reparse(path):
        raise OSError("refusing to traverse or remove a reparse point")
    if path.is_dir():
        with os.scandir(path) as children:
            for child in children:
                item = Path(child.path)
                if _is_reparse(item):
                    raise OSError(f"refusing reparse child: {item.name}")
                if child.is_dir(follow_symlinks=False):
                    _remove_without_reparse(item)
                else:
                    item.unlink()
        path.rmdir()
    else:
        path.unlink()


class WindowsAppContainerWorkspace:
    """One unique AppContainer identity and protected dedicated directory."""

    def __init__(self, *, run_id: str, identity_name: str, sid, sid_string: str,
                 workspace_path: Path, broker_sid: str):
        self.run_id = run_id
        self.identity_name = identity_name
        self.sid_string = sid_string
        self.workspace_path = Path(workspace_path)
        self._sid = sid
        self._broker_sid = broker_sid
        self._access_revoked = False
        self._closed = False
        self.cleanup_required = False

    @classmethod
    def create(cls, root: Path) -> "WindowsAppContainerWorkspace":
        try:
            root = Path(root)
            if not root.is_absolute():
                raise AppContainerWorkspaceError("invalid_root", "Root must be absolute")
            _native.validate_root(root)
        except AppContainerWorkspaceError:
            raise
        except OSError as exc:
            raise AppContainerWorkspaceError("root_validation_failed", "Could not validate workspace root",
                                             system_error=_system_error(exc)) from exc
        run_id = uuid.uuid4().hex
        identity_name = f"cs.{run_id}"
        workspace = root / run_id
        sid = None
        sid_string = ""
        broker_sid = None
        created = False

        def mark_created(value):
            nonlocal created, broker_sid
            created, broker_sid = True, value

        def recovery_workspace(revoked):
            recovery = cls.__new__(cls)
            recovery.run_id = run_id
            recovery.identity_name = identity_name
            recovery.sid_string = sid_string
            recovery.workspace_path = Path(workspace)
            recovery._sid = sid if not revoked else None
            recovery._broker_sid = broker_sid or ""
            recovery._access_revoked = revoked
            recovery._closed = False
            recovery.cleanup_required = True
            return recovery

        try:
            sid, sid_string = _native.derive_sid(identity_name)
            broker_sid = _native.create_directory(workspace, sid_string, on_created=mark_created)
            return cls(run_id=run_id, identity_name=identity_name, sid=sid, sid_string=sid_string,
                       workspace_path=workspace, broker_sid=broker_sid)
        except BaseException as exc:
            revoked = not created
            cleanup_required = False
            cleanup_failure = None
            if created:
                try:
                    _native.revoke(workspace, broker_sid or "")
                    revoked = True
                    _native.remove_tree(workspace)
                except BaseException as cleanup_exc:
                    cleanup_required = True
                    cleanup_failure = cleanup_exc
            if sid and revoked:
                try:
                    _native.free_sid(sid)
                    sid = None
                except BaseException as cleanup_exc:
                    cleanup_required = True
                    cleanup_failure = cleanup_failure or cleanup_exc
            recovery = recovery_workspace(revoked) if cleanup_required and created else None
            if isinstance(exc, AppContainerWorkspaceError):
                exc.cleanup_required = cleanup_required
                exc.workspace_path = workspace if cleanup_required else None
                exc.recovery_reference = str(workspace) if cleanup_required else None
                exc.workspace = recovery
                if isinstance(exc, Exception):
                    raise
                raise
            if not isinstance(exc, Exception):
                # Preserve KeyboardInterrupt/SystemExit; recovery is attached
                # rather than replacing the caller's cancellation signal.
                try:
                    exc.cleanup_required = cleanup_required
                    exc.workspace_path = workspace if cleanup_required else None
                    exc.recovery_reference = str(workspace) if cleanup_required else None
                    exc.workspace = recovery
                except BaseException:
                    pass
                raise
            raise AppContainerWorkspaceError("workspace_create_failed", "Could not create protected workspace",
                                             system_error=_system_error(exc),
                                             cleanup_required=cleanup_required,
                                             workspace_path=workspace if cleanup_required else None,
                                             workspace=recovery) from exc

    def close(self) -> None:
        """Revoke the identity's ACL, then remove workspace; safe to retry."""
        if self._closed:
            return
        try:
            if not self._access_revoked:
                _native.revoke(self.workspace_path, self._broker_sid)
                self._access_revoked = True
                if self._sid:
                    _native.free_sid(self._sid)
                    self._sid = None
            _native.remove_tree(self.workspace_path)
        except BaseException as exc:
            self.cleanup_required = True
            if not isinstance(exc, Exception):
                try:
                    exc.cleanup_required = True
                    exc.workspace_path = self.workspace_path
                    exc.recovery_reference = str(self.workspace_path)
                    exc.workspace = self
                except BaseException:
                    pass
                raise
            raise AppContainerWorkspaceError("cleanup_failed", "Workspace cleanup failed; retry close() after resolving the cause",
                                             system_error=_system_error(exc),
                                             cleanup_required=True, workspace_path=self.workspace_path,
                                             workspace=self) from exc
        self.cleanup_required = False
        self._closed = True

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        self.close()
        return False
