"""Experimental registered-LPAC helpers; deliberately not a product backend.

This module is used only by native acceptance tests. It never edits private
registry mappings and it refuses to adopt an existing profile name.
"""
from __future__ import annotations

import ctypes
import hashlib
import json
import os
import re
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any

PROFILE_PREFIX = "CyberSentinel.LPAC.v1."
PROFILE_NAME_RE = re.compile(r"[-_. A-Za-z0-9]+\Z")
RUN_ID_RE = re.compile(r"[0-9a-f]{32}\Z")
SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")
JOURNAL_SCHEMA = "cybersentinel-registered-lpac-journal-v1"
_JOURNAL_FIELDS = {
    "schema", "sequence", "run_id", "profile_name", "owner_sid_sha256",
    "state", "package_sid_sha256", "profile_folder_sha256",
}
_TRANSITION_FIELDS = {"package_sid_sha256", "profile_folder_sha256"}

STATES = frozenset({
    "CREATE_INTENT",
    "PROFILE_CREATED",
    "PROFILE_PATH_RESOLVED",
    "PROBE_RUNNING",
    "PROBE_COMPLETE",
    "CLEANUP_PENDING",
    "DELETED",
    "QUARANTINED",
})
_TRANSITIONS = {
    "CREATE_INTENT": {"PROFILE_CREATED", "QUARANTINED"},
    "PROFILE_CREATED": {"PROFILE_PATH_RESOLVED", "CLEANUP_PENDING", "QUARANTINED"},
    "PROFILE_PATH_RESOLVED": {"PROBE_RUNNING", "CLEANUP_PENDING", "QUARANTINED"},
    "PROBE_RUNNING": {"PROBE_COMPLETE", "QUARANTINED"},
    "PROBE_COMPLETE": {"CLEANUP_PENDING", "QUARANTINED"},
    "CLEANUP_PENDING": {"DELETED", "QUARANTINED"},
    "DELETED": set(),
    "QUARANTINED": set(),
}


class PrototypeError(RuntimeError):
    """Sanitized error for the experimental acceptance path."""

    def __init__(self, code: str, *, system_error: int | None = None):
        self.code = code
        self.system_error = system_error
        suffix = "" if system_error is None else f"; system_error={system_error}"
        super().__init__(f"registered LPAC prototype failed ({code}){suffix}")


def new_run_id() -> str:
    """Return a cryptographically random UUIDv4 identifier in canonical hex form."""
    return uuid.uuid4().hex


def profile_name_for_run(run_id: str) -> str:
    if not isinstance(run_id, str) or not RUN_ID_RE.fullmatch(run_id):
        raise PrototypeError("invalid_run_id")
    name = PROFILE_PREFIX + run_id
    if len(name) > 64 or not PROFILE_NAME_RE.fullmatch(name):
        raise PrototypeError("invalid_profile_name")
    return name


def sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _valid_document(document: Any) -> bool:
    if not isinstance(document, dict) or set(document) - _JOURNAL_FIELDS:
        return False
    if document.get("schema") != JOURNAL_SCHEMA:
        return False
    if not isinstance(document.get("sequence"), int) or document["sequence"] < 0:
        return False
    if not isinstance(document.get("run_id"), str) or not RUN_ID_RE.fullmatch(document["run_id"]):
        return False
    if document.get("profile_name") != profile_name_for_run(document["run_id"]):
        return False
    if document.get("state") not in STATES:
        return False
    if not isinstance(document.get("owner_sid_sha256"), str) or not SHA256_RE.fullmatch(document["owner_sid_sha256"]):
        return False
    state = document["state"]
    if state in {"PROFILE_CREATED", "PROFILE_PATH_RESOLVED", "PROBE_RUNNING", "PROBE_COMPLETE", "CLEANUP_PENDING", "DELETED"}:
        if not isinstance(document.get("package_sid_sha256"), str) or not SHA256_RE.fullmatch(document["package_sid_sha256"]):
            return False
    if state in {"PROFILE_PATH_RESOLVED", "PROBE_RUNNING", "PROBE_COMPLETE", "CLEANUP_PENDING", "DELETED"}:
        if not isinstance(document.get("profile_folder_sha256"), str) or not SHA256_RE.fullmatch(document["profile_folder_sha256"]):
            return False
    if state == "CREATE_INTENT" and any(document.get(key) is not None for key in ("package_sid_sha256", "profile_folder_sha256")):
        return False
    if state == "PROFILE_CREATED" and document.get("profile_folder_sha256") is not None:
        return False
    for key in ("package_sid_sha256", "profile_folder_sha256"):
        value = document.get(key)
        if value is not None and (not isinstance(value, str) or not SHA256_RE.fullmatch(value)):
            return False
    return True


@dataclass
class OwnershipJournal:
    """Fsync'ed append-only per-run record; ambiguous state is never adopted.

    The record lives under the test runner's private temporary root. It is not
    evidence of persistence across a host reboot.
    """

    path: Path
    document: dict[str, Any]

    @classmethod
    def create(cls, path: Path, run_id: str, owner_sid: str) -> "OwnershipJournal":
        name = profile_name_for_run(run_id)
        if not isinstance(owner_sid, str) or not owner_sid.startswith("S-"):
            raise PrototypeError("invalid_owner_identity")
        target = Path(path)
        document = {
            "schema": JOURNAL_SCHEMA,
            "sequence": 0,
            "run_id": run_id,
            "profile_name": name,
            "owner_sid_sha256": sha256_text(owner_sid),
            "state": "CREATE_INTENT",
        }
        if target.exists():
            raise PrototypeError("journal_already_exists")
        target.parent.mkdir(parents=True, exist_ok=True)
        payload = (json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
        try:
            descriptor = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except FileExistsError:
            raise PrototypeError("journal_already_exists") from None
        try:
            with os.fdopen(descriptor, "wb", closefd=True) as stream:
                stream.write(payload)
                stream.flush()
                os.fsync(stream.fileno())
        except BaseException:
            try:
                target.unlink()
            except OSError:
                pass
            raise
        return cls(target, document)

    @classmethod
    def load(cls, path: Path) -> "OwnershipJournal":
        try:
            payload = Path(path).read_bytes()
        except OSError:
            raise PrototypeError("journal_corrupt_or_missing") from None
        if not payload.endswith(b"\n"):
            raise PrototypeError("journal_truncated")
        try:
            lines = payload.splitlines()
            if not lines or any(not line for line in lines):
                raise PrototypeError("journal_blank_record")
            events = [json.loads(line) for line in lines]
        except PrototypeError:
            raise
        except (UnicodeError, json.JSONDecodeError):
            raise PrototypeError("journal_corrupt_or_missing") from None
        if not events or any(not _valid_document(event) for event in events):
            raise PrototypeError("journal_invalid_or_incomplete")
        first = events[0]
        if first.get("sequence") != 0 or first.get("state") != "CREATE_INTENT":
            raise PrototypeError("journal_invalid_or_incomplete")
        previous = first
        for index, current in enumerate(events[1:], start=1):
            if current.get("sequence") != index:
                raise PrototypeError("journal_sequence_invalid")
            for key in ("schema", "run_id", "profile_name", "owner_sid_sha256"):
                if current.get(key) != first.get(key):
                    raise PrototypeError("journal_owner_changed")
            if current.get("state") not in _TRANSITIONS.get(str(previous.get("state")), set()):
                raise PrototypeError("journal_transition_invalid")
            for key in ("package_sid_sha256", "profile_folder_sha256"):
                if previous.get(key) is not None and current.get(key) != previous.get(key):
                    raise PrototypeError("journal_identity_changed")
            previous = current
        return cls(Path(path), dict(events[-1]))

    @property
    def state(self) -> str:
        return str(self.document["state"])

    def transition(self, state: str, **fields: Any) -> None:
        if state not in _TRANSITIONS.get(self.state, set()):
            raise PrototypeError("invalid_lifecycle_transition")
        if set(fields) - _TRANSITION_FIELDS:
            raise PrototypeError("invalid_journal_field")
        updated = dict(self.document)
        updated.update(fields)
        updated["sequence"] = int(self.document["sequence"]) + 1
        updated["state"] = state
        if not _valid_document(updated):
            raise PrototypeError("journal_state_incomplete")
        payload = (json.dumps(updated, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
        try:
            descriptor = os.open(self.path, os.O_WRONLY | os.O_APPEND)
            with os.fdopen(descriptor, "ab", closefd=True) as stream:
                stream.write(payload)
                stream.flush()
                os.fsync(stream.fileno())
        except OSError:
            raise PrototypeError("journal_append_failed") from None
        self.document = updated

    def recovery_decision(
        self,
        *,
        observed_sid_sha256: str | None,
        derived_sid_sha256: str | None,
        owner_sid_sha256: str | None,
        observed_profile_folder_sha256: str | None,
        job_is_empty: bool,
        handles_closed: bool,
    ) -> str:
        """Permit only proven-owner cleanup after process and handle closure.

        PID, elapsed time, and a stale lock are intentionally not ownership or
        liveness evidence. Any malformed, partial, mismatched, or active state
        must be quarantined and refused.
        """
        if not _valid_document(self.document):
            return "QUARANTINE_AND_REFUSE"
        if self.state not in {"PROFILE_CREATED", "PROFILE_PATH_RESOLVED", "PROBE_COMPLETE", "CLEANUP_PENDING"}:
            return "QUARANTINE_AND_REFUSE"
        if not owner_sid_sha256 or self.document.get("owner_sid_sha256") != owner_sid_sha256:
            return "QUARANTINE_AND_REFUSE"
        expected_folder = self.document.get("profile_folder_sha256")
        if not expected_folder or expected_folder != observed_profile_folder_sha256:
            return "QUARANTINE_AND_REFUSE"
        expected = self.document.get("package_sid_sha256")
        if not expected or expected != observed_sid_sha256 or expected != derived_sid_sha256:
            return "QUARANTINE_AND_REFUSE"
        if not job_is_empty or not handles_closed:
            return "QUARANTINE_AND_REFUSE"
        return "DELETE_OWNED_PROFILE"


@dataclass(frozen=True)
class RegisteredProfile:
    name: str
    sid: str
    folder_path: Path


class WindowsProfileApi:
    """Narrow ctypes wrapper over documented userenv profile APIs."""

    S_OK = 0
    HRESULT_ALREADY_EXISTS = 0x800700B7

    def __init__(self) -> None:
        if os.name != "nt":
            raise PrototypeError("windows_only")
        self._userenv = ctypes.WinDLL("userenv.dll", use_last_error=True)
        self._advapi = ctypes.WinDLL("advapi32.dll", use_last_error=True)
        self._kernel = ctypes.WinDLL("kernel32.dll", use_last_error=True)
        self._ole32 = ctypes.WinDLL("ole32.dll", use_last_error=True)
        self._configure()

    def _configure(self) -> None:
        h = ctypes.c_void_p
        w = ctypes.c_wchar_p
        u32 = ctypes.c_uint32
        self._userenv.CreateAppContainerProfile.argtypes = [w, w, w, h, u32, ctypes.POINTER(h)]
        self._userenv.CreateAppContainerProfile.restype = ctypes.c_int32
        self._userenv.DeriveAppContainerSidFromAppContainerName.argtypes = [w, ctypes.POINTER(h)]
        self._userenv.DeriveAppContainerSidFromAppContainerName.restype = ctypes.c_int32
        self._userenv.GetAppContainerFolderPath.argtypes = [w, ctypes.POINTER(w)]
        self._userenv.GetAppContainerFolderPath.restype = ctypes.c_int32
        self._userenv.DeleteAppContainerProfile.argtypes = [w]
        self._userenv.DeleteAppContainerProfile.restype = ctypes.c_int32
        self._advapi.ConvertSidToStringSidW.argtypes = [h, ctypes.POINTER(w)]
        self._advapi.ConvertSidToStringSidW.restype = ctypes.c_int
        self._advapi.FreeSid.argtypes = [h]
        self._advapi.FreeSid.restype = h
        self._kernel.LocalFree.argtypes = [h]
        self._kernel.LocalFree.restype = h
        self._ole32.CoTaskMemFree.argtypes = [h]
        self._ole32.CoTaskMemFree.restype = None

    def _sid_string(self, sid: ctypes.c_void_p) -> str:
        text = ctypes.c_wchar_p()
        if not self._advapi.ConvertSidToStringSidW(sid, ctypes.byref(text)):
            raise PrototypeError("sid_format_failed", system_error=ctypes.get_last_error())
        try:
            return str(text.value)
        finally:
            self._kernel.LocalFree(ctypes.cast(text, ctypes.c_void_p))

    def create(self, name: str) -> str:
        if len(name) > 64 or not PROFILE_NAME_RE.fullmatch(name):
            raise PrototypeError("invalid_profile_name")
        sid = ctypes.c_void_p()
        hr = int(self._userenv.CreateAppContainerProfile(name, name, "CyberSentinel isolated LPAC experiment", None, 0, ctypes.byref(sid))) & 0xFFFFFFFF
        if hr == self.HRESULT_ALREADY_EXISTS:
            raise PrototypeError("profile_name_already_exists", system_error=hr)
        if hr != self.S_OK or not sid:
            raise PrototypeError("profile_create_failed", system_error=hr)
        try:
            return self._sid_string(sid)
        finally:
            self._advapi.FreeSid(sid)

    def derive_sid(self, name: str) -> str:
        sid = ctypes.c_void_p()
        hr = int(self._userenv.DeriveAppContainerSidFromAppContainerName(name, ctypes.byref(sid))) & 0xFFFFFFFF
        if hr != self.S_OK or not sid:
            raise PrototypeError("profile_sid_derivation_failed", system_error=hr)
        try:
            return self._sid_string(sid)
        finally:
            self._advapi.FreeSid(sid)

    def folder_path(self, sid: str) -> Path:
        path = ctypes.c_wchar_p()
        hr = int(self._userenv.GetAppContainerFolderPath(sid, ctypes.byref(path))) & 0xFFFFFFFF
        if hr != self.S_OK or not path.value:
            raise PrototypeError("profile_folder_lookup_failed", system_error=hr)
        try:
            result = Path(path.value)
            if not result.is_absolute():
                raise PrototypeError("profile_folder_not_absolute")
            return result
        finally:
            self._ole32.CoTaskMemFree(ctypes.cast(path, ctypes.c_void_p))

    def delete(self, name: str) -> None:
        if len(name) > 64 or not PROFILE_NAME_RE.fullmatch(name):
            raise PrototypeError("invalid_profile_name")
        hr = int(self._userenv.DeleteAppContainerProfile(name)) & 0xFFFFFFFF
        if hr != self.S_OK:
            raise PrototypeError("profile_delete_unconfirmed", system_error=hr)
