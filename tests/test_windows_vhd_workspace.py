from __future__ import annotations

import errno
import json
import os
import subprocess
import sys
import time
from pathlib import Path

import pytest

from workspace import windows_vhd_workspace as vhd


_WINDOWS_NATIVE = pytest.mark.skipif(sys.platform != "win32", reason="requires native Windows VHD support")
_MIB = 1024 * 1024


@pytest.mark.parametrize(
    "capacity_bytes",
    [True, False, -1, "67108864", float(64 * _MIB), vhd.MAX_CAPACITY_BYTES + _MIB, vhd.MIN_CAPACITY_BYTES + 1],
)
def test_capacity_validation_rejects_invalid_values_before_touching_root(tmp_path: Path, capacity_bytes) -> None:
    root = tmp_path / "must-not-be-created"
    with pytest.raises(vhd.VhdWorkspaceError, match="invalid_capacity"):
        vhd.WindowsVhdWorkspace.create(root, capacity_bytes)
    assert not root.exists()


def test_partial_create_failure_removes_only_the_mocked_owned_artifacts(tmp_path: Path, monkeypatch) -> None:
    root = tmp_path / "root"
    root.mkdir()
    events: list[str] = []

    class FakeNative:
        def create(self, image_path: Path, _capacity: int) -> None:
            events.append("create")
            image_path.touch()
            raise vhd.VhdWorkspaceError("create_failed")

    monkeypatch.setattr(vhd, "_validate_root", lambda _root: root)
    monkeypatch.setattr(vhd, "_NativeVhd", FakeNative)

    with pytest.raises(vhd.VhdWorkspaceError, match="create_failed"):
        vhd.WindowsVhdWorkspace.create(root, vhd.MIN_CAPACITY_BYTES)

    assert events == ["create"]
    assert list(root.iterdir()) == []


def _disk_full_code(exc: OSError) -> int | None:
    winerror = getattr(exc, "winerror", None)
    if winerror in (112, 39):
        return winerror
    if exc.errno == errno.ENOSPC:
        return exc.errno
    return None


def _write_until_disk_full(path: Path, capacity_bytes: int) -> tuple[int, OSError]:
    """Write real non-zero data under a strict attempted-byte ceiling."""
    block = bytes(range(1, 256)) * (4096)  # 1 MiB, not a sparse seek/truncate.
    attempted = 0
    written = 0
    limit = capacity_bytes + 4 * _MIB
    failure: OSError | None = None
    with path.open("xb", buffering=0) as stream:
        while attempted < limit:
            payload = block[: min(len(block), limit - attempted)]
            attempted += len(payload)
            try:
                count = stream.write(payload)
                if count is not None:
                    written += count
                stream.flush()
                os.fsync(stream.fileno())
                if count != len(payload):
                    # A short write at capacity must be followed by an OS-reported full-disk error.
                    stream.write(b"X")
            except OSError as exc:
                failure = exc
                break
    if failure is None:
        raise AssertionError(f"disk did not report full within {limit} attempted bytes")
    return written, failure


def _native_root(tmp_path: Path, name: str) -> Path:
    root = tmp_path / name
    root.mkdir()
    return root


@_WINDOWS_NATIVE
def test_native_vhd_capacity_is_hard_for_direct_writes(tmp_path: Path, record_property) -> None:
    capacity = vhd.MIN_CAPACITY_BYTES
    root = _native_root(tmp_path, "native capacity ' & [x]")
    host_sentinel = tmp_path / "host-sentinel.bin"
    host_bytes = b"host-data-must-remain-untouched"
    host_sentinel.write_bytes(host_bytes)
    workspace = vhd.WindowsVhdWorkspace.create(root, capacity)
    try:
        fixed_before = workspace.image_path.stat().st_size
        bytes_written, failure = _write_until_disk_full(workspace.mount_path / "fill.bin", capacity)
        fixed_after = workspace.image_path.stat().st_size
        disk_full = _disk_full_code(failure)
        record_property("capacity_bytes", capacity)
        record_property("bytes_written_total", bytes_written)
        record_property("disk_full_errno", failure.errno)
        record_property("disk_full_winerror", getattr(failure, "winerror", None))
        record_property("fixed_image_bytes_before", fixed_before)
        record_property("fixed_image_bytes_after", fixed_after)
        record_property("run_id", workspace.run_id)
        assert disk_full is not None, f"expected Windows disk-full/ENOSPC, got errno={failure.errno}, winerror={getattr(failure, 'winerror', None)}"
        assert 0 < bytes_written <= capacity
        assert fixed_before == capacity + 512  # Fixed VHD data plus its footer.
        assert fixed_after == fixed_before
        assert host_sentinel.read_bytes() == host_bytes
    finally:
        workspace.close()


def _run_two_bounded_writers(mount_path: Path, capacity: int) -> list[dict[str, int | str | None]]:
    # Trusted inline fixtures only; shell=False, no project code, and each child's total request is bounded.
    child = r'''import errno,json,os,sys
path,budget=sys.argv[1],int(sys.argv[2]); written=0; full=None
block=(bytes(range(1,256))*4096)
try:
    with open(path,"xb",buffering=0) as f:
        while written < budget:
            chunk=block[:min(len(block),budget-written)]
            try:
                n=f.write(chunk)
                if n is None: n=0
                written += n
                if n < len(chunk):
                    try: f.write(b"X")
                    except OSError as e: full=getattr(e,"winerror",None) or e.errno
                    break
            except OSError as e:
                full=getattr(e,"winerror",None) or e.errno
                break
        try: os.fsync(f.fileno())
        except OSError as e:
            if full is None: full=getattr(e,"winerror",None) or e.errno
except OSError as e:
    full=getattr(e,"winerror",None) or e.errno
print(json.dumps({"written":written,"full":full}))
'''
    budget_per_child = capacity // 2 + 2 * _MIB
    processes: list[subprocess.Popen[str]] = []
    results: list[dict[str, int | str | None]] = []
    try:
        for index in range(2):
            target = mount_path / f"child-{index}.bin"
            processes.append(
                subprocess.Popen(
                    [sys.executable, "-B", "-c", child, str(target), str(budget_per_child)],
                    cwd=str(mount_path),
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    shell=False,
                )
            )
        deadline = time.monotonic() + 90
        for process in processes:
            stdout, stderr = process.communicate(timeout=max(0.1, deadline - time.monotonic()))
            if process.returncode != 0:
                raise AssertionError(f"bounded writer failed with code {process.returncode}: {stderr[-1000:]}")
            results.append(json.loads(stdout))
    except subprocess.TimeoutExpired:
        for process in processes:
            if process.poll() is None:
                process.terminate()
        for process in processes:
            try:
                process.communicate(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.communicate(timeout=5)
        raise AssertionError("bounded VHD writer exceeded its 90-second deadline")
    finally:
        # No child is allowed to outlive this test, including after an assertion failure.
        for process in processes:
            if process.poll() is None:
                process.kill()
            process.wait(timeout=5)
    return results


@_WINDOWS_NATIVE
def test_native_vhd_aggregate_children_stay_within_fixed_image_bound(tmp_path: Path, record_property) -> None:
    capacity = vhd.MIN_CAPACITY_BYTES
    root = _native_root(tmp_path, "native-aggregate")
    host_sentinel = tmp_path / "aggregate-host-sentinel.bin"
    host_bytes = b"host-volume-sentinel"
    host_sentinel.write_bytes(host_bytes)
    workspace = vhd.WindowsVhdWorkspace.create(root, capacity)
    try:
        fixed_before = workspace.image_path.stat().st_size
        results = _run_two_bounded_writers(workspace.mount_path, capacity)
        fixed_after = workspace.image_path.stat().st_size
        total_written = sum(int(result["written"]) for result in results)
        codes = [result["full"] for result in results]
        record_property("capacity_bytes", capacity)
        record_property("bytes_written_total", total_written)
        record_property("disk_full_errno_or_winerror", ",".join(str(code) for code in codes))
        record_property("fixed_image_bytes_before", fixed_before)
        record_property("fixed_image_bytes_after", fixed_after)
        record_property("run_id", workspace.run_id)
        assert any(code in (112, 39, errno.ENOSPC) for code in codes)
        assert total_written <= capacity
        assert total_written <= capacity + 4 * _MIB + 2
        assert fixed_after == fixed_before
        assert host_sentinel.read_bytes() == host_bytes
    finally:
        workspace.close()


@_WINDOWS_NATIVE
def test_native_vhd_runs_are_unique_and_isolated_when_first_is_full(tmp_path: Path, record_property) -> None:
    capacity = vhd.MIN_CAPACITY_BYTES
    root = _native_root(tmp_path, "native-isolation")
    first = vhd.WindowsVhdWorkspace.create(root, capacity)
    second: vhd.WindowsVhdWorkspace | None = None
    try:
        second = vhd.WindowsVhdWorkspace.create(root, capacity)
        record_property("capacity_bytes", capacity)
        record_property("unique_run_ids", f"{first.run_id},{second.run_id}")
        assert first.run_id != second.run_id
        assert first.image_path != second.image_path
        assert first.mount_path != second.mount_path
        marker = first.mount_path / "run-one-only.bin"
        marker.write_bytes(b"belongs only to first run")
        assert not (second.mount_path / marker.name).exists()

        fixed_before = first.image_path.stat().st_size
        bytes_written, failure = _write_until_disk_full(first.mount_path / "fill.bin", capacity)
        fixed_after = first.image_path.stat().st_size
        disk_full = _disk_full_code(failure)
        record_property("bytes_written_total", bytes_written)
        record_property("disk_full_errno", failure.errno)
        record_property("disk_full_winerror", getattr(failure, "winerror", None))
        record_property("fixed_image_bytes_before", fixed_before)
        record_property("fixed_image_bytes_after", fixed_after)
        assert disk_full is not None
        assert fixed_after == fixed_before
        other_run_file = second.mount_path / "still-writable.bin"
        other_run_file.write_bytes(b"the other VHD remains writable")
        assert other_run_file.read_bytes() == b"the other VHD remains writable"
    finally:
        try:
            if second is not None:
                second.close()
        finally:
            first.close()


@_WINDOWS_NATIVE
def test_native_vhd_cleanup_is_complete_idempotent_and_unassociated(tmp_path: Path, record_property) -> None:
    root = _native_root(tmp_path, "native-cleanup")
    workspace = vhd.WindowsVhdWorkspace.create(root, vhd.MIN_CAPACITY_BYTES)
    image_path, mount_path, run_dir = workspace.image_path, workspace.mount_path, workspace.image_path.parent
    run_id = workspace.run_id
    (mount_path / "payload.bin").write_bytes(b"temporary workspace payload")
    workspace.close()
    workspace.close()
    record_property("capacity_bytes", workspace.capacity_bytes)
    record_property("run_id", run_id)
    assert not image_path.exists()
    assert not mount_path.exists()
    assert not run_dir.exists()
    assert list(root.iterdir()) == []


@_WINDOWS_NATIVE
def test_native_vhd_cleanup_failure_is_visible_and_retryable(tmp_path: Path, record_property, monkeypatch) -> None:
    root = _native_root(tmp_path, "native-cleanup-retry")
    workspace = vhd.WindowsVhdWorkspace.create(root, vhd.MIN_CAPACITY_BYTES)
    image_path, mount_path = workspace.image_path, workspace.mount_path
    original_detach = workspace._native.detach
    calls = 0

    def fail_once_at_real_detach(handle) -> None:
        nonlocal calls
        calls += 1
        if calls == 1:
            raise vhd.VhdWorkspaceError("injected_detach_failure")
        original_detach(handle)

    monkeypatch.setattr(workspace._native, "detach", fail_once_at_real_detach)
    try:
        with pytest.raises(vhd.VhdWorkspaceError, match="detach_failed"):
            workspace.close()
        record_property("capacity_bytes", workspace.capacity_bytes)
        record_property("run_id", workspace.run_id)
        assert workspace.cleanup_required
        assert image_path.is_file()
        assert mount_path.is_dir()
        workspace.close()
        assert calls == 2
        assert not workspace.cleanup_required
        assert not image_path.exists()
        assert not mount_path.exists()
    finally:
        # If the injected operation failed, restore the actual adapter and retry to avoid a leaked VHD.
        monkeypatch.setattr(workspace._native, "detach", original_detach)
        if workspace.cleanup_required:
            workspace.close()


def test_storage_script_is_static_encoded_code_with_json_only_on_stdin(monkeypatch) -> None:
    import base64
    from types import SimpleNamespace

    executable = Path("/trusted/system/WindowsPowerShell/v1.0/powershell.exe")
    payload = {"image_path": "C:\\broker space' & [x]\\workspace.vhd", "capacity_bytes": 64 * _MIB}
    calls = []

    def run(argv, **kwargs):
        calls.append((argv, kwargs))
        return SimpleNamespace(returncode=0, stdout='{"ok":true}', stderr="")

    monkeypatch.setattr(vhd, "_powershell_executable", lambda: executable)
    monkeypatch.setattr(vhd.subprocess, "run", run)
    vhd._run_storage_script(vhd._FORMAT_SCRIPT, payload, "format_or_mount_failed")
    argv, kwargs = calls[0]
    assert argv[0] == str(executable)
    assert argv[-2] == "-EncodedCommand"
    assert base64.b64decode(argv[-1]).decode("utf-16-le") == vhd._FORMAT_SCRIPT
    assert payload["image_path"] not in " ".join(argv)
    assert json.loads(kwargs["input"]) == payload
    assert kwargs["shell"] is False
    assert kwargs["timeout"] == 180
    assert kwargs["env"]["PSModulePath"] == str(executable.parent / "Modules")


class _FakeLifecycleNative:
    def __init__(self):
        self.events = []
        self.loaded = False
        self.fail_once = None

    def _step(self, name):
        self.events.append(name)
        if self.fail_once == name:
            self.fail_once = None
            raise vhd.VhdWorkspaceError("injected_failure")

    def create(self, image, capacity):
        self._step("create")
        image.touch()
        return object()

    def attach(self, handle):
        self._step("attach")
        self.loaded = True

    def physical_path(self, handle):
        self._step("identity")
        return "\\\\.\\PhysicalDrive7"

    def verify_capacity(self, handle, capacity):
        self._step("capacity")

    def detach(self, handle):
        self._step("detach")
        self.loaded = False

    def is_loaded(self, handle):
        self._step("loaded")
        return self.loaded

    def close_handle(self, handle):
        self._step("close_handle")


def _mocked_workspace(tmp_path, monkeypatch):
    native = _FakeLifecycleNative()
    monkeypatch.setattr(vhd, "_validate_root", lambda root: root)
    monkeypatch.setattr(vhd, "_NativeVhd", lambda: native)
    monkeypatch.setattr(vhd, "_run_storage_script", lambda *args: native._step("storage"))
    return vhd.WindowsVhdWorkspace.create(tmp_path, vhd.MIN_CAPACITY_BYTES), native


@pytest.mark.parametrize("stage", ["storage", "detach", "loaded", "close_handle", "image_delete", "run_dir_delete"])
def test_cleanup_failure_retains_identity_and_can_retry_every_stage(tmp_path, monkeypatch, stage) -> None:
    workspace, native = _mocked_workspace(tmp_path, monkeypatch)
    image, run_dir = workspace.image_path, workspace.image_path.parent
    if stage in ("image_delete", "run_dir_delete"):
        method = "unlink" if stage == "image_delete" else "rmdir"
        original = getattr(Path, method)
        target = image if stage == "image_delete" else run_dir
        failed = False

        def delete(path, *args, **kwargs):
            nonlocal failed
            if path == target and not failed:
                failed = True
                raise OSError("injected deletion failure")
            return original(path, *args, **kwargs)

        monkeypatch.setattr(Path, method, delete)
    else:
        native.fail_once = stage
    with pytest.raises(vhd.VhdWorkspaceError) as failure:
        workspace.close()
    assert failure.value.cleanup_required is True
    assert failure.value.workspace is workspace
    assert workspace.cleanup_required
    assert workspace.run_id == run_dir.name
    if stage != "run_dir_delete":
        assert image.is_file()
    workspace.close()
    workspace.close()
    assert not workspace.cleanup_required
    assert not run_dir.exists()
    # Successful detach is not repeated after later close/delete failures.
    if stage in ("close_handle", "image_delete", "run_dir_delete"):
        assert native.events.count("detach") == 1


@pytest.mark.parametrize("stage", ["attach", "identity", "capacity", "storage"])
def test_partial_provision_failure_rolls_back_without_ready_workspace(tmp_path, monkeypatch, stage) -> None:
    native = _FakeLifecycleNative()
    native.fail_once = stage
    monkeypatch.setattr(vhd, "_validate_root", lambda root: root)
    monkeypatch.setattr(vhd, "_NativeVhd", lambda: native)
    monkeypatch.setattr(vhd, "_run_storage_script", lambda *args: native._step("storage"))
    with pytest.raises(vhd.VhdWorkspaceError) as failure:
        vhd.WindowsVhdWorkspace.create(tmp_path, vhd.MIN_CAPACITY_BYTES)
    assert not failure.value.cleanup_required
    assert not native.loaded
    assert list(tmp_path.iterdir()) == []


def test_native_create_requests_explicit_detach_right_and_fixed_allocation(tmp_path) -> None:
    import ctypes
    from types import SimpleNamespace

    observed = {}

    def create(storage, path, access, descriptor, flags, provider_flags, params, overlap, handle):
        observed.update(access=access, flags=flags, params=params._obj)
        ctypes.cast(handle, ctypes.POINTER(ctypes.c_void_p))[0] = ctypes.c_void_p(123)
        return 0

    native = object.__new__(vhd._NativeVhd)
    native._dll = SimpleNamespace(CreateVirtualDisk=create)
    handle = native.create(tmp_path / "fixed.vhd", vhd.MIN_CAPACITY_BYTES)
    assert handle.value == 123
    assert observed["access"] == 0x001E0000  # SDK CREATE | ATTACH_RW | DETACH | GET_INFO.
    assert observed["flags"] == native._CREATE_FULL_PHYSICAL_ALLOCATION
    assert observed["params"].Version == 1
    assert observed["params"].u.Version1.MaximumSize == vhd.MIN_CAPACITY_BYTES
    assert not observed["params"].u.Version1.ParentPath
    assert not observed["params"].u.Version1.SourcePath


def test_storage_timeout_is_sanitized_and_never_reports_success(monkeypatch) -> None:
    monkeypatch.setattr(vhd, "_powershell_executable", lambda: Path("/trusted/powershell.exe"))

    def timeout(*args, **kwargs):
        raise subprocess.TimeoutExpired(args[0], kwargs["timeout"], output="sensitive fixture output")

    monkeypatch.setattr(vhd.subprocess, "run", timeout)
    with pytest.raises(vhd.VhdWorkspaceError) as failure:
        vhd._run_storage_script(vhd._FORMAT_SCRIPT, {"image_path": "private fixture path"}, "format_or_mount_failed")
    assert failure.value.code == "format_or_mount_failed"
    assert "sensitive" not in str(failure.value)
    assert "private" not in str(failure.value)


def test_storage_mutations_use_owned_cim_objects_not_reused_disk_numbers() -> None:
    import re

    for script in (vhd._FORMAT_SCRIPT, vhd._UNMOUNT_SCRIPT):
        assert "Get-DiskImage -ImagePath" in script
        for line in script.splitlines():
            if re.search(r"\b(Initialize-Disk|New-Partition|Set-Partition|Add-PartitionAccessPath|Remove-PartitionAccessPath)\b", line):
                assert "-InputObject" in line
                assert "-DiskNumber" not in line
                assert "-Number " not in line
    assert "Format-Volume -Partition $p" in vhd._FORMAT_SCRIPT


@_WINDOWS_NATIVE
def test_native_vhd_writer_timeout_leaves_no_children(tmp_path, record_property, monkeypatch) -> None:
    from types import SimpleNamespace

    original_popen = subprocess.Popen
    children = []

    def hanging_fixture(argv, **kwargs):
        trusted = [sys.executable, "-B", "-c", "import time; time.sleep(300)"]
        process = original_popen(trusted, **kwargs)
        children.append(process)
        return process

    times = iter((0.0, 100.0))
    # Replace only this test module's clock, not subprocess's real timeout clock.
    monkeypatch.setattr(sys.modules[__name__], "time", SimpleNamespace(monotonic=lambda: next(times, 100.0)))
    monkeypatch.setattr(subprocess, "Popen", hanging_fixture)
    with pytest.raises(AssertionError, match="90-second deadline"):
        _run_two_bounded_writers(tmp_path, vhd.MIN_CAPACITY_BYTES)
    assert len(children) == 2
    assert all(process.poll() is not None for process in children)
    record_property("trusted_hanging_child_count", len(children))
    record_property("remaining_child_count", sum(process.poll() is None for process in children))


def test_create_win32_status_remains_visible_after_successful_rollback(tmp_path, monkeypatch) -> None:
    from types import SimpleNamespace

    native = object.__new__(vhd._NativeVhd)
    native._dll = SimpleNamespace(CreateVirtualDisk=lambda *args: 5)
    monkeypatch.setattr(vhd, "_validate_root", lambda root: root)
    monkeypatch.setattr(vhd, "_NativeVhd", lambda: native)
    with pytest.raises(vhd.VhdWorkspaceError) as failure:
        vhd.WindowsVhdWorkspace.create(tmp_path, vhd.MIN_CAPACITY_BYTES)
    assert failure.value.code == "create_failed"
    assert failure.value.system_error == 5
    assert "system_error=5" in str(failure.value)
    assert str(tmp_path) not in str(failure.value)
    assert not failure.value.cleanup_required
    assert list(tmp_path.iterdir()) == []


@pytest.mark.parametrize("phase,expected", [("initialize", "format_or_mount_failed_initialize"), ("private/path & sensitive stderr", "format_or_mount_failed"), (["initialize"], "format_or_mount_failed")])
def test_storage_diagnostics_allow_only_fixed_phase_names(monkeypatch, phase, expected) -> None:
    from types import SimpleNamespace

    monkeypatch.setattr(vhd, "_powershell_executable", lambda: Path("/trusted/powershell.exe"))
    monkeypatch.setattr(vhd.subprocess, "run", lambda *args, **kwargs: SimpleNamespace(returncode=1, stdout=json.dumps({"ok": False, "code": phase}), stderr="sensitive stderr"))
    with pytest.raises(vhd.VhdWorkspaceError) as failure:
        vhd._run_storage_script(vhd._FORMAT_SCRIPT, {}, "format_or_mount_failed")
    assert failure.value.code == expected
    assert "private/path" not in str(failure.value)
    assert "stderr" not in str(failure.value)


def test_unmount_phase_remains_visible_with_cleanup_required(tmp_path, monkeypatch) -> None:
    workspace, native = _mocked_workspace(tmp_path, monkeypatch)

    def fail(*args):
        raise vhd.VhdWorkspaceError("unmount_failed_unmount_lookup")

    monkeypatch.setattr(vhd, "_run_storage_script", fail)
    with pytest.raises(vhd.VhdWorkspaceError) as failure:
        workspace.close()
    assert failure.value.code == "unmount_failed_unmount_lookup"
    assert failure.value.cleanup_required
    assert failure.value.workspace is workspace
    assert workspace.image_path.is_file()
    assert "detach" not in native.events
    monkeypatch.setattr(vhd, "_run_storage_script", lambda *args: None)
    workspace.close()
    assert not workspace.cleanup_required
