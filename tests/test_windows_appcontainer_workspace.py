from pathlib import Path

import pytest

from workspace import windows_appcontainer_workspace as module


class FakeNative:
    def __init__(self):
        self.calls = []
        self.fail_revoke = 0
        self.fail_remove = 0
        self.fail_create = False
        self.create_error = None
        self.next_sid = 100

    def validate_root(self, path):
        self.calls.append(("validate", Path(path)))
        if not Path(path).is_dir():
            raise module.AppContainerWorkspaceError("invalid_root", "missing")

    def derive_sid(self, name):
        self.calls.append(("derive", name))
        self.next_sid += 1
        return self.next_sid, f"S-1-15-2-{self.next_sid}"

    def create_directory(self, path, sid_string, on_created=None):
        self.calls.append(("create", Path(path), sid_string))
        if self.fail_create:
            raise OSError("mkdir failed")
        if self.create_error:
            raise self.create_error
        Path(path).mkdir()
        broker_sid = "S-1-5-21-broker"
        if on_created is not None:
            on_created(broker_sid)
        return broker_sid

    def revoke(self, path, broker_sid):
        self.calls.append(("revoke", Path(path), broker_sid))
        if self.fail_revoke:
            self.fail_revoke -= 1
            raise OSError("revoke failed")

    def remove_tree(self, path):
        self.calls.append(("remove", Path(path)))
        if self.fail_remove:
            self.fail_remove -= 1
            raise OSError("remove failed")
        module._remove_without_reparse(Path(path))

    def free_sid(self, sid):
        self.calls.append(("free", sid))


@pytest.fixture
def native(monkeypatch):
    fake = FakeNative()
    monkeypatch.setattr(module, "_native", fake)
    return fake


def test_create_allocates_unique_profileless_identity_and_dedicated_directory(tmp_path, native):
    first = module.WindowsAppContainerWorkspace.create(tmp_path)
    second = module.WindowsAppContainerWorkspace.create(tmp_path)

    assert first.run_id != second.run_id
    assert first.identity_name == f"cs.{first.run_id}"
    assert first.workspace_path == tmp_path / first.run_id
    assert first.workspace_path.is_dir()
    assert first.sid_string == "S-1-15-2-101"
    assert all(call[0] != "create_profile" for call in native.calls)
    first.close()
    second.close()


def test_close_revokes_before_removal_and_is_idempotent(tmp_path, native):
    workspace = module.WindowsAppContainerWorkspace.create(tmp_path)
    start = len(native.calls)
    workspace.close()
    workspace.close()

    cleanup_calls = native.calls[start:]
    kinds = [call[0] for call in cleanup_calls]
    assert kinds == ["revoke", "free", "remove"]
    assert not workspace.workspace_path.exists()
    assert workspace.cleanup_required is False


def test_failed_revocation_preserves_directory_and_sid_then_retry_succeeds(tmp_path, native):
    workspace = module.WindowsAppContainerWorkspace.create(tmp_path)
    native.fail_revoke = 1

    with pytest.raises(module.AppContainerWorkspaceError) as caught:
        workspace.close()
    assert caught.value.code == "cleanup_failed"
    assert caught.value.cleanup_required is True
    assert caught.value.recovery_reference == str(workspace.workspace_path)
    assert workspace.workspace_path.exists()
    assert not any(call[0] in ("free", "remove") for call in native.calls)
    assert workspace.cleanup_required is True

    workspace.close()
    assert not workspace.workspace_path.exists()
    assert workspace.cleanup_required is False
    assert [call[0] for call in native.calls].count("free") == 1


def test_failed_removal_retries_without_revoking_twice(tmp_path, native):
    workspace = module.WindowsAppContainerWorkspace.create(tmp_path)
    native.fail_remove = 1

    with pytest.raises(module.AppContainerWorkspaceError):
        workspace.close()
    assert workspace._access_revoked
    assert workspace._sid is None
    workspace.close()

    kinds = [call[0] for call in native.calls]
    assert kinds.count("revoke") == 1
    assert kinds.count("remove") == 2
    assert not workspace.workspace_path.exists()


def test_create_failure_frees_allocated_sid_and_leaves_no_workspace(tmp_path, native):
    native.fail_create = True

    with pytest.raises(module.AppContainerWorkspaceError) as caught:
        module.WindowsAppContainerWorkspace.create(tmp_path)

    assert caught.value.code == "workspace_create_failed"
    assert caught.value.cleanup_required is False
    assert [call[0] for call in native.calls].count("free") == 1
    assert not list(tmp_path.iterdir())


def test_create_rollback_failure_returns_retryable_recovery_workspace(tmp_path, native, monkeypatch):
    original_init = module.WindowsAppContainerWorkspace.__init__

    def fail_after_directory(self, **kwargs):
        raise RuntimeError("injected after atomic directory creation")

    monkeypatch.setattr(module.WindowsAppContainerWorkspace, "__init__", fail_after_directory)
    native.fail_remove = 1
    with pytest.raises(module.AppContainerWorkspaceError) as caught:
        module.WindowsAppContainerWorkspace.create(tmp_path)
    monkeypatch.setattr(module.WindowsAppContainerWorkspace, "__init__", original_init)

    error = caught.value
    assert error.cleanup_required is True
    assert error.workspace is not None
    assert error.workspace.workspace_path == error.workspace_path
    assert error.workspace._access_revoked is True
    error.workspace.close()
    assert not error.workspace_path.exists()


def test_invalid_root_fails_before_identity_allocation(tmp_path, native):
    missing = tmp_path / "missing"
    with pytest.raises(module.AppContainerWorkspaceError) as caught:
        module.WindowsAppContainerWorkspace.create(missing)

    assert caught.value.code == "invalid_root"
    assert [call[0] for call in native.calls] == ["validate"]


def test_relative_root_is_rejected_before_native_validation(native):
    with pytest.raises(module.AppContainerWorkspaceError) as caught:
        module.WindowsAppContainerWorkspace.create(Path("relative-root"))

    assert caught.value.code == "invalid_root"
    assert native.calls == []


def test_sddl_keeps_low_label_and_owner_rights_bounded():
    sddl = module._WindowsNative._descriptor_sddl("S-1-15-2-123", "S-1-5-21-123")

    assert sddl.startswith("O:S-1-5-21-123D:P")
    assert "S:(ML;OICI;NW;;;LW)" in sddl
    assert "(A;OICI;FA;;;SY)" in sddl
    assert "(A;OICI;FA;;;S-1-5-21-123)" in sddl
    assert "(A;OICI;RC;;;OW)" in sddl
    assert "(A;;0x001201FF;;;S-1-15-2-123)" in sddl
    assert "(D;" not in sddl


def test_reparse_child_cleanup_is_refused_without_touching_target(tmp_path):
    target = tmp_path / "outside"
    target.mkdir()
    (target / "keep.txt").write_text("untouched")
    root = tmp_path / "workspace"
    root.mkdir()
    (root / "escape").symlink_to(target, target_is_directory=True)

    with pytest.raises(OSError, match="reparse"):
        module._remove_without_reparse(root)

    assert (target / "keep.txt").read_text() == "untouched"
    assert root.exists()


def test_broad_acl_predicate_covers_every_broad_sid_and_inherit_only_handling():
    risky_root = module._ROOT_RISKY_MASK
    for sid in module._BROAD_PRINCIPAL_SIDS:
        assert module._broad_acl_grants_write(sid, risky_root, is_root=True)
        assert module._broad_acl_grants_write(sid, module._PARENT_RISKY_MASK, is_root=False)
    # The restricted-applications group is included in the policy used by the native validator.
    assert "S-1-15-2-2" in module._BROAD_PRINCIPAL_SIDS
    assert not module._broad_acl_grants_write("S-1-15-2-2", 0x00000001, is_root=True)
    assert not module._broad_acl_grants_write("S-1-15-2-2", 0x00000040, is_root=True, ace_flags=0x08)
    assert not module._broad_acl_grants_write("S-1-15-2-2", 0x00000040, is_root=False, ace_flags=0x08)
    assert not module._broad_acl_grants_write("S-1-5-18", risky_root, is_root=True)


def test_ancestor_policy_distinguishes_sibling_creation_from_package_write_authority():
    for sid in module._BROAD_PRINCIPAL_SIDS:
        for access in (0x40000000, 0x10, 0x100, 0x40, 0x10000, 0x40000, 0x80000):
            assert module._broad_acl_grants_write(sid, access, is_root=False)
    for sid in ("S-1-15-2-1", "S-1-15-2-2"):
        for create_access in (0x2, 0x4):
            assert module._broad_acl_grants_write(sid, create_access, is_root=False)
    for sid in ("S-1-1-0", "S-1-5-11", "S-1-5-32-545"):
        for create_access in (0x2, 0x4):
            assert not module._broad_acl_grants_write(sid, create_access, is_root=False)
            assert module._broad_acl_grants_write(sid, create_access, is_root=True)


def test_revoke_preserves_owner_rights_control_for_root_children_and_broker(tmp_path, monkeypatch):
    root = tmp_path / "workspace"
    root.mkdir()
    child_dir = root / "child"
    child_dir.mkdir()
    (child_dir / "file.txt").write_text("content")
    applied = []
    monkeypatch.setattr(module._WindowsNative, "_set_path_security",
                        staticmethod(lambda path, sddl, include_label=True: applied.append((Path(path), sddl, include_label))))
    module._WindowsNative().revoke(root, "S-1-5-21-broker")

    assert {path for path, _, _ in applied} == {root, child_dir, child_dir / "file.txt"}
    assert all("(A;OICI;RC;;;OW)" in sddl for _, sddl, _ in applied)
    assert all("(A;OICI;FA;;;S-1-5-21-broker)" in sddl for _, sddl, _ in applied)
    assert all(include_label is False for _, _, include_label in applied)


def test_create_cancellation_after_directory_creation_rolls_back_and_reraises(tmp_path, native, monkeypatch):
    monkeypatch.setattr(module.WindowsAppContainerWorkspace, "__init__",
                        lambda self, **kwargs: (_ for _ in ()).throw(KeyboardInterrupt("cancel")))
    with pytest.raises(KeyboardInterrupt) as caught:
        module.WindowsAppContainerWorkspace.create(tmp_path)

    assert caught.value.cleanup_required is False
    assert caught.value.workspace_path is None
    assert not list(tmp_path.iterdir())
    assert [call[0] for call in native.calls].count("revoke") == 1
    assert [call[0] for call in native.calls].count("free") == 1
    assert [call[0] for call in native.calls].count("remove") == 1


def test_create_cancellation_after_sid_allocation_frees_sid_and_reraises(tmp_path, native):
    native.create_error = SystemExit("cancel")
    with pytest.raises(SystemExit) as caught:
        module.WindowsAppContainerWorkspace.create(tmp_path)

    assert caught.value.cleanup_required is False
    assert caught.value.workspace is None
    assert not list(tmp_path.iterdir())
    assert [call[0] for call in native.calls].count("free") == 1
    assert [call[0] for call in native.calls].count("revoke") == 0
    assert [call[0] for call in native.calls].count("remove") == 0


def test_create_cancellation_cleanup_failure_attaches_retryable_recovery(tmp_path, native, monkeypatch):
    monkeypatch.setattr(module.WindowsAppContainerWorkspace, "__init__",
                        lambda self, **kwargs: (_ for _ in ()).throw(KeyboardInterrupt("cancel")))
    native.fail_revoke = 1
    with pytest.raises(KeyboardInterrupt) as caught:
        module.WindowsAppContainerWorkspace.create(tmp_path)

    cancellation = caught.value
    assert cancellation.cleanup_required is True
    assert cancellation.workspace_path is not None
    recovery = cancellation.workspace
    assert recovery is not None and recovery.cleanup_required
    assert recovery._access_revoked is False
    recovery.close()
    assert not cancellation.workspace_path.exists()


def test_create_failure_does_not_remove_preexisting_collision(tmp_path, native, monkeypatch):
    run_id = "a" * 32
    monkeypatch.setattr(module.uuid, "uuid4", lambda: type("UUID", (), {"hex": run_id})())
    collision = tmp_path / run_id
    collision.mkdir()
    sentinel = collision / "keep.txt"
    sentinel.write_text("existing")
    native.fail_create = True

    with pytest.raises(module.AppContainerWorkspaceError):
        module.WindowsAppContainerWorkspace.create(tmp_path)

    assert sentinel.read_text() == "existing"
    assert [call[0] for call in native.calls].count("revoke") == 0
    assert [call[0] for call in native.calls].count("remove") == 0
