from __future__ import annotations

import hashlib
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

from agent.local_runtime.catalog import ModelSpec
from agent.local_runtime import manager as manager_module
from agent.local_runtime.manager import LocalModelManager
from agent.model_router import ModelRouter


RAM_GIB = 1024**3


def make_spec(model_id: str, payload: bytes) -> ModelSpec:
    return ModelSpec(
        model_id=model_id,
        family="TestFamily",
        display_name=f"Test {model_id}",
        parameter_size="tiny",
        repository="tests/pinned-fixture",
        revision="a" * 40,
        filename=f"{model_id}.gguf",
        size_bytes=len(payload),
        sha256=hashlib.sha256(payload).hexdigest(),
        quantization="Q4_K_M",
        license="Apache-2.0",
        min_ram_gib=1,
        recommended_ram_gib=2,
        context_length=1024,
    )


def hardware(ram_gib: int = 8) -> dict:
    return {
        "os": "linux",
        "architecture": "x86_64",
        "cpu_count": 8,
        "ram_bytes": ram_gib * RAM_GIB,
        "ram_gib": float(ram_gib),
        "free_disk_bytes": 20 * RAM_GIB,
        "free_disk_gib": 20.0,
        "gpu_devices": [],
        "gpu_acceleration_available": False,
    }


class FakeRuntime:
    def __init__(self, *, fail_for: str = ""):
        self.active = ""
        self.started: list[str] = []
        self.stopped = 0
        self.fail_for = fail_for

    def start(self, spec, model_path: Path):
        assert model_path.is_file()
        if spec.model_id == self.fail_for:
            raise RuntimeError("fake_runtime_start_failed")
        self.active = spec.model_id
        self.started.append(spec.model_id)
        return SimpleNamespace(name="fake_local", model=spec.model_id)

    def stop(self):
        self.stopped += 1
        self.active = ""


def make_manager(tmp_path, specs, payloads, *, ram_gib=8, runtime=None, router=None):
    def downloader(_url, destination, *, expected_size, expected_sha256, progress=None, cancel_event=None):
        payload = payloads[Path(destination).name]
        assert len(payload) == expected_size
        assert hashlib.sha256(payload).hexdigest() == expected_sha256
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(payload)
        if progress:
            progress(len(payload), len(payload))
        return destination

    runtime = runtime or FakeRuntime()
    router = router or ModelRouter([])
    manager = LocalModelManager(
        tmp_path / "model-state",
        runtime=runtime,
        router=router,
        catalog=tuple(specs),
        hardware_provider=lambda _path: hardware(ram_gib),
        downloader=downloader,
    )
    return manager, runtime, router


def wait_operation(manager, expected: str, timeout: float = 5.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        state = manager.public_state()["manager"]["operation"]["status"]
        if state == expected:
            return manager.public_state()["manager"]
        if state == "failed" and expected != "failed":
            pytest.fail(f"model operation failed: {manager.public_state()['manager']['operation']}")
        time.sleep(0.01)
    pytest.fail(f"timed out waiting for {expected}: {manager.public_state()['manager']}")


def test_models_download_verify_install_activate_switch_and_restore(tmp_path):
    payloads = {"small.gguf": b"small-model-bits", "next.gguf": b"second-model-bits"}
    specs = [make_spec(name.removesuffix(".gguf"), data) for name, data in payloads.items()]
    manager, runtime, router = make_manager(tmp_path, specs, payloads)
    assert manager.public_state()["manager"]["operation"]["status"] == "idle"

    for spec in specs:
        state = manager.install(spec.model_id)
        assert state["manager"]["operation"]["status"] in {"downloading", "verifying", "complete"}
        wait_operation(manager, "complete")
        row = next(item for item in manager.public_state()["models"] if item["model_id"] == spec.model_id)
        assert row["installed"] is True
        assert row["installed_sha256"] == hashlib.sha256(payloads[spec.filename]).hexdigest()

    manager.activate(specs[0].model_id)
    wait_operation(manager, "complete")
    assert runtime.active == specs[0].model_id
    assert [item.name for item in router.providers] == ["fake_local"]

    manager.activate(specs[1].model_id)
    state = wait_operation(manager, "complete")
    assert runtime.active == specs[1].model_id
    assert state["active_model_id"] == specs[1].model_id
    assert runtime.started[-2:] == [specs[0].model_id, specs[1].model_id]
    active_row = next(item for item in manager.public_state()["models"] if item["model_id"] == specs[1].model_id)
    assert active_row["active"] is True
    assert active_row["selected"] is True

    restarted_runtime = FakeRuntime()
    restarted = LocalModelManager(
        tmp_path / "model-state",
        runtime=restarted_runtime,
        router=ModelRouter([]),
        catalog=tuple(specs),
        hardware_provider=lambda _path: hardware(),
        downloader=lambda *_args, **_kwargs: pytest.fail("restore must not download"),
    )
    assert restarted.public_state()["manager"]["active_model_id"] == specs[1].model_id
    restarted_row = next(item for item in restarted.public_state()["models"] if item["model_id"] == specs[1].model_id)
    assert restarted_row["active"] is False
    assert restarted_row["selected"] is True
    assert restarted_row["installed"] is True
    assert restarted_row["installed_sha256"] == specs[1].sha256
    restarted.restore_active()
    restored = wait_operation(restarted, "complete")
    assert restored["runtime"]["status"] == "ready"
    assert restarted_runtime.active == specs[1].model_id
    restored_row = next(item for item in restarted.public_state()["models"] if item["model_id"] == specs[1].model_id)
    assert restored_row["active"] is True
    assert restored_row["selected"] is True
    assert restored_row["installed_sha256"] == specs[1].sha256


def test_install_directory_creation_failure_is_recorded_and_cleaned_up(tmp_path):
    payload = b"model-bits"
    spec = make_spec("blocked", payload)
    manager, _runtime, _router = make_manager(tmp_path, [spec], {spec.filename: payload})
    model_directory = manager.models_root / spec.model_id
    model_directory.write_bytes(b"not-a-directory")

    manager.install(spec.model_id)
    operation = wait_operation(manager, "failed")["operation"]
    manager._operation_thread.join(timeout=5)

    assert operation["error"] == "FileExistsError"
    assert not manager._operation_thread.is_alive()
    assert manager._download_cancel_event is None


def test_install_rechecks_catalog_sha_before_treating_model_as_installed(tmp_path):
    payload = b"trusted model bytes"
    spec = make_spec("integrity", payload)
    manager, _runtime, _router = make_manager(tmp_path, [spec], {spec.filename: payload})
    original_downloader = manager._downloader
    download_count = 0

    def tracked_downloader(*args, **kwargs):
        nonlocal download_count
        download_count += 1
        return original_downloader(*args, **kwargs)

    manager._downloader = tracked_downloader
    manager.install(spec.model_id)
    wait_operation(manager, "complete")
    model_path = manager.models_root / spec.model_id / spec.filename
    model_path.write_bytes(b"x" * spec.size_bytes)

    # A positive cache without a verified digest must be re-hashed for display.
    stat = model_path.stat()
    fingerprint = (
        spec.sha256,
        spec.size_bytes,
        stat.st_dev,
        stat.st_ino,
        stat.st_size,
        stat.st_mtime_ns,
        stat.st_ctime_ns,
    )
    manager._display_integrity_cache[spec.model_id] = (fingerprint, True, None)

    row = next(item for item in manager.public_state()["models"] if item["model_id"] == spec.model_id)
    assert row["installed"] is False
    assert row["installed_sha256"] is None
    manager.install(spec.model_id)
    wait_operation(manager, "complete")

    assert download_count == 2
    assert model_path.read_bytes() == payload


def test_public_state_hashes_unchanged_installed_model_once(tmp_path, monkeypatch):
    payload = b"stable model bytes"
    spec = make_spec("polling", payload)
    manager, _runtime, _router = make_manager(tmp_path, [spec], {spec.filename: payload})
    manager.install(spec.model_id)
    wait_operation(manager, "complete")

    manager._display_integrity_cache.clear()
    original_hash = manager_module._hash_file
    hash_calls = 0

    def tracked_hash(*args, **kwargs):
        nonlocal hash_calls
        hash_calls += 1
        return original_hash(*args, **kwargs)

    monkeypatch.setattr(manager_module, "_hash_file", tracked_hash)
    for _ in range(6):
        row = next(item for item in manager.public_state()["models"] if item["model_id"] == spec.model_id)
        assert row["installed"] is True
        assert row["installed_sha256"] == hashlib.sha256(payload).hexdigest()

    assert hash_calls == 1


@pytest.mark.parametrize(
    "tampered,cached_fields,expected_installed",
    [
        (False, (True,), True),
        (False, (True, None), True),
        (False, (True, "0" * 64), True),
        (True, (True,), False),
        (True, (True, None), False),
        (True, (True, "0" * 64), False),
    ],
)
def test_positive_legacy_or_malformed_integrity_cache_rehashes_artifact(
    tmp_path, monkeypatch, tampered, cached_fields, expected_installed
):
    payload = b"verified cache fixture"
    spec = make_spec("cache-rehash", payload)
    manager, _runtime, _router = make_manager(tmp_path, [spec], {spec.filename: payload})
    manager.install(spec.model_id)
    wait_operation(manager, "complete")
    model_path = manager._model_path(spec)
    if tampered:
        model_path.write_bytes(b"x" * len(payload))

    stat = model_path.stat()
    fingerprint = (
        spec.sha256,
        spec.size_bytes,
        stat.st_dev,
        stat.st_ino,
        stat.st_size,
        stat.st_mtime_ns,
        stat.st_ctime_ns,
    )
    manager._display_integrity_cache[spec.model_id] = (fingerprint, *cached_fields)

    original_hash = manager_module._hash_file
    hash_calls = 0

    def tracked_hash(path):
        nonlocal hash_calls
        hash_calls += 1
        return original_hash(path)

    monkeypatch.setattr(manager_module, "_hash_file", tracked_hash)
    row = next(item for item in manager.public_state()["models"] if item["model_id"] == spec.model_id)

    expected_digest = hashlib.sha256(payload).hexdigest() if expected_installed else None
    assert hash_calls == 1
    assert row["installed"] is expected_installed
    assert row["installed_sha256"] == expected_digest


def test_public_state_exposes_installed_sha_only_for_a_verified_complete_artifact(tmp_path):
    payload = b"complete pinned model artifact"
    spec = make_spec("verified-digest", payload)
    manager, _runtime, _router = make_manager(tmp_path, [spec], {spec.filename: payload})

    def model_row():
        return next(item for item in manager.public_state()["models"] if item["model_id"] == spec.model_id)

    row = model_row()
    assert row["installed"] is False
    assert row["installed_sha256"] is None

    partial_path = manager._model_path(spec).with_name(spec.filename + ".part")
    partial_path.parent.mkdir(parents=True, exist_ok=True)
    partial_path.write_bytes(payload[:8])
    row = model_row()
    assert row["installed"] is False
    assert row["installed_sha256"] is None

    manager.install(spec.model_id)
    wait_operation(manager, "complete")
    model_path = manager._model_path(spec)
    row = model_row()
    assert row["installed"] is True
    assert row["installed_sha256"] == hashlib.sha256(model_path.read_bytes()).hexdigest()

    model_path.write_bytes(b"x" * spec.size_bytes)
    row = model_row()
    assert row["installed"] is False
    assert row["installed_sha256"] is None

    manager._manifest_path(spec).unlink()
    row = model_row()
    assert row["installed"] is False
    assert row["installed_sha256"] is None

    model_path.unlink()
    row = model_row()
    assert row["installed"] is False
    assert row["installed_sha256"] is None


@pytest.mark.parametrize(
    "runtime_status,runtime_model_id,provider_model_id,expected_active",
    [
        ("stopped", "selected", "selected", False),
        ("starting", "selected", "selected", False),
        ("stopping", "selected", "selected", False),
        ("ready", "other", "other", False),
        ("ready", "selected", "other", False),
        ("ready", "selected", "selected", True),
    ],
)
def test_model_row_active_requires_ready_runtime_with_matching_identity(
    tmp_path, runtime_status, runtime_model_id, provider_model_id, expected_active
):
    payload = b"active model identity"
    spec = make_spec("selected", payload)
    manager, _runtime, _router = make_manager(tmp_path, [spec], {spec.filename: payload})
    manager.install(spec.model_id)
    wait_operation(manager, "complete")

    manager._state["active_model_id"] = spec.model_id
    manager._state["runtime"] = {
        "status": runtime_status,
        "model_id": runtime_model_id,
        "error": "",
    }
    manager._active_provider = SimpleNamespace(model=provider_model_id)

    row = next(item for item in manager.public_state()["models"] if item["model_id"] == spec.model_id)
    assert row["selected"] is True
    assert row["active"] is expected_active


def test_failed_runtime_switch_restores_previous_model(tmp_path):
    payloads = {"safe.gguf": b"safe", "broken.gguf": b"broken"}
    specs = [make_spec(name.removesuffix(".gguf"), data) for name, data in payloads.items()]
    runtime = FakeRuntime(fail_for="broken")
    manager, runtime, _router = make_manager(tmp_path, specs, payloads, runtime=runtime)
    for spec in specs:
        manager.install(spec.model_id)
        wait_operation(manager, "complete")
    manager.activate("safe")
    wait_operation(manager, "complete")
    manager.activate("broken")
    state = wait_operation(manager, "failed")
    assert state["active_model_id"] == "safe"
    assert state["runtime"]["status"] == "ready"
    assert runtime.active == "safe"


def test_manager_rejects_models_incompatible_with_available_ram(tmp_path):
    payloads = {"large.gguf": b"model"}
    spec = ModelSpec(
        **{**make_spec("large", b"model").__dict__, "min_ram_gib": 12, "recommended_ram_gib": 16}
    )
    manager, _runtime, _router = make_manager(tmp_path, [spec], payloads, ram_gib=4)
    with pytest.raises(ValueError, match="model_not_compatible:insufficient_system_memory"):
        manager.install("large")
    with pytest.raises(ValueError, match="model_not_compatible:insufficient_system_memory"):
        manager.activate("large")


def test_activation_rechecks_file_hash_and_removes_invalid_manifest(tmp_path, monkeypatch):
    payloads = {"guarded.gguf": b"expected model"}
    spec = make_spec("guarded", payloads["guarded.gguf"])
    manager, runtime, _router = make_manager(tmp_path, [spec], payloads)
    manager.install(spec.model_id)
    wait_operation(manager, "complete")
    model_path = manager.models_root / spec.model_id / spec.filename
    original_hash = manager_module._hash_file
    hash_calls = 0

    def tracked_hash(*args, **kwargs):
        nonlocal hash_calls
        hash_calls += 1
        return original_hash(*args, **kwargs)

    manager._display_integrity_cache.clear()
    monkeypatch.setattr(manager_module, "_hash_file", tracked_hash)
    assert next(item for item in manager.public_state()["models"] if item["model_id"] == spec.model_id)["installed"]
    model_path.write_bytes(b"x" * spec.size_bytes)
    assert model_path.stat().st_size == spec.size_bytes
    assert next(item for item in manager.public_state()["models"] if item["model_id"] == spec.model_id)["installed"] is False
    manager.activate(spec.model_id)
    state = wait_operation(manager, "failed")
    assert state["runtime"]["status"] == "error"
    assert not (manager.models_root / spec.model_id / "manifest.json").exists()
    assert runtime.started == []
    assert hash_calls >= 3  # display validation before/after tampering and fresh activation verification
    row = next(item for item in manager.public_state()["models"] if item["model_id"] == spec.model_id)
    assert row["installed"] is False
    assert row["installed_sha256"] is None
    assert row["active"] is False


def test_partial_model_artifact_is_never_activated(tmp_path):
    payload = b"expected complete model payload"
    spec = make_spec("partial", payload)
    manager, runtime, _router = make_manager(tmp_path, [spec], {spec.filename: payload})
    partial_path = manager._model_path(spec).with_name(spec.filename + ".part")
    partial_path.parent.mkdir(parents=True, exist_ok=True)
    partial_path.write_bytes(payload[:8])

    with pytest.raises(FileNotFoundError, match="model_not_installed"):
        manager.activate(spec.model_id)

    assert runtime.started == []
    assert partial_path.read_bytes() == payload[:8]
    assert next(item for item in manager.public_state()["models"] if item["model_id"] == spec.model_id)["installed"] is False


class FakeLocalInferenceProvider:
    name = "local_llama_cpp"

    def __init__(self, *, failure: str = ""):
        self.model = ""
        self.failure = failure
        self.calls = 0
        self.last_kwargs = {}

    def generate(self, messages, **kwargs):
        self.calls += 1
        self.last_kwargs = kwargs
        assert messages[-1]["content"] == "Reply with the single word CYBERSENTINEL_LOCAL_OK."
        if self.failure:
            raise RuntimeError(self.failure)
        return SimpleNamespace(
            text="CYBERSENTINEL_LOCAL_OK",
            provider=self.name,
            model=self.model,
        )


class FakeLocalInferenceRuntime(FakeRuntime):
    def __init__(self, provider):
        super().__init__()
        self.provider = provider

    def start(self, spec, model_path: Path):
        super().start(spec, model_path)
        self.provider.model = spec.model_id
        return self.provider


class FakeExternalProvider:
    name = "remote-provider"
    model = "remote-model"

    def __init__(self):
        self.calls = 0

    def generate(self, *_args, **_kwargs):
        self.calls += 1
        raise AssertionError("local inference tests must not fall back to an external provider")


def test_local_inference_uses_active_provider_and_stop_restores_external_router(tmp_path):
    payload = b"model-bits"
    spec = make_spec("local", payload)
    local_provider = FakeLocalInferenceProvider()
    runtime = FakeLocalInferenceRuntime(local_provider)
    external_provider = FakeExternalProvider()
    manager, runtime, router = make_manager(
        tmp_path,
        [spec],
        {spec.filename: payload},
        runtime=runtime,
        router=ModelRouter([external_provider]),
    )
    manager.install(spec.model_id)
    wait_operation(manager, "complete")
    manager.activate(spec.model_id)
    wait_operation(manager, "complete")

    result = manager.test_inference()
    assert result == {
        "ok": True,
        "real_inference": True,
        "provider": "local_llama_cpp",
        "model": spec.model_id,
        "response": "CYBERSENTINEL_LOCAL_OK",
    }
    assert local_provider.calls == 1
    assert external_provider.calls == 0
    assert manager.public_state()["manager"]["operation"]["result"] == "CYBERSENTINEL_LOCAL_OK"

    manager.deactivate()
    state = wait_operation(manager, "complete")
    assert state["active_model_id"] == ""
    assert state["runtime"]["status"] == "stopped"
    assert runtime.active == ""
    assert router.providers == [external_provider]
    with pytest.raises(RuntimeError, match="local_runtime_not_ready"):
        manager.test_inference()


def test_qwen3_local_smoke_disables_thinking_with_bounded_completion(tmp_path):
    """Control-plane contract test; actual Qwen inference is tested by the opt-in harness."""
    payload = b"qwen3-model-bits"
    spec = make_spec("qwen3-4b-q4-k-m", payload)
    local_provider = FakeLocalInferenceProvider()
    manager, _runtime, _router = make_manager(
        tmp_path,
        [spec],
        {spec.filename: payload},
        runtime=FakeLocalInferenceRuntime(local_provider),
    )
    manager.install(spec.model_id)
    wait_operation(manager, "complete")
    manager.activate(spec.model_id)
    wait_operation(manager, "complete")

    manager.test_inference()

    assert local_provider.last_kwargs == {
        "temperature": 0,
        "timeout": 90,
        "max_tokens": 64,
        "chat_template_kwargs": {"enable_thinking": False},
    }


def test_local_inference_failure_is_visible_and_never_falls_back(tmp_path):
    payload = b"model-bits"
    spec = make_spec("local", payload)
    local_provider = FakeLocalInferenceProvider(failure="local_model_timeout")
    runtime = FakeLocalInferenceRuntime(local_provider)
    external_provider = FakeExternalProvider()
    manager, _runtime, _router = make_manager(
        tmp_path,
        [spec],
        {spec.filename: payload},
        runtime=runtime,
        router=ModelRouter([external_provider]),
    )
    manager.install(spec.model_id)
    wait_operation(manager, "complete")
    manager.activate(spec.model_id)
    wait_operation(manager, "complete")

    with pytest.raises(RuntimeError, match="local_inference_failed:local_model_timeout"):
        manager.test_inference()
    state = manager.public_state()
    assert state["manager"]["operation"]["status"] == "failed"
    # The request timed out, but the manager still has a ready, matching runtime.
    assert state["manager"]["runtime"]["status"] == "ready"
    assert state["manager"]["runtime"]["model_id"] == spec.model_id
    row = next(item for item in state["models"] if item["model_id"] == spec.model_id)
    assert row["active"] is True
    assert row["selected"] is True
    assert local_provider.calls == 1
    assert external_provider.calls == 0


def test_cancel_download_keeps_partial_file_uninstalled_and_reports_cancelled(tmp_path):
    import threading

    from agent.local_runtime.downloader import DownloadCancelled

    payload = b"a verified test model payload"
    spec = make_spec("cancel-me", payload)
    entered = threading.Event()

    def cancelable_downloader(_url, destination, *, expected_size, expected_sha256, progress=None, cancel_event=None):
        assert cancel_event is not None
        destination.parent.mkdir(parents=True, exist_ok=True)
        partial = destination.with_name(destination.name + ".part")
        partial.write_bytes(payload[:7])
        entered.set()
        while not cancel_event.wait(0.01):
            pass
        raise DownloadCancelled("download_cancelled")

    manager = LocalModelManager(
        tmp_path / "cancel-state",
        runtime=FakeRuntime(),
        router=ModelRouter([]),
        catalog=(spec,),
        hardware_provider=lambda _path: hardware(),
        downloader=cancelable_downloader,
    )
    manager.install(spec.model_id)
    assert entered.wait(2)
    state = manager.cancel_download(spec.model_id)
    assert state["manager"]["operation"]["status"] in {"cancelling", "cancelled"}
    final = wait_operation(manager, "cancelled")
    model_path = manager.models_root / spec.model_id / spec.filename
    assert model_path.with_name(model_path.name + ".part").read_bytes() == payload[:7]
    assert model_path.exists() is False
    assert (manager.models_root / spec.model_id / "manifest.json").exists() is False
    assert final["operation"]["error"] == "download_cancelled"


def test_non_top_three_pinned_candidate_remains_in_full_manager_catalog(tmp_path):
    import hashlib
    from dataclasses import replace

    from agent.local_runtime.catalog import MODEL_CATALOG

    payload = b"user-selected-curated-model"
    extra = replace(
        MODEL_CATALOG[0],
        model_id="extra-curated-model",
        family="Extra",
        display_name="Extra eligible model",
        parameter_size="1B",
        repository="tests/pinned-fixture",
        revision="b" * 40,
        filename="extra-curated-model.gguf",
        size_bytes=len(payload),
        sha256=hashlib.sha256(payload).hexdigest(),
        min_ram_gib=1,
        recommended_ram_gib=1000,
        min_cpu_cores=64,
        context_length=1,
        capability_evidence_url="",
        advisor_capabilities=(),
    )
    payloads = {extra.filename: payload}
    manager, _runtime, _router = make_manager(tmp_path, (*MODEL_CATALOG, extra), payloads, ram_gib=64)
    state = manager.public_state()
    rows = {item["model_id"]: item for item in state["models"]}
    top_ids = {item["model_id"] for item in state["advisor"]["recommendations"]}
    assert extra.model_id in rows
    assert rows[extra.model_id]["compatible"] is True
    assert extra.model_id not in top_ids

    started = manager.install(extra.model_id)
    assert started["manager"]["operation"]["kind"] == "install"
    assert wait_operation(manager, "complete")["operation"]["model_id"] == extra.model_id
