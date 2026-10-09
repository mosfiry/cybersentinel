from __future__ import annotations

import hashlib
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

from agent.local_runtime.catalog import ModelSpec
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

    manager.activate(specs[0].model_id)
    wait_operation(manager, "complete")
    assert runtime.active == specs[0].model_id
    assert [item.name for item in router.providers] == ["fake_local"]

    manager.activate(specs[1].model_id)
    state = wait_operation(manager, "complete")
    assert runtime.active == specs[1].model_id
    assert state["active_model_id"] == specs[1].model_id
    assert runtime.started[-2:] == [specs[0].model_id, specs[1].model_id]

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
    restarted.restore_active()
    restored = wait_operation(restarted, "complete")
    assert restored["runtime"]["status"] == "ready"
    assert restarted_runtime.active == specs[1].model_id


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


def test_activation_rechecks_file_hash_and_removes_invalid_manifest(tmp_path):
    payloads = {"guarded.gguf": b"expected model"}
    spec = make_spec("guarded", payloads["guarded.gguf"])
    manager, _runtime, _router = make_manager(tmp_path, [spec], payloads)
    manager.install(spec.model_id)
    wait_operation(manager, "complete")
    model_path = manager.models_root / spec.model_id / spec.filename
    model_path.write_bytes(b"x" * spec.size_bytes)
    assert model_path.stat().st_size == spec.size_bytes
    manager.activate(spec.model_id)
    state = wait_operation(manager, "failed")
    assert state["runtime"]["status"] == "error"
    assert not (manager.models_root / spec.model_id / "manifest.json").exists()


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
    assert manager.public_state()["manager"]["operation"]["status"] == "failed"
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
