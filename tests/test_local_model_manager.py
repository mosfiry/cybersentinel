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
    def downloader(_url, destination, *, expected_size, expected_sha256, progress=None):
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

    for spec in specs:
        state = manager.install(spec.model_id)
        assert state["manager"]["operation"]["status"] == "downloading"
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
