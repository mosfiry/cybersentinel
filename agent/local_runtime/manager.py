from __future__ import annotations

import json
import os
import tempfile
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from agent.model_router import ModelRouter
from agent.provider_api import ProviderError

from .catalog import CATALOG_VERSION, MODEL_CATALOG, ModelSpec, get_model
from .downloader import DownloadError, _hash_file, download_verified_file
from .hardware import assess_compatibility, detect_hardware
from .runtime import RuntimeAdapter

_BUSY_OPERATION_STATUSES = frozenset({"downloading", "verifying", "activating", "testing", "stopping"})


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


class LocalModelManager:
    """Durable catalog, installer, integrity verifier, and local-runtime switcher."""

    def __init__(
        self,
        storage_root: str | Path,
        *,
        runtime: RuntimeAdapter,
        router: ModelRouter,
        catalog: tuple[ModelSpec, ...] = MODEL_CATALOG,
        hardware_provider: Callable[[str | Path], dict[str, Any]] = detect_hardware,
        downloader: Callable[..., Path] = download_verified_file,
    ):
        self.storage_root = Path(storage_root).expanduser().resolve()
        self.models_root = self.storage_root / "models"
        self.models_root.mkdir(parents=True, exist_ok=True)
        self._state_file = self.storage_root / "manager-state.json"
        self._runtime = runtime
        self._router = router
        self._external_providers = list(router.providers)
        self._catalog = tuple(catalog)
        self._by_id = {item.model_id: item for item in self._catalog}
        self._hardware_provider = hardware_provider
        self._downloader = downloader
        self._lock = threading.RLock()
        self._operation_thread: threading.Thread | None = None
        self._active_provider: Any | None = None
        self._state: dict[str, Any] = {
            "active_model_id": "",
            "runtime": {"status": "stopped", "model_id": "", "error": ""},
            "operation": {"kind": "", "model_id": "", "status": "idle", "bytes_downloaded": 0, "total_bytes": 0, "progress": 0, "error": "", "result": ""},
            "updated_at": _utc_now(),
        }
        self._load_state()
        if self._state["operation"].get("status") in _BUSY_OPERATION_STATUSES:
            self._state["operation"].update(status="interrupted", error="application_restarted")
            self._save_locked()

    def _load_state(self) -> None:
        try:
            loaded = json.loads(self._state_file.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError, TypeError):
            return
        if not isinstance(loaded, dict):
            return
        active = str(loaded.get("active_model_id", ""))
        if active and active not in self._by_id:
            active = ""
        runtime = loaded.get("runtime") if isinstance(loaded.get("runtime"), dict) else {}
        operation = loaded.get("operation") if isinstance(loaded.get("operation"), dict) else {}
        self._state.update(
            active_model_id=active,
            runtime={"status": "stopped", "model_id": active, "error": ""},
            operation={
                "kind": str(operation.get("kind", "")),
                "model_id": str(operation.get("model_id", "")),
                "status": str(operation.get("status", "idle")),
                "bytes_downloaded": max(0, int(operation.get("bytes_downloaded", 0) or 0)),
                "total_bytes": max(0, int(operation.get("total_bytes", 0) or 0)),
                "progress": max(0, min(100, int(operation.get("progress", 0) or 0))),
                "error": str(operation.get("error", "")),
                "result": str(operation.get("result", ""))[:1000],
            },
            updated_at=str(loaded.get("updated_at", _utc_now())),
        )

    def _save_locked(self) -> None:
        self.storage_root.mkdir(parents=True, exist_ok=True)
        self._state["updated_at"] = _utc_now()
        fd, temporary_name = tempfile.mkstemp(prefix=".manager-state-", suffix=".tmp", dir=self.storage_root)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as stream:
                json.dump(self._state, stream, ensure_ascii=False, sort_keys=True)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary_name, self._state_file)
        finally:
            try:
                os.unlink(temporary_name)
            except FileNotFoundError:
                pass

    def _spec(self, model_id: str) -> ModelSpec:
        try:
            return self._by_id[str(model_id)]
        except KeyError as exc:
            raise KeyError("unknown_model") from exc

    def _model_directory(self, spec: ModelSpec) -> Path:
        return self.models_root / spec.model_id

    def _model_path(self, spec: ModelSpec) -> Path:
        return self._model_directory(spec) / spec.filename

    def _manifest_path(self, spec: ModelSpec) -> Path:
        return self._model_directory(spec) / "manifest.json"

    def _installed_by_metadata(self, spec: ModelSpec) -> bool:
        model_path = self._model_path(spec)
        manifest_path = self._manifest_path(spec)
        try:
            if model_path.is_symlink() or manifest_path.is_symlink():
                return False
            if model_path.stat().st_size != spec.size_bytes:
                return False
            metadata = json.loads(manifest_path.read_text(encoding="utf-8"))
            return (
                metadata.get("model_id") == spec.model_id
                and metadata.get("revision") == spec.revision
                and metadata.get("sha256") == spec.sha256
                and metadata.get("size_bytes") == spec.size_bytes
                and metadata.get("verified") is True
            )
        except (OSError, json.JSONDecodeError, AttributeError):
            return False

    def _verify_installed(self, spec: ModelSpec) -> Path:
        path = self._model_path(spec)
        if not self._installed_by_metadata(spec):
            raise FileNotFoundError("model_not_installed_or_manifest_invalid")
        if _hash_file(path) != spec.sha256:
            self._manifest_path(spec).unlink(missing_ok=True)
            raise DownloadError("installed_model_integrity_check_failed")
        return path

    def _hardware(self) -> dict[str, Any]:
        return self._hardware_provider(self.models_root)

    def _catalog_rows(self, hardware: dict[str, Any]) -> list[dict[str, Any]]:
        rows = []
        for spec in self._catalog:
            compatibility = assess_compatibility(spec, hardware)
            rows.append({
                **spec.public(),
                "compatible": compatibility["compatible"],
                "recommended": compatibility["recommended"],
                "too_large": compatibility["too_large"],
                "compatibility_reasons": compatibility["reasons"],
                "warnings": compatibility["warnings"],
                "required_disk_bytes": compatibility["required_disk_bytes"],
                "installed": self._installed_by_metadata(spec),
                "active": self._state.get("active_model_id") == spec.model_id,
            })
        return rows

    def public_state(self, hardware: dict[str, Any] | None = None) -> dict[str, Any]:
        hardware = hardware if hardware is not None else self._hardware()
        with self._lock:
            return {
                "ok": True,
                "catalog_version": CATALOG_VERSION,
                "catalog_source": "bundled-pinned-manifest",
                "hardware": hardware,
                "models": self._catalog_rows(hardware),
                "manager": json.loads(json.dumps(self._state)),
            }

    def _begin_operation(self, kind: str, spec: ModelSpec, status: str, *, total: int = 0) -> None:
        with self._lock:
            current = self._state["operation"]
            if self._operation_thread is not None and self._operation_thread.is_alive():
                raise RuntimeError("model_manager_busy")
            if current.get("status") in _BUSY_OPERATION_STATUSES:
                raise RuntimeError("model_manager_busy")
            self._state["operation"] = {
                "kind": kind,
                "model_id": spec.model_id,
                "status": status,
                "bytes_downloaded": 0,
                "total_bytes": total,
                "progress": 0,
                "error": "",
                "result": "",
            }
            self._save_locked()

    def install(self, model_id: str) -> dict[str, Any]:
        spec = self._spec(model_id)
        hardware = self._hardware()
        compatibility = assess_compatibility(spec, hardware)
        if not compatibility["compatible"]:
            raise ValueError("model_not_compatible:" + ",".join(compatibility["reasons"]))
        if self._installed_by_metadata(spec):
            return self.public_state(hardware)
        self._begin_operation("install", spec, "downloading", total=spec.size_bytes)
        thread = threading.Thread(target=self._install_worker, args=(spec,), name="model-download", daemon=True)
        self._operation_thread = thread
        thread.start()
        return self.public_state(hardware)

    def _install_worker(self, spec: ModelSpec) -> None:
        destination = self._model_path(spec)
        destination.parent.mkdir(parents=True, exist_ok=True)
        last_update = 0.0

        def on_progress(downloaded: int, total: int) -> None:
            nonlocal last_update
            now = time.monotonic()
            if downloaded < total and now - last_update < 0.4:
                return
            last_update = now
            with self._lock:
                operation = self._state["operation"]
                operation.update(
                    status="downloading",
                    bytes_downloaded=int(downloaded),
                    total_bytes=int(total),
                    progress=max(0, min(100, int(downloaded * 100 / max(1, total)))),
                )
                self._save_locked()

        try:
            path = self._downloader(
                spec.download_url,
                destination,
                expected_size=spec.size_bytes,
                expected_sha256=spec.sha256,
                progress=on_progress,
            )
            with self._lock:
                self._state["operation"].update(status="verifying", progress=99)
                self._save_locked()
            if path.stat().st_size != spec.size_bytes or _hash_file(path) != spec.sha256:
                path.unlink(missing_ok=True)
                raise DownloadError("download_integrity_check_failed")
            metadata = {
                "model_id": spec.model_id,
                "family": spec.family,
                "repository": spec.repository,
                "revision": spec.revision,
                "filename": spec.filename,
                "size_bytes": spec.size_bytes,
                "sha256": spec.sha256,
                "quantization": spec.quantization,
                "license": spec.license,
                "verified": True,
                "verified_at": _utc_now(),
            }
            temporary = self._manifest_path(spec).with_suffix(".tmp")
            temporary.write_text(json.dumps(metadata, ensure_ascii=False, sort_keys=True), encoding="utf-8")
            os.replace(temporary, self._manifest_path(spec))
            with self._lock:
                self._state["operation"].update(
                    status="complete", bytes_downloaded=spec.size_bytes,
                    total_bytes=spec.size_bytes, progress=100, error="",
                )
                self._save_locked()
        except Exception as exc:
            code = str(exc) if isinstance(exc, (DownloadError, ValueError, FileNotFoundError)) else type(exc).__name__
            with self._lock:
                self._state["operation"].update(status="failed", error=code[:160])
                self._save_locked()

    def activate(self, model_id: str) -> dict[str, Any]:
        spec = self._spec(model_id)
        compatibility = assess_compatibility(spec, self._hardware())
        if not compatibility["compatible"]:
            raise ValueError("model_not_compatible:" + ",".join(compatibility["reasons"]))
        if not self._installed_by_metadata(spec):
            raise FileNotFoundError("model_not_installed")
        self._begin_operation("activate", spec, "activating")
        thread = threading.Thread(target=self._activate_worker, args=(spec,), name="model-activation", daemon=True)
        self._operation_thread = thread
        thread.start()
        return self.public_state()

    def _activate_worker(self, spec: ModelSpec) -> None:
        with self._lock:
            previous_id = str(self._state.get("active_model_id", ""))
            self._state["runtime"] = {"status": "starting", "model_id": spec.model_id, "error": ""}
            self._save_locked()
        try:
            model_path = self._verify_installed(spec)
            self._runtime.stop()
            self._active_provider = None
            self._router.providers = list(self._external_providers)
            provider = self._runtime.start(spec, model_path)
            self._router.providers = [provider]
            self._active_provider = provider
            with self._lock:
                self._state["active_model_id"] = spec.model_id
                self._state["runtime"] = {"status": "ready", "model_id": spec.model_id, "error": ""}
                self._state["operation"].update(status="complete", progress=100, error="")
                self._save_locked()
        except Exception as exc:
            try:
                self._runtime.stop()
            except Exception:
                pass
            restored = False
            restored_provider = None
            if previous_id and previous_id != spec.model_id and previous_id in self._by_id:
                try:
                    previous_spec = self._by_id[previous_id]
                    previous_path = self._verify_installed(previous_spec)
                    restored_provider = self._runtime.start(previous_spec, previous_path)
                    self._router.providers = [restored_provider]
                    restored = True
                except Exception:
                    restored = False
            if not restored:
                self._router.providers = list(self._external_providers)
            self._active_provider = restored_provider if restored else None
            code = str(exc) if isinstance(exc, (DownloadError, FileNotFoundError, ValueError)) else type(exc).__name__
            with self._lock:
                if not restored:
                    self._state["active_model_id"] = ""
                self._state["runtime"] = {
                    "status": "ready" if restored else "error",
                    "model_id": previous_id if restored else "",
                    "error": "" if restored else code[:160],
                }
                self._state["operation"].update(status="failed", error=code[:160])
                self._save_locked()

    def test_inference(self) -> dict[str, Any]:
        """Call only the activated local provider; never route to a fallback."""
        with self._lock:
            model_id = str(self._state.get("active_model_id", ""))
            provider = self._active_provider
            if (
                not model_id
                or self._state.get("runtime", {}).get("status") != "ready"
                or provider is None
            ):
                raise RuntimeError("local_runtime_not_ready")
            spec = self._spec(model_id)
            if getattr(provider, "name", "") != "local_llama_cpp" or getattr(provider, "model", "") != model_id:
                raise RuntimeError("local_runtime_provider_identity_mismatch")
            self._begin_operation("inference_test", spec, "testing")

        try:
            generation_options: dict[str, Any] = {
                "temperature": 0,
                "timeout": 90,
                "max_tokens": 64,
            }
            if spec.model_id.startswith("qwen3-"):
                # Qwen3 defaults to a reasoning channel; tiny smoke-test token
                # limits can end before the user-facing content is produced.
                generation_options["chat_template_kwargs"] = {"enable_thinking": False}
            response = provider.generate(
                [
                    {"role": "system", "content": "Follow the user request exactly and answer briefly."},
                    {"role": "user", "content": "Reply with the single word CYBERSENTINEL_LOCAL_OK."},
                ],
                **generation_options,
            )
            text = str(getattr(response, "text", "") or "").strip()
            if not text:
                raise RuntimeError("local_inference_empty_response")
            response_provider = str(getattr(response, "provider", "") or provider.name)
            response_model = str(getattr(response, "model", "") or provider.model)
            if response_provider != "local_llama_cpp" or response_model != model_id:
                raise RuntimeError("local_inference_identity_mismatch")
        except Exception as exc:
            kind = getattr(exc.kind, "value", "") if isinstance(exc, ProviderError) else ""
            code = str(kind or (str(exc) if isinstance(exc, RuntimeError) else type(exc).__name__))[:160]
            with self._lock:
                self._state["operation"].update(status="failed", error=code, result="")
                self._save_locked()
            raise RuntimeError("local_inference_failed:" + code) from exc

        with self._lock:
            self._state["operation"].update(status="complete", progress=100, error="", result=text[:1000])
            self._save_locked()
        return {
            "ok": True,
            "real_inference": True,
            "provider": response_provider,
            "model": response_model,
            "response": text[:1000],
        }

    def deactivate(self) -> dict[str, Any]:
        with self._lock:
            model_id = str(self._state.get("active_model_id", ""))
            if not model_id:
                return self.public_state()
            spec = self._spec(model_id)
        self._begin_operation("stop", spec, "stopping")
        thread = threading.Thread(
            target=self._deactivate_worker,
            args=(model_id,),
            name="model-stop",
            daemon=True,
        )
        self._operation_thread = thread
        thread.start()
        return self.public_state()

    def _deactivate_worker(self, model_id: str) -> None:
        try:
            self._runtime.stop()
        except Exception as exc:
            code = str(exc)[:160] if isinstance(exc, RuntimeError) else type(exc).__name__
            with self._lock:
                self._state["runtime"] = {"status": "error", "model_id": model_id, "error": code}
                self._state["operation"].update(status="failed", error=code)
                self._save_locked()
            return
        self._router.providers = list(self._external_providers)
        with self._lock:
            self._active_provider = None
            self._state["active_model_id"] = ""
            self._state["runtime"] = {"status": "stopped", "model_id": "", "error": ""}
            self._state["operation"].update(status="complete", progress=100, error="", result="")
            self._save_locked()

    def restore_active(self) -> None:
        with self._lock:
            model_id = str(self._state.get("active_model_id", ""))
            if not model_id or model_id not in self._by_id:
                return
            spec = self._by_id[model_id]
            if not self._installed_by_metadata(spec):
                self._state["active_model_id"] = ""
                self._state["runtime"] = {"status": "error", "model_id": "", "error": "active_model_missing"}
                self._save_locked()
                return
            self._state["runtime"] = {"status": "starting", "model_id": model_id, "error": ""}
            self._state["operation"] = {
                "kind": "activate", "model_id": model_id, "status": "activating",
                "bytes_downloaded": 0, "total_bytes": 0, "progress": 0, "error": "", "result": "",
            }
            self._save_locked()
        thread = threading.Thread(target=self._activate_worker, args=(spec,), name="model-restore", daemon=True)
        self._operation_thread = thread
        thread.start()

    def shutdown(self) -> None:
        try:
            self._runtime.stop()
        finally:
            self._router.providers = list(self._external_providers)
            with self._lock:
                self._active_provider = None
                if self._state["operation"].get("status") in _BUSY_OPERATION_STATUSES:
                    self._state["operation"].update(status="interrupted", error="application_stopped")
                self._state["runtime"] = {
                    "status": "stopped",
                    "model_id": str(self._state.get("active_model_id", "")),
                    "error": "",
                }
                self._save_locked()
