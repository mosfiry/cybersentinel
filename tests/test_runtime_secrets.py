from __future__ import annotations

from pathlib import Path

import pytest

from agent.model_router import ModelRouter
from security.runtime_secrets import secret_env


def test_secret_env_uses_direct_value_for_legacy_host_runtime(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("CS_TEST_SECRET", "  legacy-value  ")
    monkeypatch.delenv("CS_TEST_SECRET_FILE", raising=False)

    assert secret_env("CS_TEST_SECRET") == "legacy-value"


def test_secret_env_uses_default_when_unset(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("CS_TEST_SECRET", raising=False)
    monkeypatch.delenv("CS_TEST_SECRET_FILE", raising=False)

    assert secret_env("CS_TEST_SECRET", "default") == "default"


def test_secret_env_reads_a_regular_file_and_strips_trailing_newline(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    secret_file = tmp_path / "provider-key"
    secret_file.write_text("  file-value\n", encoding="utf-8")
    monkeypatch.delenv("CS_TEST_SECRET", raising=False)
    monkeypatch.setenv("CS_TEST_SECRET_FILE", str(secret_file))

    assert secret_env("CS_TEST_SECRET") == "file-value"


def test_secret_env_rejects_ambiguous_direct_and_file_sources(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    secret_file = tmp_path / "provider-key"
    secret_file.write_text("file-value", encoding="utf-8")
    monkeypatch.setenv("CS_TEST_SECRET", "direct-value")
    monkeypatch.setenv("CS_TEST_SECRET_FILE", str(secret_file))

    with pytest.raises(RuntimeError, match="either CS_TEST_SECRET or CS_TEST_SECRET_FILE"):
        secret_env("CS_TEST_SECRET")


def test_secret_env_rejects_symlinked_files(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = tmp_path / "target"
    target.write_text("file-value", encoding="utf-8")
    secret_link = tmp_path / "secret-link"
    secret_link.symlink_to(target)
    monkeypatch.delenv("CS_TEST_SECRET", raising=False)
    monkeypatch.setenv("CS_TEST_SECRET_FILE", str(secret_link))

    with pytest.raises(RuntimeError, match="could not be opened safely"):
        secret_env("CS_TEST_SECRET")


def test_secret_env_rejects_non_regular_files(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("CS_TEST_SECRET", raising=False)
    monkeypatch.setenv("CS_TEST_SECRET_FILE", str(tmp_path))

    with pytest.raises(RuntimeError, match="regular file"):
        secret_env("CS_TEST_SECRET")


def test_secret_env_rejects_oversized_files(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    secret_file = tmp_path / "oversized"
    secret_file.write_bytes(b"x" * (16 * 1024 + 1))
    monkeypatch.delenv("CS_TEST_SECRET", raising=False)
    monkeypatch.setenv("CS_TEST_SECRET_FILE", str(secret_file))

    with pytest.raises(RuntimeError, match="maximum allowed size"):
        secret_env("CS_TEST_SECRET")


def test_secret_env_rejects_non_utf8_file_contents(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    secret_file = tmp_path / "non-utf8"
    secret_file.write_bytes(b"\xff")
    monkeypatch.delenv("CS_TEST_SECRET", raising=False)
    monkeypatch.setenv("CS_TEST_SECRET_FILE", str(secret_file))

    with pytest.raises(RuntimeError, match="UTF-8"):
        secret_env("CS_TEST_SECRET")


def test_secret_env_requires_a_nonempty_file_reference(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("CS_TEST_SECRET", raising=False)
    monkeypatch.setenv("CS_TEST_SECRET_FILE", "")

    with pytest.raises(RuntimeError, match="must identify a secret file"):
        secret_env("CS_TEST_SECRET")


def test_model_router_loads_provider_api_key_from_secret_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    secret_file = tmp_path / "provider-key"
    secret_file.write_text("provider-test-secret-value\n", encoding="utf-8")
    for name in (
        "LLM_BASE_URL",
        "LLM_MODEL",
        "LLM_API_KEY",
        "LLM_API_KEY_FILE",
        "LOCAL_LLM_API_KEY",
        "LOCAL_LLM_API_KEY_FILE",
        "COLAB_LLM_BASE_URL",
        "COLAB_LLM_MODEL",
        "COLAB_LLM_API_KEY",
        "COLAB_LLM_API_KEY_FILE",
        "HF_LLM_BASE_URL",
        "HF_LLM_MODEL",
        "HF_LLM_API_KEY",
        "HF_LLM_API_KEY_FILE",
    ):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("LOCAL_LLM_BASE_URL", "https://provider.invalid/v1")
    monkeypatch.setenv("LOCAL_LLM_MODEL", "test-model")
    monkeypatch.setenv("LOCAL_LLM_API_KEY_FILE", str(secret_file))

    router = ModelRouter.from_env()

    assert len(router.providers) == 1
    assert router.providers[0].name == "local"
    assert router.providers[0].api_key == "provider-test-secret-value"
