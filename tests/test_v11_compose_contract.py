from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
COMPOSE = (ROOT / "compose.yaml").read_text(encoding="utf-8")
DOCKERFILE = (ROOT / "Dockerfile").read_text(encoding="utf-8")

SECRET_NAMES = (
    "bridge_token",
    "llm_api_key",
    "local_llm_api_key",
    "colab_llm_api_key",
    "hf_llm_api_key",
)


def test_compose_defines_file_backed_secrets_and_does_not_inline_credentials() -> None:
    for name in SECRET_NAMES:
        assert f'file: "${{CYBERSENTINEL_SECRETS_DIR:-./secrets}}/{name}"' in COMPOSE
        assert f"/run/secrets/{name}" in COMPOSE

    for variable in (
        "BRIDGE_TOKEN",
        "LLM_API_KEY",
        "LOCAL_LLM_API_KEY",
        "COLAB_LLM_API_KEY",
        "HF_LLM_API_KEY",
    ):
        assert re.search(rf"(?m)^\s+{variable}\s*:", COMPOSE) is None
        assert f"{variable}_FILE:" in COMPOSE


def test_compose_preserves_single_host_security_and_recovery_boundaries() -> None:
    assert 'user: "10001:10001"' in COMPOSE
    assert "network_mode: none" in COMPOSE
    assert "driver: bridge" in COMPOSE
    assert 'restart: unless-stopped' in COMPOSE
    assert "stop_grace_period: 330s" in COMPOSE
    assert 'read_only: true' in COMPOSE
    assert 'cap_drop: ["ALL"]' in COMPOSE
    assert 'security_opt: ["no-new-privileges:true"]' in COMPOSE
    assert 'max-size: "10m"' in COMPOSE
    assert 'max-file: "5"' in COMPOSE
    assert '127.0.0.1:${BRIDGE_PUBLISHED_PORT:-8787}:8787' in COMPOSE
    assert "cybersentinel-state:/var/lib/cybersentinel" in COMPOSE
    worker_block = COMPOSE.split("  mission-worker:\n", 1)[1].split("\nnetworks:", 1)[0]
    assert "\n    ports:" not in worker_block


def test_image_is_pinned_to_a_debian_family_and_runs_as_non_root() -> None:
    assert "FROM python:3.12-slim-bookworm" in DOCKERFILE
    assert "COPY --chown=0:0 . /app" in DOCKERFILE
    assert "USER 10001:10001" in DOCKERFILE
    assert "STOPSIGNAL SIGTERM" in DOCKERFILE
    assert "python -m pip check" in DOCKERFILE


def test_local_secret_preparer_is_outside_the_image_and_not_tracked() -> None:
    dockerignore = (ROOT / ".dockerignore").read_text(encoding="utf-8")
    gitignore = (ROOT / ".gitignore").read_text(encoding="utf-8")
    setup_script = ROOT / "scripts" / "prepare_compose_secrets.py"

    assert "scripts/prepare_compose_secrets.py" in dockerignore
    assert "secrets/" in gitignore
    assert setup_script.is_file()
    source = setup_script.read_text(encoding="utf-8")
    assert "os.O_EXCL" in source
    assert "secrets.token_urlsafe(48)" in source
    assert "existing files were preserved" in source


def test_self_hosted_deployment_has_no_cloudflare_or_wrangler_dependency() -> None:
    deployment_files = [
        ROOT / "Dockerfile",
        ROOT / "compose.yaml",
        ROOT / "requirements.txt",
        ROOT / "requirements-runtime.txt",
        *sorted((ROOT / ".github" / "workflows").glob("*.yml")),
    ]
    for path in deployment_files:
        content = path.read_text(encoding="utf-8").lower()
        assert "cloudflare" not in content, path
        assert "wrangler" not in content, path


def test_m3_overlay_does_not_create_conflicting_inline_provider_secrets() -> None:
    overlay = (ROOT / "tests" / "compose.m3-rehearsal.yaml").read_text(encoding="utf-8")
    for variable in (
        "LLM_API_KEY",
        "LOCAL_LLM_API_KEY",
        "COLAB_LLM_API_KEY",
        "HF_LLM_API_KEY",
    ):
        assert re.search(rf"(?m)^\s+{variable}\s*:", overlay) is None


def test_container_ci_secrets_are_permissioned_then_removed() -> None:
    workflow = (ROOT / ".github" / "workflows" / "tests.yml").read_text(encoding="utf-8")
    write_files = workflow.index('(directory / name).write_text')
    files_owner = workflow.index('sudo chown 10001:10001 "$CYBERSENTINEL_SECRETS_DIR"/*')
    files_mode = workflow.index('sudo chmod 0440 "$CYBERSENTINEL_SECRETS_DIR"/*')
    directory_owner = workflow.index('sudo chown root:root "$CYBERSENTINEL_SECRETS_DIR"')
    directory_mode = workflow.index('sudo chmod 0711 "$CYBERSENTINEL_SECRETS_DIR"')
    cleanup = workflow.index('sudo rm -rf -- "$CYBERSENTINEL_SECRETS_DIR"')
    assert write_files < files_owner < files_mode < directory_owner < directory_mode
    assert cleanup < workflow.index("trap cleanup EXIT") < write_files


def test_v12_archive_is_runtime_code_and_legacy_fixture_is_ci_only_readonly() -> None:
    overlay = (ROOT / "tests" / "compose.m3-rehearsal.yaml").read_text(encoding="utf-8")
    dockerignore = (ROOT / ".dockerignore").read_text(encoding="utf-8")
    fixture = ROOT / "tests" / "m3_rehearsal" / "prepare_legacy_state.py"
    initializer = overlay.split("  workspace-init:\n", 1)[1].split("\n  bridge:", 1)[0]

    assert (ROOT / "scripts" / "state_archive.py").is_file()
    assert "tests/" in dockerignore
    assert "- ./tests/m3_rehearsal:/m3-rehearsal:ro" in initializer
    assert "/m3-rehearsal" not in COMPOSE
    assert fixture.is_file()


def test_versioned_runtime_image_and_release_bundle_share_the_version_source() -> None:
    version = (ROOT / "VERSION").read_text(encoding="ascii").strip()
    env_example = (ROOT / ".env.example").read_text(encoding="utf-8")
    from core.version import VERSION

    assert version == VERSION
    assert f"CYBERSENTINEL_VERSION={version}" in env_example
    assert f"CYBERSENTINEL_IMAGE=cybersentinel-runtime:{version}" in env_example
    assert f"${{CYBERSENTINEL_IMAGE:-cybersentinel-runtime:{version}}}" in COMPOSE
    assert f"CYBERSENTINEL_VERSION: ${{CYBERSENTINEL_VERSION:-{version}}}" in COMPOSE
    assert f"ARG CYBERSENTINEL_VERSION={version}" in DOCKERFILE
    assert 'org.opencontainers.image.version="${CYBERSENTINEL_VERSION}"' in DOCKERFILE
    dockerignore = (ROOT / ".dockerignore").read_text(encoding="utf-8")
    for host_only in (
        "scripts/install_compose.sh",
        "scripts/backup_state.sh",
        "scripts/restore_state.sh",
        "scripts/package_release.py",
    ):
        assert host_only in dockerignore


def test_release_artifact_job_is_gated_on_tests_and_rehearsal_and_does_not_publish() -> None:
    workflow = (ROOT / ".github" / "workflows" / "tests.yml").read_text(encoding="utf-8")
    release_job = workflow.split("  release-artifacts:\n", 1)[1]

    assert "needs: [test, m3-nonproduction-rehearsal]" in release_job
    assert "refs/heads/release/cybersentinel-final-20261003" in release_job
    assert "docker save --output" in release_job
    assert "scripts/package_release.py build" in release_job
    assert "scripts/package_release.py verify" in release_job
    assert "actions/upload-artifact@v4" in release_job
    assert "github-release" not in release_job.lower()
    assert "gh release create" not in release_job.lower()
    assert "git tag" not in release_job.lower()


def test_release_operator_scripts_are_scoped_and_do_not_add_cloud_host_dependencies() -> None:
    for name in (
        "install_compose.sh",
        "backup_state.sh",
        "restore_state.sh",
        "package_release.py",
    ):
        source = (ROOT / "scripts" / name).read_text(encoding="utf-8").lower()
        assert "cloudflare" not in source
        assert "wrangler" not in source
    notes = (ROOT / "RELEASE_NOTES.md").read_text(encoding="utf-8")
    assert "unpublished" in notes.lower()
    assert "final tag" in notes.lower()
