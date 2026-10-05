from __future__ import annotations

import hashlib
import sqlite3

import pytest

from agent.intelligence_layer.artifacts import (
    ArtifactIntegrityError,
    ArtifactKind,
    ArtifactSensitivity,
    ArtifactStore,
    ArtifactStoreError,
    ArtifactValidation,
)


def create(store: ArtifactStore, *, owner: str = "owner:1", content: bytes = b"evidence"):
    return store.put(
        owner_identity_ref=owner,
        mission_id="mission:1",
        task_id="task:1",
        kind=ArtifactKind.EVIDENCE,
        content=content,
        filename="../../evidence.bin",
        media_type="application/octet-stream",
        sensitivity=ArtifactSensitivity.SENSITIVE,
        validation=ArtifactValidation.UNVALIDATED,
        confidence=0.75,
        scope=("host:example.test", "host:example.test"),
        provenance={"source": "web", "trust": "untrusted_data"},
        metadata={"purpose": "verification"},
    )


def test_artifact_round_trip_binds_content_and_metadata_to_owner_mission_and_task(tmp_path):
    store = ArtifactStore(tmp_path / "artifacts.sqlite")
    created = create(store)

    loaded = store.get(owner_identity_ref="owner:1", artifact_id=created.artifact_id)

    assert loaded is not None
    assert loaded.content == b"evidence"
    assert loaded.content_sha256 == hashlib.sha256(b"evidence").hexdigest()
    assert len(loaded.manifest_sha256) == 64
    assert loaded.filename == "evidence.bin"
    assert loaded.scope == ("host:example.test",)
    assert loaded.owner_identity_ref == "owner:1"
    assert loaded.mission_id == "mission:1" and loaded.task_id == "task:1"
    assert loaded.provenance["trust"] == "untrusted_data"
    assert store.list(owner_identity_ref="owner:1", mission_id="mission:1")[0]["manifest_sha256"] == loaded.manifest_sha256


def test_artifacts_are_owner_scoped_and_append_only(tmp_path):
    store = ArtifactStore(tmp_path / "artifacts.sqlite")
    created = create(store)

    assert store.get(owner_identity_ref="owner:2", artifact_id=created.artifact_id) is None
    assert store.list(owner_identity_ref="owner:2") == []
    assert len(store.list(owner_identity_ref="owner:1", task_id="task:1", kind=ArtifactKind.EVIDENCE)) == 1
    with sqlite3.connect(store.db_path) as connection:
        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            connection.execute("UPDATE artifacts SET filename = 'changed' WHERE artifact_id = ?", (created.artifact_id,))
        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            connection.execute("DELETE FROM artifacts WHERE artifact_id = ?", (created.artifact_id,))


def test_payload_and_manifest_tampering_are_detected(tmp_path):
    store = ArtifactStore(tmp_path / "artifacts.sqlite")
    created = create(store)

    with sqlite3.connect(store.db_path) as connection:
        connection.execute("DROP TRIGGER artifacts_no_update")
        connection.execute("UPDATE artifacts SET content = ? WHERE artifact_id = ?", (b"changed", created.artifact_id))
    with pytest.raises(ArtifactIntegrityError, match="content"):
        store.get(owner_identity_ref="owner:1", artifact_id=created.artifact_id)

    store2 = ArtifactStore(tmp_path / "other.sqlite")
    created2 = create(store2)
    with sqlite3.connect(store2.db_path) as connection:
        connection.execute("DROP TRIGGER artifacts_no_update")
        connection.execute("UPDATE artifacts SET provenance_json = ? WHERE artifact_id = ?", ('{"source":"forged"}', created2.artifact_id))
    with pytest.raises(ArtifactIntegrityError, match="manifest"):
        store2.get(owner_identity_ref="owner:1", artifact_id=created2.artifact_id)


def test_artifact_inputs_are_bounded_and_typed(tmp_path):
    store = ArtifactStore(tmp_path / "artifacts.sqlite")
    store.MAX_CONTENT_BYTES = 3
    with pytest.raises(ArtifactStoreError, match="size limit"):
        create(store, content=b"four")
    with pytest.raises(ArtifactStoreError, match="confidence"):
        store.put(
            owner_identity_ref="owner:1", mission_id="mission:1", task_id="task:1",
            kind=ArtifactKind.REPORT, content="ok", filename="report.txt", confidence=float("nan"),
        )
    with pytest.raises(ArtifactStoreError, match="ArtifactKind"):
        store.put(
            owner_identity_ref="owner:1", mission_id="mission:1", task_id="task:1",
            kind="report", content="ok", filename="report.txt",
        )
    with pytest.raises(ArtifactStoreError, match="scope"):
        store.put(
            owner_identity_ref="owner:1", mission_id="mission:1", task_id="task:1",
            kind=ArtifactKind.REPORT, content="ok", filename="report.txt", scope="host:example.test",
        )


def test_artifact_database_uses_owner_only_permissions_on_posix(tmp_path):
    store = ArtifactStore(tmp_path / "private" / "artifacts.sqlite")
    assert store.db_path.exists()
    if hasattr(store.db_path.stat(), "st_mode"):
        assert store.db_path.stat().st_mode & 0o077 == 0
