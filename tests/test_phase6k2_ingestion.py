from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from knowledge import store
from knowledge.foundation import IntegrityError, KnowledgeError, KnowledgeKind, TransformationPolicy, TrustClass
from knowledge.ingestion import IngestionManifest, ingest_bytes, ingest_file


@pytest.fixture
def isolated_store(tmp_path, monkeypatch):
    monkeypatch.setattr(store, "DB_PATH", Path(tmp_path) / "knowledge.sqlite3")
    store.init_store()
    return store


def manifest_for(payload: bytes, **overrides) -> IngestionManifest:
    values = {
        "source_id": "source-1",
        "source_url": "https://example.test/source",
        "edition": "2026-01",
        "author": "publisher",
        "language": "ar",
        "retrieved_at": "2026-09-21T00:00:00Z",
        "license": "test-license",
        "expected_hash": hashlib.sha256(payload).hexdigest(),
        "trust_class": TrustClass.PRIMARY_SOURCE,
        "transformation_policy": TransformationPolicy.EXACT_ONLY,
    }
    values.update(overrides)
    return IngestionManifest(**values)


def test_ingestion_hashes_raw_bytes_before_utf8_decoding(isolated_store):
    payload = "نَصٌّ  بِمسافتين\n".encode("utf-8")
    obj = ingest_bytes(
        object_id="exact-1",
        kind=KnowledgeKind.IMMUTABLE_RELIGIOUS,
        title="exact source",
        manifest=manifest_for(payload),
        payload=payload,
    )
    assert obj.content.encode("utf-8") == payload
    assert obj.content_hash == hashlib.sha256(payload).hexdigest()
    assert obj.metadata["ingestion_manifest"]["expected_hash"] == obj.content_hash
    assert isolated_store.get("exact-1").content == obj.content


def test_ingestion_rejects_hash_mismatch_before_persistence(isolated_store):
    payload = b"source bytes"
    manifest = manifest_for(payload, expected_hash=hashlib.sha256(b"different").hexdigest())
    with pytest.raises(IntegrityError, match="expected_hash"):
        ingest_bytes(
            object_id="mismatch",
            kind=KnowledgeKind.GENERAL,
            title="mismatch",
            manifest=manifest,
            payload=payload,
        )
    assert isolated_store.get("mismatch") is None


def test_ingestion_rejects_invalid_utf8_without_lossy_decode(isolated_store):
    payload = b"valid prefix\xff"
    with pytest.raises(IntegrityError, match="UTF-8"):
        ingest_bytes(
            object_id="invalid-utf8",
            kind=KnowledgeKind.GENERAL,
            title="invalid",
            manifest=manifest_for(payload),
            payload=payload,
        )
    assert isolated_store.get("invalid-utf8") is None


def test_manifest_rejects_missing_fields_and_invalid_hash():
    with pytest.raises(KnowledgeError, match="source_id"):
        IngestionManifest(
            source_id="",
            source_url="url",
            edition="edition",
            author="author",
            language="en",
            retrieved_at="now",
            license="license",
            expected_hash="0" * 64,
            trust_class=TrustClass.REFERENCE,
            transformation_policy=TransformationPolicy.RETRIEVAL_ALLOWED,
        )
    with pytest.raises(KnowledgeError, match="SHA-256"):
        manifest_for(b"x", expected_hash="not-a-hash")


def test_manifest_mapping_and_file_ingestion_preserve_exact_content(isolated_store, tmp_path):
    payload = "line one\n\nline  three".encode("utf-8")
    manifest = IngestionManifest.from_mapping({
        **manifest_for(payload).as_metadata(),
    })
    path = tmp_path / "source.txt"
    path.write_bytes(payload)
    obj = ingest_file(
        object_id="file-1",
        kind=KnowledgeKind.GENERAL,
        title="file source",
        manifest=manifest,
        path=path,
    )
    assert obj.content == "line one\n\nline  three"


def test_immutable_religious_ingestion_cannot_use_derived_policy(isolated_store):
    payload = "نص".encode("utf-8")
    manifest = manifest_for(payload, transformation_policy=TransformationPolicy.DERIVED_ALLOWED)
    with pytest.raises(KnowledgeError, match="EXACT_ONLY"):
        ingest_bytes(
            object_id="derived-religious",
            kind=KnowledgeKind.IMMUTABLE_RELIGIOUS,
            title="invalid policy",
            manifest=manifest,
            payload=payload,
        )
    assert isolated_store.get("derived-religious") is None
