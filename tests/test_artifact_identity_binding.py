"""Adversarial battery: post-open identity binding for the artifact-store
analysis handlers (P1-F/G/H/I) — stat->open TOCTOU / symlink-swap closure.

The real filesystem seams are used against a tmp_path artifact store; the
identity seam (_artifact_fstat) is faked ONLY to simulate the swap. Every
negative asserts the handler returns a fail-closed OPEN_FAILED classification
and that the swapped (outside-the-store) bytes never appear anywhere in the
returned record (no content leak, no hash of the swapped bytes). The legacy
fake shape (a plain int size from _artifact_stat) keeps working unchanged:
the identity check engages only when real stat metadata is observable, and
production always exposes it.
"""
from __future__ import annotations

import hashlib
import os

import pytest

import tools.registry as registry


HANDLERS = [
    ("local_artifact_metadata", "meta_sample.bin", registry._artifact_metadata, "META_OPEN_FAILED"),
    ("local_binary_analysis", "bin_sample.bin", registry._binary_header_analysis, "BIN_OPEN_FAILED"),
    ("local_string_extraction", "str_sample.txt", registry._printable_string_analysis, "STR_OPEN_FAILED"),
    ("local_import_analysis", "imp_sample.dll", registry._import_analysis, "IMP_OPEN_FAILED"),
]


@pytest.fixture()
def store(tmp_path, monkeypatch):
    root = tmp_path / "artifacts"
    root.mkdir()
    monkeypatch.setattr(registry, "_artifact_root", lambda: root)
    return root


def _write(root, name, body: bytes):
    path = root / name
    path.write_bytes(body)
    return path


def _outside_secret(tmp_path) -> bytes:
    secret = b"OUTSIDE-STORE-SECRET-CONTENT-0123456789"
    (tmp_path / "outside.txt").write_bytes(secret)
    return secret


def _swap_to(tmp_path, monkeypatch, target_path):
    """Fake the identity seam to report a DIFFERENT inode (the swapped one)."""
    swapped = os.stat(str(target_path))
    monkeypatch.setattr(registry, "_artifact_fstat", lambda handle: swapped)


@pytest.mark.parametrize("op_name,file_name,handler,code", HANDLERS)
def test_real_identity_flow_succeeds(store, op_name, file_name, handler, code):
    body = b"\x7fELF" + b"A" * 64  # in-store ELF-prefixed artifact
    _write(store, file_name, body)
    record = handler(file_name)
    assert record["ok"] is True
    assert record["sha256"] == hashlib.sha256(body).hexdigest()
    assert record["content"] is None
    assert record["path_within_store"] == file_name


@pytest.mark.parametrize("op_name,file_name,handler,code", HANDLERS)
def test_symlink_swap_between_stat_and_open_fails_closed(store, tmp_path, monkeypatch, op_name, file_name, handler, code):
    _write(store, file_name, b"MZ" + b"B" * 64)
    secret = _outside_secret(tmp_path)
    _swap_to(tmp_path, monkeypatch, tmp_path / "outside.txt")
    record = handler(file_name)
    assert record["ok"] is False
    assert record["error"] == code
    assert "identity" in record["reason"] or "identity changed" in record["reason"]
    # The swapped bytes never leak into the record in any form.
    flat = repr(record)
    assert "OUTSIDE-STORE-SECRET" not in flat
    assert hashlib.sha256(secret).hexdigest() not in flat
    assert record.get("content") is None


@pytest.mark.parametrize("op_name,file_name,handler,code", HANDLERS)
def test_swapped_directory_inode_fails_closed(store, tmp_path, monkeypatch, op_name, file_name, handler, code):
    _write(store, file_name, b"PK\x03\x04" + b"C" * 32)
    swapped = os.stat(str(tmp_path))  # a directory, not a regular file
    monkeypatch.setattr(registry, "_artifact_fstat", lambda handle: swapped)
    record = handler(file_name)
    assert record["ok"] is False
    assert record["error"] == code
    assert "regular file" in record["reason"]


@pytest.mark.parametrize("op_name,file_name,handler,code", HANDLERS)
def test_identity_seam_failure_fails_closed(store, tmp_path, monkeypatch, op_name, file_name, handler, code):
    _write(store, file_name, b"\x1f\x8b" + b"D" * 32)

    def _boom(handle):
        raise OSError("fstat unavailable")

    monkeypatch.setattr(registry, "_artifact_fstat", _boom)
    record = handler(file_name)
    assert record["ok"] is False
    assert record["error"] == code
    assert "identity-verified" in record["reason"]


def test_real_stat_size_and_independence_from_legacy_int_fake(store, tmp_path, monkeypatch):
    # Legacy batteries fake _artifact_stat as a plain int; production behavior
    # (size from st_size, identity verified) must not regress and the int
    # shape must remain accepted without a crash.
    body = b"%PDF-1.7 fake"
    path = _write(store, "pdf_sample.bin", body)
    monkeypatch.setattr(registry, "_artifact_stat", lambda p: int(os.path.getsize(str(p))))
    record = registry._artifact_metadata("pdf_sample.bin")
    assert record["ok"] is True
    assert record["size_bytes"] == len(body) == os.path.getsize(str(path))
    assert record["sha256"] == hashlib.sha256(body).hexdigest()


def test_real_size_from_st_size(store):
    body = b"SQLite format 3\x00" + b"E" * 16
    _write(store, "db_sample.bin", body)
    record = registry._artifact_metadata("db_sample.bin")
    assert record["ok"] is True
    assert record["size_bytes"] == len(body)
    assert record["read_cap_bytes"] == registry.ARTIFACT_METADATA_MAX_BYTES


def test_identity_binding_does_not_change_success_shape(store):
    body = b"\xca\xfe\xba\xbe" + bytes([0, 0, 0, 2]) + b"F" * 16
    _write(store, "fat_sample.bin", body)
    record = registry._binary_header_analysis("fat_sample.bin")
    assert record["ok"] is True
    assert record["format_family"] == "mach_o_universal"
    assert record["analysis_kind"] == "static_header_read"
    assert record["content"] is None


def test_no_authority_or_secret_keys_in_failure_records(store, tmp_path, monkeypatch):
    for _name, file_name, _handler, _code in HANDLERS:
        _write(store, file_name, b"MZ" + b"H" * 16)
    _outside_secret(tmp_path)
    _swap_to(tmp_path, monkeypatch, tmp_path / "outside.txt")
    for _name, file_name, handler, code in HANDLERS:
        record = handler(file_name)
        assert record["ok"] is False and record["error"] == code
        joined = " ".join(str(v) for v in record.values()).lower()
        for forbidden in ("authorization", "owner_authenticated", "scope_snapshot", "execution_proof", "password", "token"):
            assert forbidden not in joined
