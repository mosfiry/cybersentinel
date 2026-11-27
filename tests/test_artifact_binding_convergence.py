"""Adversarial battery: CONVERGENCE of the artifact-store post-open identity
binding (session 51). The binding was duplicated inline in all four
artifact-store analysis handlers (P1-F/G/H/I); it is now ONE shared
fail-closed helper (_artifact_identity_error) with a single _artifact_fstat
call site. These tests are drift guards: they fail if any handler regresses
to a private copy of the binding, if the identity seam gains a second call
site, or if the shared helper ever degrades into a permissive result on seam
failure, directory swap, or inode mismatch.
"""
from __future__ import annotations

import inspect
import os

import pytest

import tools.registry as registry


HANDLERS = [
    (registry._artifact_metadata, "meta_sample.bin", "META_OPEN_FAILED"),
    (registry._binary_header_analysis, "bin_sample.bin", "BIN_OPEN_FAILED"),
    (registry._printable_string_analysis, "str_sample.txt", "STR_OPEN_FAILED"),
    (registry._import_analysis, "imp_sample.dll", "IMP_OPEN_FAILED"),
]


@pytest.fixture()
def store(tmp_path, monkeypatch):
    root = tmp_path / "artifacts"
    root.mkdir()
    monkeypatch.setattr(registry, "_artifact_root", lambda: root)
    return root


def test_identity_seam_has_exactly_one_call_site():
    source = inspect.getsource(registry)
    assert source.count("_artifact_fstat(") == 2  # the def + the shared helper
    assert source.count("_artifact_identity_error(stat_before, handle") == 4


@pytest.mark.parametrize("handler,_name,_code", [(h, n, c) for h, n, c in HANDLERS], ids=[n for _h, n, _c in HANDLERS])
def test_every_handler_routes_through_the_shared_helper(handler, _name, _code):
    source = inspect.getsource(handler)
    assert "_artifact_identity_error(" in source
    # no private re-implementation of the binding inside any handler
    assert "S_ISREG" not in source
    assert "hasattr(stat_before" not in source


def test_shared_helper_accepts_legacy_plain_int_fake():
    # legacy test-fake shape: a plain int stat carries no identity -> binding skipped
    assert registry._artifact_identity_error(1234, object()) is None


def test_shared_helper_fails_closed_on_identity_seam_error(tmp_path, monkeypatch):
    target = tmp_path / "f.bin"
    target.write_bytes(b"MZ" + b"A" * 16)
    real_stat = os.stat(str(target))

    def _boom(handle):
        raise OSError("fstat unavailable")

    monkeypatch.setattr(registry, "_artifact_fstat", _boom)
    reason = registry._artifact_identity_error(real_stat, object())
    assert reason is not None
    assert "identity-verified" in reason


def test_shared_helper_fails_closed_on_directory_inode(tmp_path, monkeypatch):
    target = tmp_path / "f.bin"
    target.write_bytes(b"PK\x03\x04" + b"B" * 16)
    real_stat = os.stat(str(target))
    monkeypatch.setattr(registry, "_artifact_fstat", lambda handle: os.stat(str(tmp_path)))
    reason = registry._artifact_identity_error(real_stat, object())
    assert reason is not None
    assert "regular file" in reason


def test_shared_helper_fails_closed_on_inode_mismatch(tmp_path, monkeypatch):
    target = tmp_path / "f.bin"
    target.write_bytes(b"\x7fELF" + b"C" * 16)
    real_stat = os.stat(str(target))
    other = tmp_path / "other.bin"
    other.write_bytes(b"D" * 32)
    monkeypatch.setattr(registry, "_artifact_fstat", lambda handle: os.stat(str(other)))
    reason = registry._artifact_identity_error(real_stat, object())
    assert reason is not None
    assert "identity changed" in reason


def test_shared_helper_passes_on_matching_real_inode(tmp_path, monkeypatch):
    target = tmp_path / "f.bin"
    body = b"%PDF-1.7 real"
    target.write_bytes(body)
    real_stat = os.stat(str(target))
    with open(str(target), "rb") as handle:
        assert registry._artifact_identity_error(real_stat, handle) is None


@pytest.mark.parametrize("handler,file_name,code", HANDLERS)
def test_handlers_still_fail_closed_through_the_shared_path(store, tmp_path, monkeypatch, handler, file_name, code):
    # end-to-end: with the identity seam reporting an OUTSIDE inode, every
    # handler must return its own fail-closed OPEN_FAILED classification and
    # never leak the outside bytes.
    (store / file_name).write_bytes(b"MZ" + b"Z" * 16)
    secret = b"OUTSIDE-STORE-SECRET-CONTENT-9876543210"
    (tmp_path / "outside.txt").write_bytes(secret)
    outside = os.stat(str(tmp_path / "outside.txt"))
    monkeypatch.setattr(registry, "_artifact_fstat", lambda handle: outside)
    record = handler(file_name)
    assert record["ok"] is False
    assert record["error"] == code
    flat = repr(record)
    assert "OUTSIDE-STORE-SECRET" not in flat
    import hashlib
    assert hashlib.sha256(secret).hexdigest() not in flat
    assert record.get("content") is None
