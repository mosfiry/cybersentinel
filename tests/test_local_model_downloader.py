from __future__ import annotations

import hashlib
import os
import threading
from io import BytesIO
from pathlib import Path
from urllib.request import Request

import pytest

from agent.local_runtime.downloader import DownloadCancelled, DownloadError, _AllowListedRedirects, download_verified_file


class FakeResponse:
    def __init__(self, content: bytes, status: int):
        self._stream = BytesIO(content)
        self.status = status

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def getcode(self):
        return self.status

    def read(self, _size=-1):
        return self._stream.read(_size)


class CancelAfterFirstRead(FakeResponse):
    def __init__(self, content: bytes, event: threading.Event):
        super().__init__(content, 200)
        self.event = event
        self.calls = 0

    def read(self, _size=-1):
        result = super().read(min(_size, 4))
        self.calls += 1
        if self.calls == 1:
            self.event.set()
        return result


class FakeOpener:
    def __init__(self, content: bytes, status: int):
        self.response = FakeResponse(content, status)
        self.request = None

    def open(self, request, timeout):
        self.request = request
        assert timeout > 0
        return self.response


class CancelOpener(FakeOpener):
    def __init__(self, content: bytes, event: threading.Event):
        self.response = CancelAfterFirstRead(content, event)
        self.request = None


def _url():
    return "https://huggingface.co/test/model/resolve/revision/model.gguf"


def test_downloader_resumes_partial_file_and_atomically_verifies(tmp_path):
    content = b"trusted-gguf-fixture"
    target = tmp_path / "model.gguf"
    target.with_name("model.gguf.part").write_bytes(content[:8])
    opener = FakeOpener(content[8:], 206)
    callbacks = []

    result = download_verified_file(
        _url(), target, expected_size=len(content), expected_sha256=hashlib.sha256(content).hexdigest(),
        progress=lambda done, total: callbacks.append((done, total)), opener=opener,
    )

    assert result == target
    assert target.read_bytes() == content
    assert opener.request.get_header("Range") == f"bytes={8}-"
    assert not target.with_name("model.gguf.part").exists()
    assert callbacks[-1] == (len(content), len(content))


def test_downloader_restarts_when_server_ignores_range(tmp_path):
    content = b"full-content"
    target = tmp_path / "model.gguf"
    target.with_name("model.gguf.part").write_bytes(b"stale")
    download_verified_file(_url(), target, expected_size=len(content), expected_sha256=hashlib.sha256(content).hexdigest(), opener=FakeOpener(content, 200))
    assert target.read_bytes() == content


def test_downloader_rejects_hash_mismatch_and_cleans_partial(tmp_path):
    target = tmp_path / "model.gguf"
    with pytest.raises(DownloadError, match="download_integrity_check_failed"):
        download_verified_file(_url(), target, expected_size=4, expected_sha256=hashlib.sha256(b"good").hexdigest(), opener=FakeOpener(b"evil", 200))
    assert not target.exists()
    assert not target.with_name("model.gguf.part").exists()


def test_downloader_rejects_unapproved_origin_and_redirect():
    with pytest.raises(DownloadError, match="download_host_not_allowed"):
        download_verified_file("https://example.invalid/model.gguf", Path("unused.gguf"), expected_size=4, expected_sha256=hashlib.sha256(b"safe").hexdigest(), opener=FakeOpener(b"safe", 200))
    handler = _AllowListedRedirects()
    with pytest.raises(DownloadError, match="download_redirect_not_allowed"):
        handler.redirect_request(Request(_url()), FakeResponse(b"", 302), 302, "Found", {}, "http://attacker.invalid/payload")


def test_downloader_cancels_cooperatively_and_keeps_only_uninstalled_partial(tmp_path):
    target = tmp_path / "model.gguf"
    event = threading.Event()
    opener = CancelOpener(b"abcdefgh12345678", event)
    with pytest.raises(DownloadCancelled, match="download_cancelled"):
        download_verified_file(_url(), target, expected_size=16, expected_sha256=hashlib.sha256(b"abcdefgh12345678").hexdigest(), opener=opener, cancel_event=event)
    assert not target.exists()
    assert target.with_name("model.gguf.part").read_bytes() == b"abcd"


def test_downloader_rejects_symlinked_partial_without_following_it(tmp_path):
    target = tmp_path / "model.gguf"
    victim = tmp_path / "victim"
    victim.write_bytes(b"keep me")
    try:
        target.with_name("model.gguf.part").symlink_to(victim)
    except (OSError, NotImplementedError):
        pytest.skip("symlink creation is unavailable on this test host")
    with pytest.raises(DownloadError, match="unsafe_download_path"):
        download_verified_file(_url(), target, expected_size=8, expected_sha256=hashlib.sha256(b"safe-data").hexdigest(), opener=FakeOpener(b"safe-data", 200))
    assert victim.read_bytes() == b"keep me"
    assert not target.exists()


def test_download_incomplete_response_never_activates_or_replaces_existing_file(tmp_path):
    target = tmp_path / "model.gguf"
    target.write_bytes(b"existing user data")
    with pytest.raises(DownloadError, match="download_incomplete"):
        download_verified_file(_url(), target, expected_size=12, expected_sha256=hashlib.sha256(b"complete-file").hexdigest(), opener=FakeOpener(b"short", 200))
    assert target.read_bytes() == b"existing user data"
    assert target.with_name("model.gguf.part").read_bytes() == b"short"
