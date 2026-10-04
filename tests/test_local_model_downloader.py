from __future__ import annotations

import hashlib
from io import BytesIO
from pathlib import Path
from urllib.request import Request

import pytest

from agent.local_runtime.downloader import DownloadError, _AllowListedRedirects, download_verified_file


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


class FakeOpener:
    def __init__(self, content: bytes, status: int):
        self.response = FakeResponse(content, status)
        self.request = None

    def open(self, request, timeout):
        self.request = request
        assert timeout > 0
        return self.response


def test_downloader_resumes_partial_file_and_atomically_verifies(tmp_path):
    content = b"trusted-gguf-fixture"
    target = tmp_path / "model.gguf"
    target.with_name("model.gguf.part").write_bytes(content[:8])
    opener = FakeOpener(content[8:], 206)
    callbacks = []

    result = download_verified_file(
        "https://huggingface.co/test/model/resolve/revision/model.gguf",
        target,
        expected_size=len(content),
        expected_sha256=hashlib.sha256(content).hexdigest(),
        progress=lambda done, total: callbacks.append((done, total)),
        opener=opener,
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
    opener = FakeOpener(content, 200)
    download_verified_file(
        "https://huggingface.co/test/model/resolve/revision/model.gguf",
        target,
        expected_size=len(content),
        expected_sha256=hashlib.sha256(content).hexdigest(),
        opener=opener,
    )
    assert target.read_bytes() == content


def test_downloader_rejects_hash_mismatch_and_cleans_partial(tmp_path):
    target = tmp_path / "model.gguf"
    with pytest.raises(DownloadError, match="download_integrity_check_failed"):
        download_verified_file(
            "https://huggingface.co/test/model/resolve/revision/model.gguf",
            target,
            expected_size=4,
            expected_sha256=hashlib.sha256(b"good").hexdigest(),
            opener=FakeOpener(b"evil", 200),
        )
    assert not target.exists()
    assert not target.with_name("model.gguf.part").exists()


def test_downloader_rejects_unapproved_origin_and_redirect():
    with pytest.raises(DownloadError, match="download_host_not_allowed"):
        download_verified_file(
            "https://example.invalid/model.gguf",
            Path("unused.gguf"),
            expected_size=4,
            expected_sha256=hashlib.sha256(b"safe").hexdigest(),
            opener=FakeOpener(b"safe", 200),
        )
    handler = _AllowListedRedirects()
    with pytest.raises(DownloadError, match="download_redirect_not_allowed"):
        handler.redirect_request(
            Request("https://huggingface.co/model"),
            FakeResponse(b"", 302),
            302,
            "Found",
            {},
            "http://attacker.invalid/payload",
        )
