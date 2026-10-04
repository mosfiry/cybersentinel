from __future__ import annotations

import hashlib
import os
import re
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Callable

CHUNK_BYTES = 1024 * 1024
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_ALLOWED_HOSTS = ("huggingface.co", "hf.co")


class DownloadError(RuntimeError):
    pass


class _AllowListedRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        parsed = urllib.parse.urlsplit(newurl)
        hostname = (parsed.hostname or "").lower().rstrip(".")
        allowed = any(hostname == root or hostname.endswith("." + root) for root in _ALLOWED_HOSTS)
        if parsed.scheme != "https" or not allowed or parsed.username or parsed.password:
            raise DownloadError("download_redirect_not_allowed")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def _opener():
    return urllib.request.build_opener(_AllowListedRedirects())


def _hash_file(path: Path, progress: Callable[[int], None] | None = None) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while True:
            block = stream.read(CHUNK_BYTES)
            if not block:
                break
            digest.update(block)
    return digest.hexdigest()


def download_verified_file(
    url: str,
    destination: str | Path,
    *,
    expected_size: int,
    expected_sha256: str,
    progress: Callable[[int, int], None] | None = None,
    timeout: int = 60,
    opener=None,
) -> Path:
    """Download a pinned file to a .part file, verify it, then atomically install it."""
    target = Path(destination)
    if expected_size <= 0 or not _SHA256.fullmatch(expected_sha256):
        raise ValueError("invalid_download_manifest")
    parsed_url = urllib.parse.urlsplit(url)
    hostname = (parsed_url.hostname or "").lower().rstrip(".")
    if parsed_url.scheme != "https" or not any(
        hostname == root or hostname.endswith("." + root) for root in _ALLOWED_HOSTS
    ):
        raise DownloadError("download_host_not_allowed")
    target.parent.mkdir(parents=True, exist_ok=True)
    part = target.with_name(target.name + ".part")
    client = opener or _opener()

    if target.is_file():
        if target.stat().st_size == expected_size and _hash_file(target) == expected_sha256:
            if progress:
                progress(expected_size, expected_size)
            return target
        target.unlink()

    offset = part.stat().st_size if part.exists() else 0
    if offset > expected_size:
        part.unlink()
        offset = 0
    request_headers = {"User-Agent": "CyberSentinel-Desktop/1", "Accept-Encoding": "identity"}
    if offset:
        request_headers["Range"] = f"bytes={offset}-"
    request = urllib.request.Request(url, headers=request_headers)
    try:
        response = client.open(request, timeout=timeout)
    except (OSError, urllib.error.URLError, TimeoutError) as exc:
        raise DownloadError("download_transport_failed") from exc

    with response:
        status = int(getattr(response, "status", response.getcode()))
        append = bool(offset and status == 206)
        if offset and not append:
            # Some mirrors ignore Range. Their 200 body is a full file, so restart
            # the temporary file rather than appending duplicate content.
            offset = 0
        elif status not in {200, 206}:
            raise DownloadError(f"download_http_{status}")
        written = offset
        mode = "ab" if append else "wb"
        try:
            with part.open(mode) as output:
                while True:
                    block = response.read(CHUNK_BYTES)
                    if not block:
                        break
                    written += len(block)
                    if written > expected_size:
                        raise DownloadError("download_exceeds_expected_size")
                    output.write(block)
                    if progress:
                        progress(written, expected_size)
                output.flush()
                os.fsync(output.fileno())
        except (OSError, urllib.error.URLError, TimeoutError) as exc:
            raise DownloadError("download_interrupted") from exc

    actual_size = part.stat().st_size if part.exists() else 0
    if actual_size != expected_size:
        raise DownloadError("download_incomplete")
    actual_sha256 = _hash_file(part)
    if actual_sha256 != expected_sha256:
        part.unlink(missing_ok=True)
        raise DownloadError("download_integrity_check_failed")
    os.replace(part, target)
    try:
        directory_fd = os.open(target.parent, os.O_RDONLY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    except OSError:
        pass
    if progress:
        progress(expected_size, expected_size)
    return target
