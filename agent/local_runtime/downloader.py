from __future__ import annotations

import hashlib
import os
import re
import stat
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from threading import Event
from typing import Callable

CHUNK_BYTES = 1024 * 1024
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_ALLOWED_HOSTS = ("huggingface.co", "hf.co")


class DownloadError(RuntimeError):
    pass


class DownloadCancelled(DownloadError):
    """Raised when the user cooperatively cancels a verified model download."""


def _raise_if_cancelled(cancel_event: Event | None) -> None:
    if cancel_event is not None and cancel_event.is_set():
        raise DownloadCancelled("download_cancelled")


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


def _assert_safe_output_paths(target: Path, part: Path) -> None:
    for candidate in (target, part, target.parent):
        if candidate.is_symlink():
            raise DownloadError("unsafe_download_path")
    if target.exists() and not target.is_file():
        raise DownloadError("unsafe_download_path")
    if part.exists() and not part.is_file():
        raise DownloadError("unsafe_download_path")


def _hash_file(path: Path, cancel_event: Event | None = None) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while True:
            _raise_if_cancelled(cancel_event)
            block = stream.read(CHUNK_BYTES)
            if not block:
                break
            digest.update(block)
    _raise_if_cancelled(cancel_event)
    return digest.hexdigest()


def _open_partial(path: Path, *, append: bool):
    _assert_safe_output_paths(path.with_name(path.name.removesuffix(".part")), path)
    flags = os.O_WRONLY | os.O_CREAT
    flags |= os.O_APPEND if append else os.O_TRUNC
    flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags, 0o600)
    except OSError as exc:
        raise DownloadError("unsafe_download_path") from exc
    try:
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            raise DownloadError("unsafe_download_path")
        return os.fdopen(descriptor, "ab" if append else "wb")
    except Exception:
        os.close(descriptor)
        raise


def _promote_verified_part(part: Path, target: Path) -> None:
    _assert_safe_output_paths(target, part)
    os.replace(part, target)
    try:
        directory_fd = os.open(target.parent, os.O_RDONLY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    except OSError:
        pass


def download_verified_file(
    url: str,
    destination: str | Path,
    *,
    expected_size: int,
    expected_sha256: str,
    progress: Callable[[int, int], None] | None = None,
    timeout: int = 60,
    opener=None,
    cancel_event: Event | None = None,
) -> Path:
    """Download to a resumable private partial file, verify, then atomically install."""
    target = Path(destination)
    if expected_size <= 0 or not _SHA256.fullmatch(expected_sha256):
        raise ValueError("invalid_download_manifest")
    parsed_url = urllib.parse.urlsplit(url)
    hostname = (parsed_url.hostname or "").lower().rstrip(".")
    if parsed_url.scheme != "https" or not any(
        hostname == root or hostname.endswith("." + root) for root in _ALLOWED_HOSTS
    ) or parsed_url.username or parsed_url.password:
        raise DownloadError("download_host_not_allowed")

    _raise_if_cancelled(cancel_event)
    target.parent.mkdir(parents=True, exist_ok=True)
    part = target.with_name(target.name + ".part")
    _assert_safe_output_paths(target, part)
    client = opener or _opener()

    if target.is_file():
        if target.stat().st_size == expected_size and _hash_file(target, cancel_event) == expected_sha256:
            if progress:
                progress(expected_size, expected_size)
            return target

    offset = part.stat().st_size if part.exists() else 0
    if offset > expected_size:
        part.unlink()
        offset = 0
    if offset == expected_size:
        if _hash_file(part, cancel_event) == expected_sha256:
            _raise_if_cancelled(cancel_event)
            _promote_verified_part(part, target)
            if progress:
                progress(expected_size, expected_size)
            return target
        part.unlink()
        offset = 0

    request_headers = {"User-Agent": "CyberSentinel-Desktop/1", "Accept-Encoding": "identity"}
    if offset:
        request_headers["Range"] = f"bytes={offset}-"
    request = urllib.request.Request(url, headers=request_headers)
    _raise_if_cancelled(cancel_event)
    try:
        response = client.open(request, timeout=timeout)
    except (OSError, urllib.error.URLError, TimeoutError) as exc:
        raise DownloadError("download_transport_failed") from exc

    with response:
        status = int(getattr(response, "status", response.getcode()))
        append = bool(offset and status == 206)
        if offset and not append:
            # Some mirrors ignore Range. Restart instead of appending duplicate bytes.
            offset = 0
        elif status not in {200, 206}:
            raise DownloadError(f"download_http_{status}")
        written = offset
        try:
            with _open_partial(part, append=append) as output:
                while True:
                    _raise_if_cancelled(cancel_event)
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
    actual_sha256 = _hash_file(part, cancel_event)
    if actual_sha256 != expected_sha256:
        part.unlink(missing_ok=True)
        raise DownloadError("download_integrity_check_failed")
    _raise_if_cancelled(cancel_event)
    _promote_verified_part(part, target)
    if progress:
        progress(expected_size, expected_size)
    return target
