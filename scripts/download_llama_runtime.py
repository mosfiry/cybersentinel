#!/usr/bin/env python3
"""Fetch and verify the pinned upstream llama.cpp Windows CPU runtime."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import urllib.parse
import urllib.request
import zipfile
from pathlib import Path, PurePosixPath

ROOT = Path(__file__).resolve().parents[1]
TAG = "b11146"
ASSET = "llama-b11146-bin-win-cpu-x64.zip"
URL = f"https://github.com/ggml-org/llama.cpp/releases/download/{TAG}/{ASSET}"
EXPECTED_SIZE = 18_560_055
EXPECTED_SHA256 = "14cf1303ca9ac3abd94816850532f9f9a69ac66fbaca3776fc6f9061c2fac1d1"
ALLOWED_REDIRECT_HOSTS = {"github.com", "release-assets.githubusercontent.com", "objects.githubusercontent.com"}


class PinnedReleaseRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        parsed = urllib.parse.urlsplit(newurl)
        if parsed.scheme != "https" or (parsed.hostname or "").lower() not in ALLOWED_REDIRECT_HOSTS:
            raise RuntimeError("runtime_download_redirect_not_allowed")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=ROOT / "desktop" / "build" / "llama")
    args = parser.parse_args()
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    downloads = ROOT / "desktop" / "build" / "downloads"
    downloads.mkdir(parents=True, exist_ok=True)
    archive = downloads / ASSET
    part = archive.with_suffix(archive.suffix + ".part")
    if archive.exists() and (archive.stat().st_size != EXPECTED_SIZE or _sha256(archive) != EXPECTED_SHA256):
        archive.unlink()

    if not archive.exists():
        opener = urllib.request.build_opener(PinnedReleaseRedirects())
        request = urllib.request.Request(URL, headers={"User-Agent": "CyberSentinel-Desktop-Build/1", "Accept-Encoding": "identity"})
        digest = hashlib.sha256()
        size = 0
        try:
            with opener.open(request, timeout=90) as response, part.open("wb") as stream:
                while True:
                    block = response.read(1024 * 1024)
                    if not block:
                        break
                    size += len(block)
                    if size > EXPECTED_SIZE:
                        raise RuntimeError("runtime_download_exceeds_expected_size")
                    digest.update(block)
                    stream.write(block)
                    print(f"llama.cpp download: {size}/{EXPECTED_SIZE} bytes", flush=True)
                stream.flush()
                os.fsync(stream.fileno())
        except Exception:
            part.unlink(missing_ok=True)
            raise
        if size != EXPECTED_SIZE:
            part.unlink(missing_ok=True)
            raise RuntimeError("runtime_download_incomplete")
        if digest.hexdigest() != EXPECTED_SHA256:
            part.unlink(missing_ok=True)
            raise RuntimeError("runtime_download_integrity_check_failed")
        os.replace(part, archive)

    shutil.rmtree(output, ignore_errors=True)
    output.mkdir(parents=True, exist_ok=True)
    extracted = output / ".extracted"
    extracted.mkdir()
    with zipfile.ZipFile(archive) as bundle:
        for member in bundle.infolist():
            name = PurePosixPath(member.filename.replace("\\", "/"))
            if name.is_absolute() or ".." in name.parts or (name.parts and ":" in name.parts[0]):
                raise RuntimeError("runtime_archive_path_traversal")
        bundle.extractall(extracted)

    binaries = list(extracted.rglob("llama-server.exe"))
    if len(binaries) != 1:
        raise RuntimeError(f"runtime_server_binary_count:{len(binaries)}")
    source_dir = binaries[0].parent
    for source in source_dir.rglob("*"):
        if source.is_file():
            relative = source.relative_to(source_dir)
            target = output / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, target)
    shutil.rmtree(extracted, ignore_errors=True)
    if not (output / "llama-server.exe").is_file():
        raise RuntimeError("runtime_server_binary_not_installed")
    manifest = {
        "provider": "llama.cpp",
        "tag": TAG,
        "asset": ASSET,
        "source_url": URL,
        "asset_size_bytes": EXPECTED_SIZE,
        "asset_sha256": EXPECTED_SHA256,
        "platform": "windows-x64-cpu",
        "server_binary": "llama-server.exe",
    }
    (output / "runtime-manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    print(f"Verified llama.cpp {TAG}; runtime installed at {output}", flush=True)
    return 0


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


if __name__ == "__main__":
    raise SystemExit(main())
