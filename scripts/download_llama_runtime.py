#!/usr/bin/env python3
"""Fetch and verify the pinned llama.cpp CPU runtime for supported x64 hosts."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import stat
import sys
import tarfile
import tempfile
import urllib.parse
import urllib.request
import zipfile

ROOT = Path(__file__).resolve().parents[1]
TAG = "b11146"
ALLOWED_REDIRECT_HOSTS = {
    "github.com",
    "release-assets.githubusercontent.com",
    "objects.githubusercontent.com",
}
ASSETS = {
    "windows-x64": {
        "asset": "llama-b11146-bin-win-cpu-x64.zip",
        "url": f"https://github.com/ggml-org/llama.cpp/releases/download/{TAG}/llama-b11146-bin-win-cpu-x64.zip",
        "size": 18_560_055,
        "sha256": "14cf1303ca9ac3abd94816850532f9f9a69ac66fbaca3776fc6f9061c2fac1d1",
        "platform": "windows-x64-cpu",
        "server": "llama-server.exe",
        "format": "zip",
    },
    "linux-x64": {
        "asset": "llama-b11146-bin-ubuntu-x64.tar.gz",
        "url": f"https://github.com/ggml-org/llama.cpp/releases/download/{TAG}/llama-b11146-bin-ubuntu-x64.tar.gz",
        "size": 16_998_357,
        "sha256": "c150306eb16b5ab696f76a8bdf810c35fd98a24e82158742e6fa28f420ff8410",
        "platform": "linux-x64-cpu",
        "server": "llama-server",
        "format": "tar.gz",
    },
}


class PinnedReleaseRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        parsed = urllib.parse.urlsplit(newurl)
        if parsed.scheme != "https" or (parsed.hostname or "").lower() not in ALLOWED_REDIRECT_HOSTS:
            raise RuntimeError("runtime_download_redirect_not_allowed")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _absolute_path_without_symlinks(path: Path) -> Path:
    absolute = Path(os.path.abspath(path.expanduser()))
    current = Path(absolute.anchor)
    for component in absolute.parts[1:]:
        current = current / component
        if current.is_symlink():
            raise RuntimeError("runtime_path_symlink_not_allowed")
    return absolute


def _safe_member_path(name: str) -> PurePosixPath:
    path = PurePosixPath(name.replace("\\", "/"))
    if path.is_absolute() or not path.parts or ".." in path.parts or ":" in path.parts[0]:
        raise RuntimeError("runtime_archive_path_traversal")
    return path


def _extract_zip(archive_path: Path, destination: Path) -> None:
    with zipfile.ZipFile(archive_path) as bundle:
        for member in bundle.infolist():
            _safe_member_path(member.filename)
            mode = (member.external_attr >> 16) & 0xFFFF
            if stat.S_ISLNK(mode):
                raise RuntimeError("runtime_archive_link_not_allowed")
        bundle.extractall(destination)


def _extract_tar(archive_path: Path, destination: Path) -> None:
    with tarfile.open(archive_path, "r:gz") as bundle:
        members = bundle.getmembers()
        for member in members:
            _safe_member_path(member.name)
            if member.issym() or member.islnk():
                link = PurePosixPath(member.linkname.replace("\\", "/"))
                if link.is_absolute() or ".." in link.parts or (link.parts and ":" in link.parts[0]):
                    raise RuntimeError("runtime_archive_link_not_allowed")
            elif not (member.isfile() or member.isdir()):
                raise RuntimeError("runtime_archive_special_file_not_allowed")
        # Python 3.12's data filter adds a second containment check during extraction.
        bundle.extractall(destination, members=members, filter="data")


def _download(asset: dict[str, object], archive: Path) -> None:
    if archive.is_symlink():
        raise RuntimeError("runtime_archive_path_not_regular_file")
    if archive.exists():
        if not archive.is_file():
            raise RuntimeError("runtime_archive_path_not_regular_file")
        if archive.stat().st_size == asset["size"] and _sha256(archive) == asset["sha256"]:
            return
        archive.unlink()

    opener = urllib.request.build_opener(PinnedReleaseRedirects())
    request = urllib.request.Request(
        str(asset["url"]),
        headers={"User-Agent": "CyberSentinel-Desktop-Build/1", "Accept-Encoding": "identity"},
    )
    digest = hashlib.sha256()
    size = 0
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{archive.name}.part-", dir=archive.parent)
    part = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as stream, opener.open(request, timeout=90) as response:
            while True:
                block = response.read(1024 * 1024)
                if not block:
                    break
                size += len(block)
                if size > asset["size"]:
                    raise RuntimeError("runtime_download_exceeds_expected_size")
                digest.update(block)
                stream.write(block)
                print(f"llama.cpp download: {size}/{asset['size']} bytes", flush=True)
            stream.flush()
            os.fsync(stream.fileno())
        if size != asset["size"]:
            raise RuntimeError("runtime_download_incomplete")
        if digest.hexdigest() != asset["sha256"]:
            raise RuntimeError("runtime_download_integrity_check_failed")
        os.replace(part, archive)
    except Exception:
        part.unlink(missing_ok=True)
        raise


def _existing_output_is_valid(output: Path, asset: dict[str, object]) -> bool:
    try:
        manifest_path = output / "runtime-manifest.json"
        server = output / str(asset["server"])
        if (
            manifest_path.is_symlink()
            or not manifest_path.is_file()
            or manifest_path.stat().st_size > 16 * 1024
            or server.is_symlink()
            or not server.is_file()
        ):
            return False
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        return bool(
            manifest.get("tag") == TAG
            and manifest.get("asset") == asset["asset"]
            and manifest.get("asset_sha256") == asset["sha256"]
            and manifest.get("platform") == asset["platform"]
            and manifest.get("server_binary") == asset["server"]
            and manifest.get("server_binary_sha256") == _sha256(server)
        )
    except (OSError, TypeError, ValueError):
        return False


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=ROOT / "desktop" / "build" / "llama")
    parser.add_argument("--platform", choices=("auto", "linux-x64", "windows-x64"), default="auto")
    args = parser.parse_args()

    platform_key = args.platform
    if platform_key == "auto":
        if os.name == "nt" and ("AMD64" in os.environ.get("PROCESSOR_ARCHITECTURE", "AMD64").upper()):
            platform_key = "windows-x64"
        elif sys.platform.startswith("linux") and os.uname().machine.lower() in {"x86_64", "amd64"}:
            platform_key = "linux-x64"
        else:
            parser.error("automatic runtime selection supports only Windows x64 and Linux x64")
    asset = ASSETS[platform_key]
    try:
        output = _absolute_path_without_symlinks(args.output)
    except RuntimeError as exc:
        parser.error(str(exc))
    output.parent.mkdir(parents=True, exist_ok=True)
    if output.is_symlink() or (output.exists() and not output.is_dir()):
        parser.error("runtime output must be a non-symlink directory path")
    if output.exists():
        if _existing_output_is_valid(output, asset):
            print(f"Verified llama.cpp {TAG}; existing runtime retained at {output}", flush=True)
            return 0
        parser.error("runtime output directory exists and is not a verified matching runtime")

    try:
        downloads = _absolute_path_without_symlinks(ROOT / "desktop" / "build" / "downloads")
    except RuntimeError as exc:
        parser.error(str(exc))
    downloads.mkdir(parents=True, exist_ok=True)
    archive = downloads / str(asset["asset"])
    _download(asset, archive)

    staging = Path(tempfile.mkdtemp(prefix=f".{output.name}.staging-", dir=output.parent))
    try:
        extracted = staging / "extracted"
        extracted.mkdir()
        if asset["format"] == "zip":
            _extract_zip(archive, extracted)
        else:
            _extract_tar(archive, extracted)

        binaries = [path for path in extracted.rglob(str(asset["server"])) if path.is_file() and not path.is_symlink()]
        if len(binaries) != 1:
            raise RuntimeError(f"runtime_server_binary_count:{len(binaries)}")
        source_dir = binaries[0].parent
        install_dir = staging / "runtime"
        install_dir.mkdir()
        for source in source_dir.rglob("*"):
            if not source.is_file():
                continue
            resolved = source.resolve(strict=True)
            if not resolved.is_relative_to(extracted.resolve()):
                raise RuntimeError("runtime_archive_link_escapes_extraction_root")
            relative = source.relative_to(source_dir)
            target = install_dir / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, target)

        server_path = install_dir / str(asset["server"])
        if not server_path.is_file():
            raise RuntimeError("runtime_server_binary_not_installed")
        if platform_key == "linux-x64":
            server_path.chmod(server_path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
        manifest = {
            "provider": "llama.cpp",
            "tag": TAG,
            "asset": asset["asset"],
            "source_url": asset["url"],
            "asset_size_bytes": asset["size"],
            "asset_sha256": asset["sha256"],
            "platform": asset["platform"],
            "server_binary": asset["server"],
            "server_binary_sha256": _sha256(server_path),
        }
        (install_dir / "runtime-manifest.json").write_text(
            json.dumps(manifest, sort_keys=True, indent=2) + "\n", encoding="utf-8"
        )
        os.replace(install_dir, output)
    finally:
        shutil.rmtree(staging, ignore_errors=True)

    if not _existing_output_is_valid(output, asset):
        raise RuntimeError("runtime_install_verification_failed")
    print(f"Verified llama.cpp {TAG} ({asset['platform']}); runtime installed at {output}", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
