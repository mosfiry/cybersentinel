from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class FilesystemObservation:
    path: str
    exists: bool
    file_type: str
    size: int | None = None
    sha256: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "exists": self.exists,
            "type": self.file_type,
            "size": self.size,
            "sha256": self.sha256,
        }


class FilesystemVerifier:
    """Independent read-only verifier for filesystem claims."""

    def __init__(self, root: str | Path):
        self.root = Path(root).expanduser().resolve()

    def _resolve(self, relative: str | Path) -> Path:
        candidate = Path(relative)
        path = candidate.resolve() if candidate.is_absolute() else (self.root / candidate).resolve()
        if path != self.root and self.root not in path.parents:
            raise ValueError("filesystem verification path escapes workspace")
        return path

    def observe(self, relative: str | Path, *, include_hash: bool = False) -> FilesystemObservation:
        path = self._resolve(relative)
        if not path.exists():
            return FilesystemObservation(str(path.relative_to(self.root)), False, "missing")
        if path.is_dir():
            return FilesystemObservation(str(path.relative_to(self.root)), True, "directory")
        digest = None
        if include_hash and path.is_file():
            digest = sha256(path.read_bytes()).hexdigest()
        return FilesystemObservation(str(path.relative_to(self.root)), True, "file", path.stat().st_size, digest)

    def verify_created(self, relative: str | Path, *, expected_type: str = "file", expected_size: int | None = None, expected_sha256: str | None = None) -> dict[str, Any]:
        observation = self.observe(relative, include_hash=expected_sha256 is not None)
        verified = observation.exists and observation.file_type == expected_type
        if expected_size is not None:
            verified = verified and observation.size == expected_size
        if expected_sha256 is not None:
            verified = verified and observation.sha256 == expected_sha256
        return {"verification": "VERIFIED" if verified else "OBSERVED", "passed": verified, "source": "filesystem-verifier", "observation": observation.to_dict()}


__all__ = ["FilesystemObservation", "FilesystemVerifier"]
