"""Read-only review of unlisted Hugging Face model metadata.

This module never downloads weights, executes repository content, or adds a
candidate to the installable catalog. Only an explicit namespace/repository ID
and a full immutable commit SHA are accepted; all requests go to the fixed
Hugging Face Hub API host.
"""
from __future__ import annotations

import json
import re
import urllib.error
import urllib.parse
import urllib.request
from typing import Callable


_REPOSITORY_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,95}/[A-Za-z0-9][A-Za-z0-9._-]{0,95}$")
_REVISION_RE = re.compile(r"^[0-9a-f]{40}$")
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_QUANTIZATION_RE = re.compile(r"(?:^|[-_.])((?:I)?Q\d(?:_[A-Z0-9]+)*|F16|BF16)(?=[-_.]|$)", re.IGNORECASE)
_API_HOST = "huggingface.co"
_MAX_RESPONSE_BYTES = 4 * 1024 * 1024
_MAX_GGUF_FILES = 40
_REQUEST_TIMEOUT_SECONDS = 12


class CatalogReviewError(Exception):
    """Safe, user-displayable failure from remote metadata review."""

    def __init__(self, code: str, status_code: int = 502):
        super().__init__(code)
        self.code = code
        self.status_code = status_code


def _int_size(value: object) -> int | None:
    return value if type(value) is int and value > 0 else None


def _lfs_sha256(sibling: dict) -> str | None:
    lfs = sibling.get("lfs")
    if not isinstance(lfs, dict):
        return None
    value = lfs.get("sha256")
    if not isinstance(value, str):
        oid = lfs.get("oid")
        value = oid[7:] if isinstance(oid, str) and oid.startswith("sha256:") else None
    return value.lower() if isinstance(value, str) and _SHA256_RE.fullmatch(value.lower()) else None


def _request_metadata(repository: str, revision: str, opener: Callable | None) -> dict:
    repo_path = urllib.parse.quote(repository, safe="/")
    url = f"https://{_API_HOST}/api/models/{repo_path}/revision/{revision}?blobs=true"
    request = urllib.request.Request(
        url,
        headers={
            "Accept": "application/json",
            "User-Agent": "CyberSentinel-LocalModelAdvisor/5.2",
        },
        method="GET",
    )
    open_request = opener or urllib.request.urlopen
    try:
        with open_request(request, timeout=_REQUEST_TIMEOUT_SECONDS) as response:
            final = urllib.parse.urlsplit(response.geturl())
            if final.scheme != "https" or final.hostname != _API_HOST or final.username or final.password:
                raise CatalogReviewError("hub_metadata_redirect_rejected", 502)
            body = response.read(_MAX_RESPONSE_BYTES + 1)
            if len(body) > _MAX_RESPONSE_BYTES:
                raise CatalogReviewError("hub_metadata_response_too_large", 502)
    except CatalogReviewError:
        raise
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            raise CatalogReviewError("hub_repository_or_revision_not_found_or_private", 404) from None
        if exc.code in {401, 403}:
            raise CatalogReviewError("hub_repository_is_private_or_gated", 403) from None
        if exc.code == 429:
            raise CatalogReviewError("hub_metadata_rate_limited_retry_later", 503) from None
        raise CatalogReviewError("hub_metadata_unavailable", 502) from None
    except (urllib.error.URLError, TimeoutError, OSError):
        raise CatalogReviewError("hub_metadata_unavailable", 502) from None
    try:
        payload = json.loads(body)
    except (json.JSONDecodeError, UnicodeDecodeError, TypeError):
        raise CatalogReviewError("hub_metadata_invalid_json", 502) from None
    if not isinstance(payload, dict):
        raise CatalogReviewError("hub_metadata_invalid_shape", 502)
    return payload


def review_huggingface_candidate(repository: object, revision: object, *, opener: Callable | None = None) -> dict:
    """Resolve one public, immutable Hub revision and report safe-review blockers.

    A successful result is deliberately *never installable*. Dynamic candidates
    remain outside the product's curated catalog until maintainers pin, audit,
    and test the exact artifact and the bundled runtime's support for its GGUF
    architecture.
    """
    if not isinstance(repository, str) or not _REPOSITORY_RE.fullmatch(repository) or ".." in repository:
        raise ValueError("invalid_huggingface_repository_id")
    if not isinstance(revision, str) or not _REVISION_RE.fullmatch(revision):
        raise ValueError("immutable_40_character_commit_sha_required")

    metadata = _request_metadata(repository, revision, opener)
    resolved_sha = metadata.get("sha") if isinstance(metadata.get("sha"), str) else ""
    if not _REVISION_RE.fullmatch(resolved_sha.lower()) or resolved_sha.lower() != revision:
        raise CatalogReviewError("hub_revision_did_not_resolve_to_requested_commit", 409)

    card = metadata.get("cardData") if isinstance(metadata.get("cardData"), dict) else {}
    license_id = card.get("license")
    if isinstance(license_id, list):
        license_id = ", ".join(item for item in license_id if isinstance(item, str))
    if not isinstance(license_id, str) or not license_id.strip():
        license_id = None
    else:
        license_id = license_id.strip()[:120]

    siblings = metadata.get("siblings") if isinstance(metadata.get("siblings"), list) else []
    gguf_siblings = []
    for sibling in siblings:
        if not isinstance(sibling, dict):
            continue
        filename = sibling.get("rfilename") or sibling.get("path")
        if not isinstance(filename, str) or not filename.lower().endswith(".gguf"):
            continue
        size = _int_size(sibling.get("size"))
        lfs = sibling.get("lfs") if isinstance(sibling.get("lfs"), dict) else {}
        size = size or _int_size(lfs.get("size"))
        match = _QUANTIZATION_RE.search(filename.rsplit("/", 1)[-1])
        quantization = match.group(1).upper() if match else None
        sha256 = _lfs_sha256(sibling)
        blockers = []
        if size is None:
            blockers.append("file_size_not_published")
        if sha256 is None:
            blockers.append("trusted_sha256_not_published_by_hub")
        if quantization is None:
            blockers.append("quantization_not_identified_from_filename")
        gguf_siblings.append({
            "filename": filename[:512],
            "size_bytes": size,
            "quantization": quantization,
            "hub_declared_sha256": sha256,
            "sha256_provenance": "Hugging Face Hub LFS metadata; not downloaded or locally recomputed" if sha256 else "unavailable",
            "blockers": blockers,
        })
    gguf_siblings.sort(key=lambda item: item["filename"].casefold())
    truncated = len(gguf_siblings) > _MAX_GGUF_FILES
    gguf_siblings = gguf_siblings[:_MAX_GGUF_FILES]

    blockers = []
    if metadata.get("private") is True or metadata.get("gated") not in (False, None):
        blockers.append("repository_is_private_or_gated")
    if not license_id:
        blockers.append("public_license_not_declared_in_model_card_metadata")
    if not gguf_siblings:
        blockers.append("no_gguf_files_at_this_revision")
    if truncated:
        blockers.append("gguf_file_list_truncated_review_each_file_before_curation")
    if any(not item["hub_declared_sha256"] for item in gguf_siblings):
        blockers.append("one_or_more_files_lack_hub_sha256_metadata")
    if any(item["blockers"] for item in gguf_siblings):
        blockers.append("one_or_more_files_lack_size_hash_or_quantization_metadata")
    blockers.extend([
        "gguf_architecture_header_not_verified_by_this_metadata_only_review",
        "bundled_windows_llama_cpp_cpu_backend_support_not_tested_for_this_artifact",
        "hub_metadata_hash_not_yet_independently_pinned_and_tested_by_product_maintainers",
        "unlisted_models_are_not_added_to_the_installable_product_catalog",
    ])
    blockers = list(dict.fromkeys(blockers))

    return {
        "status": "metadata_reviewed_not_installable",
        "installable": False,
        "repository": repository,
        "requested_revision": revision,
        "resolved_revision": resolved_sha.lower(),
        "revision_is_immutable": True,
        "repository_visibility": "gated_or_private" if metadata.get("private") is True or metadata.get("gated") not in (False, None) else "public_api_response",
        "declared_license": license_id,
        "license_evidence_url": f"https://huggingface.co/{repository}/tree/{revision}",
        "gguf_files": gguf_siblings,
        "blockers": blockers,
        "review_limits": [
            "This request reads only public Hub JSON metadata; it never downloads model weights.",
            "A Hub-declared SHA-256 is shown as evidence, not treated as a product-maintained trusted pin.",
            "No repository script, model-provided code, or installer content is executed.",
            "The existing Windows product installs only models already reviewed and pinned in its built-in catalog.",
        ],
    }
