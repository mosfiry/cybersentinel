from __future__ import annotations

import json
from urllib.error import HTTPError

import pytest

from agent.local_runtime.catalog_review import (
    CatalogReviewError,
    review_huggingface_candidate,
)


REVISION = "a" * 40
DIGEST = "b" * 64


class FakeResponse:
    def __init__(self, payload, *, url="https://huggingface.co/api/models/example/model"):
        self._body = json.dumps(payload).encode("utf-8")
        self._url = url

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def geturl(self):
        return self._url

    def read(self, limit):
        assert limit > 0
        return self._body


def _metadata(**overrides):
    data = {
        "sha": REVISION,
        "private": False,
        "gated": False,
        "cardData": {"license": "apache-2.0"},
        "siblings": [
            {
                "rfilename": "Acme-3B-Q4_K_M.gguf",
                "size": 2_000_000_000,
                "lfs": {"size": 2_000_000_000, "sha256": DIGEST},
            },
            {"rfilename": "model.safetensors", "size": 8_000_000},
        ],
    }
    data.update(overrides)
    return data


def test_review_resolves_exact_commit_and_reports_metadata_without_installing():
    calls = []

    def opener(request, *, timeout):
        calls.append((request, timeout))
        return FakeResponse(_metadata())

    result = review_huggingface_candidate("acme/example-model", REVISION, opener=opener)

    assert result["status"] == "metadata_reviewed_not_installable"
    assert result["installable"] is False
    assert result["resolved_revision"] == REVISION
    assert result["revision_is_immutable"] is True
    assert result["declared_license"] == "apache-2.0"
    assert result["gguf_files"][0]["filename"] == "Acme-3B-Q4_K_M.gguf"
    assert result["gguf_files"][0]["quantization"] == "Q4_K_M"
    assert result["gguf_files"][0]["hub_declared_sha256"] == DIGEST
    assert result["gguf_files"][0]["sha256_provenance"].startswith("Hugging Face Hub LFS")
    assert "gguf_architecture_header_not_verified_by_this_metadata_only_review" in result["blockers"]
    assert "unlisted_models_are_not_added_to_the_installable_product_catalog" in result["blockers"]
    assert len(calls) == 1
    request, timeout = calls[0]
    assert request.full_url.startswith("https://huggingface.co/api/models/acme/example-model/revision/")
    assert request.get_method() == "GET"
    assert request.get_header("Authorization") is None
    assert timeout <= 15


def test_review_requires_repository_id_and_immutable_sha_before_network():
    called = False

    def opener(*_args, **_kwargs):
        nonlocal called
        called = True
        raise AssertionError("invalid candidates must not make network requests")

    with pytest.raises(ValueError, match="invalid_huggingface_repository_id"):
        review_huggingface_candidate("https://attacker.example/acme/model", REVISION, opener=opener)
    with pytest.raises(ValueError, match="immutable_40_character_commit_sha_required"):
        review_huggingface_candidate("acme/model", "main", opener=opener)
    assert called is False


def test_review_reports_exact_missing_hash_license_and_gguf_blockers():
    result = review_huggingface_candidate(
        "acme/example-model",
        REVISION,
        opener=lambda *_args, **_kwargs: FakeResponse(_metadata(
            cardData={},
            siblings=[{"rfilename": "weights.gguf", "size": 1024, "lfs": None}],
        )),
    )
    assert result["declared_license"] is None
    assert result["gguf_files"][0]["quantization"] is None
    assert result["gguf_files"][0]["hub_declared_sha256"] is None
    assert "public_license_not_declared_in_model_card_metadata" in result["blockers"]
    assert "one_or_more_files_lack_hub_sha256_metadata" in result["blockers"]
    assert "quantization_not_identified_from_filename" in result["gguf_files"][0]["blockers"]


def test_review_rejects_redirects_outside_fixed_hub_host():
    with pytest.raises(CatalogReviewError, match="hub_metadata_redirect_rejected"):
        review_huggingface_candidate(
            "acme/model",
            REVISION,
            opener=lambda *_args, **_kwargs: FakeResponse(
                _metadata(), url="https://evil.example/api/models/acme/model"
            ),
        )


def test_review_reports_not_found_without_leaking_upstream_response():
    def opener(request, *, timeout):
        raise HTTPError(request.full_url, 404, "not found", {}, None)

    with pytest.raises(CatalogReviewError, match="hub_repository_or_revision_not_found_or_private"):
        review_huggingface_candidate("acme/missing", REVISION, opener=opener)
