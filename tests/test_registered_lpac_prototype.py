from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from tests import registered_lpac_prototype as prototype
from tests.registered_lpac_prototype import (
    OwnershipJournal,
    PrototypeError,
    WindowsProfileApi,
    new_run_id,
    profile_name_for_run,
    sha256_text,
)


def test_profile_name_is_unique_valid_and_within_documented_limit() -> None:
    first, second = new_run_id(), new_run_id()
    name_a, name_b = profile_name_for_run(first), profile_name_for_run(second)
    assert first != second
    assert name_a != name_b
    assert len(name_a) <= 64 and len(name_b) <= 64
    assert name_a.startswith("CyberSentinel.LPAC.v1.")
    assert all(ch.isascii() and (ch.isalnum() or ch in "-_. ") for ch in name_a)


@pytest.mark.parametrize("bad_id", ["", "a" * 31, "g" * 32, "../profile", 17, None])
def test_profile_name_refuses_invalid_run_id(bad_id) -> None:
    with pytest.raises(PrototypeError, match="invalid_run_id"):
        profile_name_for_run(bad_id)


def test_journal_is_exclusive_append_only_and_requires_monotonic_lifecycle(tmp_path: Path) -> None:
    path = tmp_path / "owned-profile.jsonl"
    journal = OwnershipJournal.create(path, "1" * 32, "S-1-5-21-100")
    assert journal.state == "CREATE_INTENT"
    with pytest.raises(PrototypeError, match="journal_already_exists"):
        OwnershipJournal.create(path, "1" * 32, "S-1-5-21-100")

    sid_hash = sha256_text("S-1-15-2-1234")
    folder_hash = sha256_text("C:\\Local\\Packages\\profile\\AC")
    journal.transition("PROFILE_CREATED", package_sid_sha256=sid_hash)
    journal.transition("PROFILE_PATH_RESOLVED", profile_folder_sha256=folder_hash)
    journal.transition("PROBE_RUNNING")
    journal.transition("PROBE_COMPLETE")
    journal.transition("CLEANUP_PENDING")
    loaded = OwnershipJournal.load(path)
    assert loaded.state == "CLEANUP_PENDING"
    events = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]
    assert [event["state"] for event in events] == [
        "CREATE_INTENT", "PROFILE_CREATED", "PROFILE_PATH_RESOLVED", "PROBE_RUNNING", "PROBE_COMPLETE", "CLEANUP_PENDING"
    ]
    assert [event["sequence"] for event in events] == list(range(len(events)))
    with pytest.raises(PrototypeError, match="invalid_lifecycle_transition"):
        journal.transition("PROFILE_CREATED", package_sid_sha256=sid_hash, profile_folder_sha256=folder_hash)


def test_partial_or_corrupt_journal_is_quarantined_not_adopted(tmp_path: Path) -> None:
    path = tmp_path / "partial.jsonl"
    journal = OwnershipJournal.create(path, "2" * 32, "S-1-5-21-200")
    assert journal.recovery_decision(
        observed_sid_sha256=None,
        derived_sid_sha256=None,
        owner_sid_sha256=sha256_text("S-1-5-21-200"),
        observed_profile_folder_sha256=None,
        job_is_empty=True,
        handles_closed=True,
    ) == "QUARANTINE_AND_REFUSE"

    path.write_text('{"schema":"broken"', encoding="utf-8")
    with pytest.raises(PrototypeError, match="journal_truncated"):
        OwnershipJournal.load(path)


def test_blank_journal_record_is_rejected(tmp_path: Path) -> None:
    path = tmp_path / "blank-record.jsonl"
    OwnershipJournal.create(path, "5" * 32, "S-1-5-21-250")
    path.write_bytes(path.read_bytes() + b"\n")
    with pytest.raises(PrototypeError, match="journal_blank_record"):
        OwnershipJournal.load(path)


def test_recovery_requires_matching_owner_sid_and_closed_resources(tmp_path: Path) -> None:
    path = tmp_path / "recover.jsonl"
    journal = OwnershipJournal.create(path, "3" * 32, "S-1-5-21-300")
    sid_hash = sha256_text("S-1-15-2-5678")
    folder_hash = sha256_text("C:\\Local\\Packages\\profile\\AC")
    owner_hash = sha256_text("S-1-5-21-300")
    journal.transition("PROFILE_CREATED", package_sid_sha256=sid_hash)
    journal.transition("PROFILE_PATH_RESOLVED", profile_folder_sha256=folder_hash)

    def decision(*, observed=sid_hash, derived=sid_hash, owner=owner_hash, folder=folder_hash, empty=True, closed=True):
        return journal.recovery_decision(
            observed_sid_sha256=observed,
            derived_sid_sha256=derived,
            owner_sid_sha256=owner,
            observed_profile_folder_sha256=folder,
            job_is_empty=empty,
            handles_closed=closed,
        )

    assert decision() == "DELETE_OWNED_PROFILE"
    assert decision(observed="0" * 64) == "QUARANTINE_AND_REFUSE"
    assert decision(derived="0" * 64) == "QUARANTINE_AND_REFUSE"
    assert decision(owner="0" * 64) == "QUARANTINE_AND_REFUSE"
    assert decision(folder="0" * 64) == "QUARANTINE_AND_REFUSE"
    assert decision(empty=False) == "QUARANTINE_AND_REFUSE"
    assert decision(closed=False) == "QUARANTINE_AND_REFUSE"


def test_windows_profile_api_refuses_non_windows_platform(monkeypatch) -> None:
    monkeypatch.setattr(prototype, "os", SimpleNamespace(name="posix"))
    with pytest.raises(PrototypeError, match="windows_only"):
        WindowsProfileApi()


def test_journal_does_not_store_raw_package_sid(tmp_path: Path) -> None:
    journal = OwnershipJournal.create(tmp_path / "journal.jsonl", "4" * 32, "S-1-5-21-400")
    sid = "S-1-15-2-987654"
    journal.transition(
        "PROFILE_CREATED",
        package_sid_sha256=sha256_text(sid),
    )
    journal.transition(
        "PROFILE_PATH_RESOLVED",
        profile_folder_sha256=sha256_text("C:\\Local\\Packages\\profile\\AC"),
    )
    raw = [json.loads(line) for line in journal.path.read_text(encoding="utf-8").splitlines()]
    assert sid not in journal.path.read_text(encoding="utf-8")
    assert raw[-1]["package_sid_sha256"] == sha256_text(sid)
