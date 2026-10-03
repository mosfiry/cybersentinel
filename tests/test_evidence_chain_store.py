from concurrent.futures import ThreadPoolExecutor
import json
import sqlite3
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

from agent.evidence import Evidence, EvidenceChainStore, observed, verify_chain


def test_append_rehashes_evidence_after_assigning_chain_position(tmp_path):
    store = EvidenceChainStore(tmp_path / "evidence.sqlite3")

    first_input = observed("first", "test", {"value": 1})
    first = store.append(first_input)
    second_input = observed("second", "test", {"value": 2})
    second = store.append(second_input)

    records = store.list()
    assert [record["sequence"] for record in records] == [1, 2]
    assert records[0]["previous_hash"] == ""
    assert records[1]["previous_hash"] == records[0]["current_hash"]
    assert first["current_hash"] != first_input["current_hash"]
    assert second["current_hash"] != second_input["current_hash"]
    assert all(Evidence(**record).verify() for record in records)
    assert store.verify()


def test_concurrent_appends_are_serialized_into_one_valid_chain(tmp_path):
    database = tmp_path / "concurrent-evidence.sqlite3"
    stores = [EvidenceChainStore(database) for _ in range(8)]

    def append(index):
        return stores[index % len(stores)].append(
            {
                "claim": f"claim-{index}",
                "source": "concurrency-test",
                "evidence": {"index": index},
                "request_id": "concurrent-request",
            }
        )

    with ThreadPoolExecutor(max_workers=8) as executor:
        returned = list(executor.map(append, range(64)))

    records = stores[0].list()
    assert len(returned) == 64
    assert [record["sequence"] for record in records] == list(range(1, 65))
    assert len({record["current_hash"] for record in records}) == 64
    assert stores[0].verify()


def test_chain_verification_detects_payload_tampering(tmp_path):
    database = tmp_path / "tampered-evidence.sqlite3"
    store = EvidenceChainStore(database)
    store.append(observed("original", "test", {"value": 1}))

    with sqlite3.connect(database) as db:
        row = db.execute("SELECT payload FROM evidence_chain WHERE sequence=1").fetchone()
        payload = json.loads(row[0])
        payload["claim"] = "tampered"
        db.execute(
            "UPDATE evidence_chain SET payload=? WHERE sequence=1",
            (json.dumps(payload),),
        )

    assert store.verify() is False


def test_failed_serialization_rolls_back_without_consuming_chain_sequence(tmp_path):
    store = EvidenceChainStore(tmp_path / "rollback-evidence.sqlite3")

    with pytest.raises(TypeError):
        store.append(
            {
                "claim": "invalid evidence",
                "source": "test",
                "evidence": {"not_json": {1, 2, 3}},
            }
        )

    first = store.append(observed("first valid", "test", {"value": 1}))
    assert first["sequence"] == 1
    assert first["previous_hash"] == ""
    assert store.verify()


def test_confidence_outside_integer_zero_to_ten_is_rejected_and_fails_verification():
    record = observed("bounded confidence", "test", {"value": 1})
    record["confidence"] = 11

    with pytest.raises(ValueError, match="confidence"):
        Evidence(**record)
    assert verify_chain([record]) is False


def test_duplicate_evidence_ids_are_rejected_on_append(tmp_path):
    store = EvidenceChainStore(tmp_path / "duplicate-evidence.sqlite3")
    first = observed("first", "test", {"value": 1})
    first["evidence_id"] = "stable-evidence-id"
    store.append(first)

    second = observed("second", "test", {"value": 2})
    second["evidence_id"] = "stable-evidence-id"
    with pytest.raises(ValueError, match="duplicate evidence identity"):
        store.append(second)

    assert len(store.list()) == 1
    assert store.verify()


def test_chain_verification_rejects_recomputed_duplicate_evidence_ids():
    first = Evidence(
        "first",
        "test",
        {"value": 1},
        evidence_id="duplicate-id",
        sequence=1,
    ).to_dict()
    second = Evidence(
        "second",
        "test",
        {"value": 2},
        evidence_id="duplicate-id",
        sequence=2,
        previous_hash=first["current_hash"],
    ).to_dict()

    assert verify_chain([first, second]) is False


def test_chain_verification_rejects_a_missing_previous_hash_field():
    record = observed("missing previous hash", "test", {"value": 1})
    del record["previous_hash"]

    assert verify_chain([record]) is False


def test_process_death_during_uncommitted_append_rolls_back_the_record(tmp_path):
    database = tmp_path / "crash-during-append.sqlite3"
    store = EvidenceChainStore(database)
    with sqlite3.connect(database) as db:
        db.execute(
            "CREATE TRIGGER pause_before_commit AFTER INSERT ON evidence_chain "
            "BEGIN SELECT cs_test_barrier(); END"
        )

    child_script = textwrap.dedent(
        """
        import sys
        import agent.evidence as evidence_module

        original_connect = evidence_module.sqlite3.connect

        def connect_with_barrier(*args, **kwargs):
            connection = original_connect(*args, **kwargs)

            def barrier():
                print("UNCOMMITTED_EVIDENCE_INSERT", flush=True)
                sys.stdin.readline()
                return 0

            connection.create_function("cs_test_barrier", 0, barrier)
            return connection

        evidence_module.sqlite3.connect = connect_with_barrier
        chain = evidence_module.EvidenceChainStore(sys.argv[1])
        chain.append({"claim": "in-flight", "source": "process-death-test", "evidence": {"value": 1}})
        """
    )
    process = subprocess.Popen(
        [sys.executable, "-c", child_script, str(database)],
        cwd=Path(__file__).resolve().parents[1],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        assert process.stdout is not None
        barrier = process.stdout.readline().strip()
        assert barrier == "UNCOMMITTED_EVIDENCE_INSERT"
        process.kill()
        process.communicate(timeout=10)
    finally:
        if process.poll() is None:
            process.kill()
            process.communicate(timeout=10)

    recovered = EvidenceChainStore(database)
    assert recovered.list() == []
    assert recovered.verify()
