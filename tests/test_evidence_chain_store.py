from concurrent.futures import ThreadPoolExecutor
import json
import sqlite3

import pytest

from agent.evidence import Evidence, EvidenceChainStore, observed


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
