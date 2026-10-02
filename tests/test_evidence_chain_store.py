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
