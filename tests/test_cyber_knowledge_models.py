from datetime import date, timedelta

import pytest

from cyber_knowledge.models import KnowledgeObject, normalize


def test_knowledge_object_hash_identity_and_serialization_are_stable():
    obj = KnowledgeObject(
        observation="web process spawned shell",
        evidence=("process tree",),
        confidence=0.75,
        source="official:test",
        source_type="official",
    )

    assert obj.object_id == f"ko-{obj.content_hash[:16]}"
    assert obj.to_dict()["content_hash"] == obj.content_hash
    assert KnowledgeObject(**{**obj.to_dict(), "content_hash": obj.content_hash}) == obj


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("observation", "", "observation is required"),
        ("confidence", 1.1, "confidence must be between 0 and 1"),
        ("source_type", "unknown", "unsupported source_type"),
        ("date", (date.today() + timedelta(days=1)).isoformat(), "knowledge date cannot be in the future"),
    ],
)
def test_knowledge_object_rejects_invalid_contract_values(field, value, message):
    kwargs = {"observation": "valid observation", "source": "test", "source_type": "local"}
    kwargs[field] = value

    with pytest.raises(ValueError, match=message):
        KnowledgeObject(**kwargs)


def test_knowledge_object_rejects_forged_content_hash():
    with pytest.raises(ValueError, match="content hash mismatch"):
        KnowledgeObject(observation="valid", content_hash="forged")


def test_normalize_filters_empty_values_and_rejects_unknown_shapes():
    obj = normalize(
        {
            "observation": "  observed  ",
            "evidence": ["process tree", "", "  "],
            "mitre": ["T1059"],
            "confidence": "0.5",
        },
        source="official:test",
        source_type="official",
    )

    assert obj.observation == "observed"
    assert obj.evidence == ("process tree",)
    assert obj.mitre == ("T1059",)
    assert obj.confidence == 0.5

    with pytest.raises(ValueError, match="knowledge record must be an object"):
        normalize([], source="test", source_type="local")
    with pytest.raises(ValueError, match="unknown knowledge fields"):
        normalize({"observation": "ok", "instruction": "execute"}, source="test", source_type="local")
