import json

import pytest

from cyber_data.ingestion import load_jsonl, quality_filter
from cyber_knowledge.models import KnowledgeObject


def _record(observation, confidence=0.8):
    return {"observation": observation, "confidence": confidence, "evidence": ["fixture"]}


def test_load_jsonl_skips_blank_short_and_duplicate_records(tmp_path):
    first = _record("A sufficiently long observation")
    duplicate = dict(first)
    short = _record("short")
    path = tmp_path / "knowledge.jsonl"
    path.write_text(
        "\n".join(
            [
                "",
                json.dumps(first),
                json.dumps(duplicate),
                json.dumps(short),
                "  ",
            ]
        ),
        encoding="utf-8",
    )

    objects = load_jsonl(path, source="fixture", source_type="local")

    assert len(objects) == 1
    assert objects[0].observation == "A sufficiently long observation"
    assert objects[0].source == "fixture"
    assert objects[0].source_type == "local"


def test_load_jsonl_reports_invalid_record_line_number(tmp_path):
    path = tmp_path / "invalid.jsonl"
    path.write_text('{"observation":"valid observation"}\nnot-json\n', encoding="utf-8")

    with pytest.raises(ValueError, match=r"invalid knowledge record at line 2: Expecting value"):
        load_jsonl(path, source="fixture", source_type="local")


def test_load_jsonl_wraps_missing_file_errors(tmp_path):
    with pytest.raises(ValueError, match="unable to read knowledge file"):
        load_jsonl(tmp_path / "missing.jsonl", source="fixture", source_type="local")


def test_load_jsonl_wraps_invalid_utf8_errors(tmp_path):
    path = tmp_path / "invalid-encoding.jsonl"
    path.write_bytes(b"\xff\xfe")

    with pytest.raises(ValueError, match="unable to read knowledge file"):
        load_jsonl(path, source="fixture", source_type="local")


def test_load_jsonl_wraps_normalization_errors_with_line_number(tmp_path):
    path = tmp_path / "invalid-field.jsonl"
    path.write_text(
        json.dumps({"observation": "valid observation", "unexpected": True}) + "\n",
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match=r"invalid knowledge record at line 1: unknown knowledge fields"):
        load_jsonl(path, source="fixture", source_type="local")


def test_quality_filter_requires_confidence_source_and_hash():
    accepted = KnowledgeObject(
        observation="accepted knowledge observation",
        confidence=0.5,
        source="official",
        source_type="official",
    )
    low_confidence = KnowledgeObject(
        observation="low confidence observation",
        confidence=0.19,
        source="official",
        source_type="official",
    )
    no_source = KnowledgeObject(
        observation="observation without source",
        confidence=0.9,
        source="",
        source_type="local",
    )

    assert quality_filter([accepted, low_confidence, no_source]) == [accepted]
    assert quality_filter([accepted], min_confidence=0.6) == []
