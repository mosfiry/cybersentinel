import json

from agent.mission import Mission, MissionStatus
from agent.model_intelligence.context import ContextAssembler
from agent.planning import Plan


def test_compacted_mission_context_uses_hashes_for_authority_and_omits_duplicate_tool_payload():
    mission = Mission.create(
        "Check system status",
        "Check system status",
        Plan.initial("Check system status"),
        mission_id="mission-context-budget",
    )
    mission.status = MissionStatus.RUNNING
    mission.authorization_context = {"owner_proof": "AUTH_CONTEXT_SENTINEL" + "a" * 3000}
    mission.scope_snapshot = {"scope": ["workspace"], "target": "SCOPE_SENTINEL" + "b" * 1000}
    mission.observations = [{"untrusted": "OBSERVATION_SENTINEL" + "c" * 1800}]
    mission.policy_snapshot = {"bounded_test_blob": "POLICY_SENTINEL" + "p" * 9000}
    tool_output = "LIVE_TOOL_OUTPUT_SENTINEL" + "d" * 1400
    tool_results = [{
        "record_type": "LIVE_TOOL_RESULT",
        "tool_call_id": "call-status-1",
        "name": "status",
        "arguments": {"summary": True},
        "result": {"status": "ok", "untrusted_text": tool_output},
    }]

    assembled = ContextAssembler().build(
        mission,
        tool_results=tool_results,
        tools=[],
        max_chars=8192,
    )
    provider_text = "\n".join(message.content for message in assembled.messages)

    assert assembled.compacted is True
    assert assembled.context_chars <= 8192
    assert "AUTH_CONTEXT_SENTINEL" not in provider_text
    assert "SCOPE_SENTINEL" not in provider_text
    assert "OBSERVATION_SENTINEL" not in provider_text
    assert "POLICY_SENTINEL" not in provider_text
    assert provider_text.count("LIVE_TOOL_OUTPUT_SENTINEL") == 1
    assert "LIVE_TOOL_OUTPUT_SENTINEL" not in json.dumps(assembled.sections["tool"], sort_keys=True)
    binding = assembled.sections["mission"]["authorization_binding"]
    assert binding["record_type"] == "AUTHORIZATION_ENFORCED_OUT_OF_BAND"
    assert binding["authority"] == "none_in_model_context"
    assert len(binding["authorization_context_sha256"]) == 64
    assert len(binding["scope_snapshot_sha256"]) == 64
    assert assembled.sections["tool"][0]["record_type"] == "LIVE_TOOL_RESULT_REFERENCE"
    assert assembled.sections["tool"][0]["trust"] == "untrusted_data"
    assert assembled.sections["observation"][0]["raw_data_omitted"] is True
