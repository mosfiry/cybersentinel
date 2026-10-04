from __future__ import annotations

from pathlib import Path

from agent.agent_core import AgentCore
from agent.mission import MissionStore
from agent.observation_intelligence import ObservationInterpreter
from agent.provider_api import ProviderRequestRejected


class CapturingRouter:
    context_length = 4096

    def __init__(self):
        self.messages = []

    def generate(self, messages, **_kwargs):
        self.messages = list(messages)
        return {"content": '{"summary":"model proposal"}'}


def test_observation_proposal_omits_full_mission_snapshots_and_respects_local_budget(tmp_path: Path):
    router = CapturingRouter()
    core = AgentCore(router, store=MissionStore(tmp_path / "missions.sqlite3"))
    policy_sentinel = "POLICY_SNAPSHOT_SENTINEL_" + "p" * 12000
    history_sentinel = "MISSION_HISTORY_SENTINEL_" + "h" * 12000
    scope_sentinel = "SCOPE_SNAPSHOT_SENTINEL_" + "s" * 12000

    result = core._observation_proposal({
        "mission": {
            "mission_id": "context-budget-mission",
            "request_id": "context-budget-request",
            "objective": "verify local status",
            "owner_instruction": "preserve evidence and do not change authority",
            "policy_snapshot": {"body": policy_sentinel},
            "scope_snapshot": {"body": scope_sentinel},
            "progress": {"history": history_sentinel},
        },
        "plan": {"steps": [{"step_id": "step-1", "action": "status"}]},
        "current_step": {"step_id": "step-1", "objective": "observe current status"},
        "action": "status",
        "observation": {"success": True, "summary": "OBSERVATION_SENTINEL"},
        "evidence": [{"evidence_id": "status-evidence-1", "summary": "EVIDENCE_SENTINEL"}],
        "hypothesis_state": [],
        "knowledge_context": [],
        "conversation_context": [],
    })

    assert result == {"summary": "model proposal"}
    serialized = "\n".join(str(item.get("content", "")) for item in router.messages)
    assert "OBSERVATION_SENTINEL" in serialized
    assert "EVIDENCE_SENTINEL" in serialized
    assert "verify local status" in serialized
    assert "POLICY_SNAPSHOT_SENTINEL" not in serialized
    assert "MISSION_HISTORY_SENTINEL" not in serialized
    assert "SCOPE_SNAPSHOT_SENTINEL" not in serialized
    assert sum(len(str(item.get("content", ""))) for item in router.messages) <= 4096 * 2


def test_observation_fallback_keeps_typed_provider_error_provenance():
    rejected = ProviderRequestRejected(
        "provider request rejected (HTTP 400)",
        provider="local_llama_cpp",
        model="qwen3-4b-q4-k-m",
        status_code=400,
    )

    def fail(_payload):
        raise rejected

    proposal = ObservationInterpreter(proposer=fail).interpret(
        mission={"mission_id": "fallback-mission"},
        plan={},
        current_step=None,
        action="status",
        observation={"success": True, "summary": "deterministic observation retained"},
        evidence=[],
        hypothesis_state={},
    )

    assert proposal.summary == "deterministic observation retained"
    assert proposal.provenance["model_status"] == "unavailable_or_malformed"
    assert proposal.provenance["model_error"] == "ProviderRequestRejected"
    assert proposal.provenance["model_error_kind"] == "REQUEST_REJECTED"
    assert proposal.provenance["model_http_status"] == 400
