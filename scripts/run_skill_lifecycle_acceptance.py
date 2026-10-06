#!/usr/bin/env python3
"""Focused Owner Skill lifecycle acceptance using real MissionRuntime tool execution.

The planner provider is deterministic and local; the canonical run_project_tests
registered tool, Owner scope, Mission evidence, validators, Skill registry, and
OwnerSkillService are production implementations. This is not the no-mock full E2E.
"""
from __future__ import annotations

import argparse
from dataclasses import replace
import json
from pathlib import Path
import sys
import uuid

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--artifact", required=True, type=Path)
    parser.add_argument("--state-dir", required=True, type=Path)
    args = parser.parse_args()
    artifact_path = args.artifact.expanduser().resolve()
    run_dir = args.state_dir.expanduser().resolve() / ("run-" + uuid.uuid4().hex[:12])
    run_dir.mkdir(parents=True, exist_ok=False)
    artifact_path.parent.mkdir(parents=True, exist_ok=True)

    result: dict = {
        "schema": "owner-skill-lifecycle-acceptance-v1",
        "status": "FAIL",
        "provider_mode": "deterministic_local_tool-proposal; canonical MissionRuntime tool dispatch is real",
        "state_dir": str(run_dir),
        "checks": {},
    }
    patcher = None
    try:
        import pytest
        from owner_session_testutils import (
            allow_owner_sessions,
            persist_canonical_scope,
            workspace_scope_context,
        )
        from test_owner_skill_service import StatusProvider, _candidate_definition

        from agent.agent_core import AgentCore
        from agent.intelligence_layer.models import DelegationScope
        from agent.intelligence_layer.skills import (
            SkillAuthorizationError,
            SkillDefinition,
            SkillStatus,
            validate_skill_definition,
        )
        from agent.mission import MissionStore
        from agent.mission_runtime import MissionRuntime
        from agent.mission_worker import MissionQueue
        from agent.model_router import ModelRouter
        from api.missions import MissionService
        from api.skills import OwnerSkillService

        owner_token = "skill-lifecycle-owner-session"
        owner_ref = "owner:1"
        project = run_dir / "owner-project"
        project.mkdir()
        (project / "test_skill_acceptance.py").write_text(
            "def test_skill_acceptance_fixture():\n    assert 3 * 7 == 21\n",
            encoding="utf-8",
        )

        patcher = pytest.MonkeyPatch()
        allow_owner_sessions(patcher, owner_token)
        scope_snapshot = persist_canonical_scope(
            patcher,
            run_dir,
            owner_session_token=owner_token,
            target_id="local-project:skill-lifecycle-acceptance",
        )
        scope_context = workspace_scope_context(scope_snapshot, project)
        store = MissionStore(run_dir / "missions.sqlite3")

        # Mission A supplies server-verified, fenced evidence for the candidate.
        source_core = AgentCore(ModelRouter([StatusProvider()]), store=store)
        mission_a = source_core.run_owner_mission(
            "Run project tests and verify they pass",
            owner_session_token=owner_token,
            scope_context=scope_context,
        )
        runtime = MissionRuntime(
            store,
            executor=source_core._executor,
            require_execution_fence=True,
        )
        mission_service = MissionService(
            runtime,
            MissionQueue(run_dir / "management-queue.sqlite3"),
        )
        service = OwnerSkillService(run_dir / "skills.sqlite3", mission_service)

        definition_v1 = _candidate_definition("Bounded project-test skill v1")
        validate_skill_definition(definition_v1, service.registry.tool_specs)
        candidate_v1 = service.submit_candidate(
            owner_token,
            mission_a.mission_id,
            definition_v1.to_dict(),
        )
        discovered = service.list_revisions(owner_token)
        detail = service.detail(owner_token, definition_v1.skill_id, 1)
        mission_a_tools = [step.action for step in mission_a.plan.steps]
        result["checks"]["mission_a_real_owner_mission_completed_with_tool_evidence"] = (
            mission_a.status.value == "GOAL_COMPLETED"
            and mission_a.verify_integrity()
            and mission_a.verification_state.get("verified") is True
            and mission_a_tools == ["run_project_tests"]
            and len(mission_a.action_history) == 1
            and bool(mission_a.evidence)
        )
        result["checks"]["discover_and_validate_candidate"] = (
            len(discovered) == 1
            and discovered[0]["status"] == "candidate"
            and discovered[0]["active"] is False
            and candidate_v1["execution_mode"] == "untrusted_guidance_only"
            and detail["content_hash"] == candidate_v1["content_hash"]
        )
        result["checks"]["candidate_is_not_active_before_owner_approval"] = (
            service.registry.get_active(owner_ref, definition_v1.skill_id) is None
        )

        approved_v1 = service.approve(
            owner_token,
            definition_v1.skill_id,
            1,
            candidate_v1["content_hash"],
        )
        active_v1 = service.registry.get_active(owner_ref, definition_v1.skill_id)
        result["checks"]["owner_approval_activates_installable_revision"] = (
            approved_v1["status"] == "approved"
            and approved_v1["active"] is True
            and active_v1 is not None
            and active_v1.definition.version == 1
        )

        # Mission B selects the approved Skill. AgentCore binds it as untrusted
        # guidance, while the real tool call is still authorized by the Owner snapshot.
        execution_core = AgentCore(
            ModelRouter([StatusProvider()]),
            store=store,
            skill_registry=service.registry,
        )
        mission_b = execution_core.run_owner_mission(
            "Run project tests and verify they pass",
            owner_session_token=owner_token,
            scope_context=scope_context,
            skill_id=definition_v1.skill_id,
        )
        selected_context = service.registry.resolve_mission_context(
            mission_b,
            canonical_owner_identity_ref=owner_ref,
        )
        untrusted_context = selected_context.to_untrusted_context()
        from security.mission_authorization import MissionAuthorizationSnapshot
        owner_snapshot = MissionAuthorizationSnapshot.from_dict(mission_b.authorization_snapshot)
        parent_scope = DelegationScope.from_snapshot(owner_snapshot)
        try:
            selected_context.narrow_task_scope(parent_scope, tool_name="latest_intel")
            unauthorized_action_denied = False
        except SkillAuthorizationError:
            unauthorized_action_denied = True

        analysis_b = service.analyze_mission(owner_token, mission_b.mission_id)
        plan_tools = [step.action for step in mission_b.plan.steps]
        result["checks"]["install_and_execute_in_skill_bound_real_mission"] = (
            mission_b.status.value == "GOAL_COMPLETED"
            and mission_b.verify_integrity()
            and mission_b.skill_binding is not None
            and mission_b.skill_binding.get("version") == 1
            and plan_tools == ["run_project_tests"]
            and len(mission_b.action_history) == 1
            and bool(mission_b.evidence)
        )
        result["checks"]["evaluate_execution_with_verified_evidence"] = (
            analysis_b["outcome_class"] == "verified_success"
            and analysis_b["verified"] is True
            and analysis_b["candidate_seed_eligible"] is True
            and analysis_b["evidence_count"] >= 1
        )
        result["checks"]["skill_remains_without_authority"] = (
            untrusted_context.get("record_type") == "UNTRUSTED_SKILL_GUIDANCE"
            and untrusted_context.get("authority") == "none"
            and untrusted_context.get("allowed_tools_ceiling") == ["run_project_tests"]
            and set(plan_tools).issubset(set(owner_snapshot.allowed_tools))
            and set(plan_tools).issubset(set(owner_snapshot.allowed_actions))
            and unauthorized_action_denied
            and "allowed_credentials" not in untrusted_context
            and "allowed_networks" not in untrusted_context
        )

        # Version 2 is immutable and separately approved; rollback and retirement
        # are owner-session/hash/provenance checked through the public service.
        definition_v2: SkillDefinition = replace(
            _candidate_definition("Bounded project-test skill v2"),
            version=2,
            content_hash="",
        )
        candidate_v2 = service.submit_candidate(
            owner_token,
            mission_a.mission_id,
            definition_v2.to_dict(),
        )
        approved_v2 = service.approve(
            owner_token,
            definition_v2.skill_id,
            2,
            candidate_v2["content_hash"],
        )
        active_after_v2 = service.registry.get_active(owner_ref, definition_v2.skill_id)
        result["checks"]["immutable_version_2_activated"] = (
            candidate_v2["version"] == 2
            and approved_v2["active"] is True
            and active_after_v2 is not None
            and active_after_v2.definition.version == 2
            and service.registry.get_revision(owner_ref, definition_v1.skill_id, 1).definition.content_hash
            == candidate_v1["content_hash"]
        )

        rolled_back = service.rollback(
            owner_token,
            definition_v1.skill_id,
            1,
            candidate_v1["content_hash"],
        )
        active_after_rollback = service.registry.get_active(owner_ref, definition_v1.skill_id)
        result["checks"]["owner_approved_rollback_to_v1"] = (
            rolled_back["active"] is True
            and active_after_rollback is not None
            and active_after_rollback.definition.version == 1
        )
        retired = service.deprecate(
            owner_token,
            definition_v1.skill_id,
            1,
            candidate_v1["content_hash"],
        )
        result["checks"]["retirement_disables_future_installation"] = (
            retired["status"] == "deprecated"
            and retired["active"] is False
            and service.registry.get_active(owner_ref, definition_v1.skill_id) is None
        )
        try:
            service.registry.bind_mission(owner_ref, "post-retirement-mission", definition_v1.skill_id)
            retired_skill_blocked = False
        except SkillAuthorizationError:
            retired_skill_blocked = True
        result["checks"]["retired_skill_cannot_be_bound"] = retired_skill_blocked

        events = service.registry.events(owner_ref, definition_v1.skill_id)
        result["skill"] = {
            "skill_id": definition_v1.skill_id,
            "content_hash_v1": candidate_v1["content_hash"],
            "content_hash_v2": candidate_v2["content_hash"],
            "source_mission_id": mission_a.mission_id,
            "bound_mission_id": mission_b.mission_id,
            "binding_version": mission_b.skill_binding.get("version"),
            "owner_authorized_tools": list(owner_snapshot.allowed_tools),
            "skill_tool_ceiling": list(untrusted_context.get("allowed_tools_ceiling", ())),
            "unauthorized_tool_denied": unauthorized_action_denied,
            "lifecycle_events": [
                {"action": item["action"], "version": item["version"], "decision_id": item["decision_id"]}
                for item in events
            ],
        }
        result["mission_a"] = {
            "mission_id": mission_a.mission_id,
            "status": mission_a.status.value,
            "integrity_verified": mission_a.verify_integrity(),
            "executed_tools": mission_a_tools,
            "evidence_count": len(mission_a.evidence),
            "validator_verified": mission_a.verification_state.get("verified") is True,
        }
        result["mission_b"] = {
            "mission_id": mission_b.mission_id,
            "status": mission_b.status.value,
            "integrity_verified": mission_b.verify_integrity(),
            "executed_tools": plan_tools,
            "evidence_count": len(mission_b.evidence),
            "validator_verified": mission_b.verification_state.get("verified") is True,
            "skill_evaluation": {
                "outcome_class": analysis_b["outcome_class"],
                "candidate_seed_eligible": analysis_b["candidate_seed_eligible"],
                "evidence_count": analysis_b["evidence_count"],
            },
        }
        result["checks"]["all_lifecycle_checks_pass"] = all(result["checks"].values())
        result["status"] = "PASS" if result["checks"]["all_lifecycle_checks_pass"] else "FAIL"
    except Exception as exc:  # emit a bounded failure record for diagnosis
        result["error_type"] = type(exc).__name__
        result["error"] = str(exc)[:300]
        result["status"] = "FAIL"
    finally:
        if patcher is not None:
            patcher.undo()

    artifact_path.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if result["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
