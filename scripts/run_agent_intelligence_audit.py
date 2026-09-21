from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import sys
import tempfile
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from agent.agent_core import AgentCore
from agent.knowledge_context import TypedKnowledgeRetriever
from agent.mission import MissionStatus, MissionStore
from agent.mission_runtime import MissionRuntime
from agent.model_router import ModelRouter
from agent.hypotheses import HypothesisState, HypothesisStatus
from agent.planning import Plan, PlanStep
from knowledge.foundation import KnowledgeKind, KnowledgeObject, TransformationPolicy, TrustClass


FIXTURE = ROOT / "knowledge" / "fixtures" / "incident_cve_x.json"


def load_fixture() -> TypedKnowledgeRetriever:
    data = json.loads(FIXTURE.read_text(encoding="utf-8"))
    objects = [KnowledgeObject.create(**{
        **item,
        "kind": KnowledgeKind(item["kind"]),
        "trust_class": TrustClass(item["trust_class"]),
        "transformation_policy": TransformationPolicy(item["transformation_policy"]),
    }) for item in data["objects"]]
    return TypedKnowledgeRetriever(objects, fallback_store=False)


def synthetic_e2e() -> dict[str, Any]:
    with tempfile.TemporaryDirectory(prefix="cybersentinel-audit-") as directory:
        store = MissionStore(Path(directory) / "missions.sqlite3")
        calls = []

        def execute(mission, step, action_id):
            calls.append(step.action)
            if len(calls) == 1:
                return {
                    "success": True,
                    "source": "fixture-patch-record",
                    "summary": "target version is not vulnerable",
                    "counter_evidence": [{"evidence_id": "E17", "claim": "version outside vulnerable range"}],
                    "confidence_changes": [{"hypothesis_id": "H1", "delta": -0.3, "reason": "target version is outside vulnerable range", "counter_evidence_ids": ["E17"]}],
                    "hypothesis_updates": [{"hypothesis_id": "H1", "status": "WEAKENED"}, {"hypothesis_id": "H2", "statement": "external remote service was initial access", "status": "ACTIVE"}],
                    "recommended_strategy_change": "investigate alternate initial access",
                    "criterion_id": "first-observation",
                }
            if len(calls) == 2:
                return {
                    "success": True,
                    "source": "fixture-researcher-report",
                    "summary": "IOC and remote-service evidence support the alternate path",
                    "evidence": [{"evidence_id": "E18", "claim": "IOC preceded the first confirmed session"}],
                    "confidence_changes": [{"hypothesis_id": "H2", "delta": 0.25, "reason": "independent IOC timing supports alternate path", "supporting_evidence_ids": ["E18"]}],
                    "criterion_id": "second-observation",
                }
            return {"success": True, "source": "fixture-patch-record", "summary": "required evidence reconciled", "criterion_id": "goal"}

        def replan(mission, observation):
            version = mission.plan.version
            step_id = f"investigation-{version}"
            return mission.plan.replan(steps=(PlanStep(step_id, "collect next evidence", action="search", verification=("goal",)),), reason=observation.get("strategy_decision", {}).get("reason", "adaptive observation"))

        runtime = MissionRuntime(store, executor=execute, replanner=replan)
        plan = Plan.initial("Investigate whether CVE-X was the initial access vector for Incident-A").replan(steps=(PlanStep("initial", "retrieve patch evidence", action="search"),), reason="initial")
        mission = runtime.create("Investigate the incident", "Investigate whether CVE-X was the initial access vector for Incident-A", plan, completion_criteria=[{"criterion_id": "goal", "required": True}])
        mission.hypotheses = [HypothesisState("H1", "CVE-X caused initial access", HypothesisStatus.ACTIVE, 0.8).to_dict()]
        mission.knowledge_context = [item.to_dict() for item in load_fixture().retrieve("CVE-X Incident-A", limit=4)]
        store.save(mission)
        final = runtime.run_to_completion(mission.mission_id, max_slices=12)
        return {
            "status": final.status.value,
            "mission_id": final.mission_id,
            "plan_versions": [item["version"] for item in final.plan_history],
            "observations": len(final.observations),
            "hypothesis_updates": len([item for item in final.trajectory if item.get("event") == "HypothesisUpdated"]),
            "replans": len(final.replan_history),
            "transitions": final.transitions,
            "authorization_decisions": [item for item in final.trajectory if item.get("event") == "AuthorizationChecked"],
            "scope_decisions": [item for item in final.failures if item.get("class") == "SCOPE"],
            "recovery_events": final.recovery_events,
            "verification": final.verification_state,
            "trajectory": final.trajectory,
            "knowledge_objects": len(final.knowledge_context),
            "calls": calls,
            "passed": final.status is MissionStatus.GOAL_COMPLETED and len(final.replan_history) >= 1 and len(final.observations) >= 3,
        }


def real_provider_probe() -> dict[str, Any]:
    router = ModelRouter.from_env()
    status = router.status()
    result: dict[str, Any] = {"configured": bool(status), "status": status, "provider": "unavailable", "model": "unavailable", "probe": "NOT_RUN"}
    if not status:
        result["limitation"] = "No LLM_BASE_URL/LLM_MODEL provider is configured in this process."
        return result
    try:
        response = router.generate([{"role": "system", "content": "Return JSON only."}, {"role": "user", "content": "Return {\"probe\":\"ok\"} for a safe connectivity test."}])
        result.update({"provider": response.get("provider"), "model": response.get("model"), "probe": "PASS", "response_content": str(response.get("content", ""))[:500]})
    except Exception as exc:
        result.update({"probe": "FAIL", "error": type(exc).__name__})
    return result


def real_agent_mission() -> dict[str, Any]:
    router = ModelRouter.from_env()
    if not router.providers:
        return {"status": "NOT_RUN", "reason": "no provider configured"}
    with tempfile.TemporaryDirectory(prefix="cybersentinel-real-audit-") as directory:
        try:
            core = AgentCore(router, store=MissionStore(Path(directory) / "missions.sqlite3"), max_iterations=8, knowledge_retriever=load_fixture())
            mission = core.run_owner_mission(
                "Investigate whether CVE-2021-44228 was the initial access vector for Incident-A and determine the most supported hypothesis from available local evidence.",
                owner_token=os.environ.get("OWNER_TOKEN", "audit-owner"),
                completion_criteria=[{"criterion_id": "mission-goal", "description": "A tool observation is recorded and verified", "check": "tool observation", "required": True}],
            )
            return {
                "status": mission.status.value,
                "mission_id": mission.mission_id,
                "provider": router.status(),
                "plan_versions": [item.get("version") for item in mission.plan_history],
                "observations": len(mission.observations),
                "interpretations": len(mission.interpretations),
                "replans": len(mission.replan_history),
                "verification": mission.verification_state,
                "trajectory_events": [item.get("event") for item in mission.trajectory],
            }
        except Exception as exc:
            return {"status": "FAIL", "provider": router.status(), "error": type(exc).__name__}


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", default=str(ROOT / "docs" / "AGENT_INTELLIGENCE_AUDIT.md"))
    args = parser.parse_args()
    commit = __import__("subprocess").check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
    synthetic = synthetic_e2e()
    real = real_provider_probe()
    real_mission = real_agent_mission()
    lines = [
        "# CyberSentinel X Agent Intelligence Audit",
        "",
        f"Generated at: `{datetime.now(timezone.utc).isoformat()}`  ",
        f"Commit: `{commit}`  ",
        "Baseline: `25307b88960d7e9a04cb9ce14c3b00b8fbcee41e` with 276 tests before this upgrade.",
        "",
        "## Scope",
        "",
        "This report records the adaptive-loop audit. It does not claim production readiness, full autonomy, or super-intelligence. External knowledge, model output, memory, and tool results remain untrusted data or proposals; Owner Instruction and deterministic enforcement remain authoritative.",
        "",
        "## Real provider",
        "",
        "```json",
        json.dumps(real, ensure_ascii=False, indent=2, default=str),
        "```",
        "",
        "## Real AgentCore mission",
        "",
        "```json",
        json.dumps(real_mission, ensure_ascii=False, indent=2, default=str),
        "```",
        "",
        "## Safe end-to-end trajectory",
        "",
        "```json",
        json.dumps({key: value for key, value in synthetic.items() if key != "trajectory"}, ensure_ascii=False, indent=2, default=str),
        "```",
        "",
        "### Trajectory",
        "",
        "```json",
        json.dumps(synthetic["trajectory"], ensure_ascii=False, indent=2, default=str),
        "```",
        "",
        "## Architecture paths",
        "",
        "Knowledge Sources → Typed Knowledge Store → BM25/typed Retriever → RetrievalResult with provenance → ContextEngine → ModelRouter.",
        "",
        "Observation → ObservationInterpreter → typed proposal → HypothesisEngine → StrategyDecision → deterministic objective/scope/authorization checks → replanning or continuation → persistence → verification.",
        "",
        "## Limitations",
        "",
        "- The real-provider and real-AgentCore mission results are reported exactly as observed; a missing or failing provider prevents the real-model acceptance claim.",
        "- The synthetic fixture is safe and does not execute attack tooling. It validates long-horizon state transitions, counter-evidence, multiple observations, and replanning through the actual MissionRuntime, persistence, typed retrieval, and deterministic controls.",
        "- A real-provider mission audit must be rerun in an environment where the existing configured `default/gpt-5-mini` route is available; no new model or provider was introduced.",
    ]
    Path(args.output).write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(json.dumps({"output": args.output, "synthetic_passed": synthetic["passed"], "real_provider": real, "real_mission": real_mission}, ensure_ascii=False, default=str))


if __name__ == "__main__":
    main()
