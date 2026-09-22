from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sys
from urllib.request import Request, urlopen

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


def emit(payload: dict, *, code: int = 0) -> None:
    print(json.dumps(payload, ensure_ascii=False, default=str, indent=2))
    raise SystemExit(code)


def discover_model() -> str | None:
    base = os.environ.get("OPENAI_API_BASE", "").rstrip("/")
    key = os.environ.get("OPENAI_API_KEY", "")
    if not base or not key:
        return None
    try:
        request = Request(f"{base}/models", headers={"Authorization": f"Bearer {key}"})
        with urlopen(request, timeout=10) as response:
            payload = json.load(response)
        models = [str(item.get("id")) for item in payload.get("data", []) if item.get("id")]
        return os.environ.get("REAL_PROVIDER_MODEL") or (models[0] if models else None)
    except Exception:
        return os.environ.get("REAL_PROVIDER_MODEL")


def configure_provider() -> str | None:
    if os.environ.get("LLM_BASE_URL") and os.environ.get("LLM_MODEL"):
        return os.environ["LLM_MODEL"]
    base = os.environ.get("OPENAI_API_BASE", "").strip()
    key = os.environ.get("OPENAI_API_KEY", "").strip()
    model = discover_model()
    if base and key and model:
        os.environ["LLM_BASE_URL"] = base
        os.environ["LLM_API_KEY"] = key
        os.environ["LLM_MODEL"] = model
        os.environ.setdefault("LLM_TOOL_CALLING", "true")
        os.environ.setdefault("LLM_STRUCTURED_OUTPUT", "true")
        return model
    return None


def main() -> None:
    parser = argparse.ArgumentParser(description="REAL provider CyberSentinel long-horizon acceptance harness")
    parser.add_argument("--db", default=os.environ.get("AUDIT_MISSION_DB", "/tmp/cybersentinel-real-audit.sqlite3"))
    parser.add_argument("--resume", help="resume an existing mission id")
    parser.add_argument("--max-iterations", type=int, default=8)
    parser.add_argument("--owner-token", default=os.environ.get("OWNER_TOKEN", ""))
    parser.add_argument("--artifact", default=os.environ.get("REAL_ARTIFACT", ""))
    args = parser.parse_args()

    model = configure_provider()
    if not args.owner_token:
        emit({"status": "BLOCKED", "reason": "OWNER_TOKEN_REQUIRED", "provider_model": model}, code=2)

    from agent.agent_core import AgentCore
    from agent.mission import MissionStore
    from agent.model_router import ModelRouter
    from agent.knowledge_context import TypedKnowledgeRetriever
    from knowledge.foundation import KnowledgeKind, KnowledgeObject, TransformationPolicy, TrustClass

    router = ModelRouter.from_env()
    if not router.providers:
        emit({"status": "BLOCKED", "reason": "NO_PROVIDER_CONFIGURED", "provider_model": model}, code=2)
    store = MissionStore(Path(args.db))
    fixture = json.loads((ROOT / "knowledge" / "fixtures" / "incident_cve_x.json").read_text(encoding="utf-8"))
    objects = [KnowledgeObject.create(**{**item, "kind": KnowledgeKind(item["kind"]), "trust_class": TrustClass(item["trust_class"]), "transformation_policy": TransformationPolicy(item["transformation_policy"])}) for item in fixture["objects"]]
    core = AgentCore(router, store=store, max_iterations=args.max_iterations, knowledge_retriever=TypedKnowledgeRetriever(objects, fallback_store=False))
    if args.resume:
        mission = core.resume_mission(args.resume, owner_token=args.owner_token, max_slices=args.max_iterations)
    else:
        mission = core.run_owner_mission(
            "Investigate whether CVE-2021-44228 was the initial access vector for Incident-A and determine the most supported hypothesis from available local evidence.",
            owner_token=args.owner_token,
            completion_criteria=[{"criterion_id": "mission-goal", "description": "A tool observation is recorded and verified", "check": "tool observation", "required": True}],
        )
    result = {
        "status": "PASS" if mission.status.value == "GOAL_COMPLETED" else "INCOMPLETE",
        "provider": router.status(),
        "mission_id": mission.mission_id,
        "mission_status": mission.status.value,
        "plan_versions": [item.get("version") for item in mission.plan_history],
        "observations": len(mission.observations),
        "knowledge_objects": len(mission.knowledge_context),
        "hypotheses": mission.hypotheses,
        "interpretations": len(mission.interpretations),
        "replans": len(mission.replan_history),
        "verification": mission.verification_state,
        "trajectory_events": [item.get("event") for item in mission.trajectory],
        "provider_trace": router.last_trace,
    }
    if args.artifact:
        Path(args.artifact).write_text(json.dumps(result, ensure_ascii=False, default=str, indent=2) + "\n", encoding="utf-8")
    emit(result, code=0 if result["status"] == "PASS" else 1)


if __name__ == "__main__":
    main()
