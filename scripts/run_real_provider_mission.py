from __future__ import annotations

import json
import os
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from agent.agent_core import AgentCore
from agent.mission import MissionStore
from agent.model_router import ModelRouter
from agent.knowledge_context import TypedKnowledgeRetriever
from knowledge.foundation import KnowledgeKind, KnowledgeObject, TransformationPolicy, TrustClass

router = ModelRouter.from_env()
if not router.providers:
    raise SystemExit("NO_PROVIDER_CONFIGURED")
store = MissionStore(Path(os.environ.get("AUDIT_MISSION_DB", "/tmp/cybersentinel-real-audit.sqlite3")))
fixture = json.loads((ROOT / "knowledge" / "fixtures" / "incident_cve_x.json").read_text(encoding="utf-8"))
objects = [KnowledgeObject.create(**{**item, "kind": KnowledgeKind(item["kind"]), "trust_class": TrustClass(item["trust_class"]), "transformation_policy": TransformationPolicy(item["transformation_policy"])}) for item in fixture["objects"]]
core = AgentCore(router, store=store, max_iterations=8, knowledge_retriever=TypedKnowledgeRetriever(objects, fallback_store=False))
mission = core.run_owner_mission(
    "Investigate whether CVE-2021-44228 was the initial access vector for Incident-A and determine the most supported hypothesis from available local evidence.",
    owner_token=os.environ.get("OWNER_TOKEN", "audit-owner"),
    completion_criteria=[{"criterion_id": "mission-goal", "description": "A tool observation is recorded and verified", "check": "tool observation", "required": True}],
)
print(json.dumps({
    "provider": router.status(),
    "mission_id": mission.mission_id,
    "status": mission.status.value,
    "plan_versions": [item.get("version") for item in mission.plan_history],
    "observations": len(mission.observations),
    "knowledge_objects": len(mission.knowledge_context),
    "hypotheses": mission.hypotheses,
    "interpretations": len(mission.interpretations),
    "replans": len(mission.replan_history),
    "verification": mission.verification_state,
    "trajectory_events": [item.get("event") for item in mission.trajectory],
    "provider_trace": router.last_trace,
}, ensure_ascii=False, default=str))
