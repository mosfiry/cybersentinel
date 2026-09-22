from __future__ import annotations

import json
import os
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

os.environ.setdefault("OWNER_TOKEN", os.environ.get("OWNER_TOKEN", "real-smoke-owner"))

from agent.agent_core import AgentCore
from agent.model_router import ModelRouter
from agent.providers import OpenAICompatibleProvider
from agent.mission import MissionStore


def main() -> None:
    base_url = os.environ.get("OPENAI_BASE_URL", "").strip()
    api_key = os.environ.get("OPENAI_API_KEY", "").strip()
    model = os.environ.get("CYBERSENTINEL_REAL_MODEL", "gpt-5-mini")
    if not base_url or not api_key:
        print(json.dumps({"classification": "REAL_MODEL", "status": "UNAVAILABLE", "reason": "provider_not_configured"}))
        return
    provider = OpenAICompatibleProvider("real-openai-compatible", base_url, model, api_key, tool_calling=True, reasoning=True, reasoning_budget=True)
    root = Path("/tmp/cybersentinel-real-smoke")
    root.mkdir(parents=True, exist_ok=True)
    store = MissionStore(root / "missions.sqlite3")
    core = AgentCore(ModelRouter([provider]), store=store, max_iterations=5)
    try:
        mission = core.run_owner_mission("Investigate current system status and verify the observation using the status tool, then report only what was actually observed.", owner_token=os.environ["OWNER_TOKEN"], request_id="real-model-smoke-request")
    except Exception as exc:
        print(json.dumps({"classification": "REAL_MODEL", "status": "FAIL", "error": type(exc).__name__, "provider_error": provider.last_error}, ensure_ascii=False, indent=2))
        return
    result = {
        "classification": "REAL_MODEL",
        "status": "OBSERVED",
        "provider": provider.name,
        "model": model,
        "mission_id": mission.mission_id,
        "status_value": mission.status.value,
        "trajectory_events": [item.get("event") for item in mission.trajectory],
        "model_turns": len(mission.progress.get("model_loop", {}).get("turns", [])),
        "tool_calls": len(mission.progress.get("model_loop", {}).get("tool_results", [])),
        "verification": mission.verification_state,
        "error": mission.error,
    }
    print(json.dumps(result, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
