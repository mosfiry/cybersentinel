from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any
import uuid
import hashlib
import json
from pathlib import Path

from .planning import Plan, GoalVerification
from .trajectory import EventType, TrajectoryEvent, verify_trajectory


def _fingerprint(value: Any) -> str:
    payload = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


class MissionStatus(str, Enum):
    CREATED = "CREATED"
    PLANNING = "PLANNING"
    READY = "READY"
    RUNNING = "RUNNING"
    OBSERVING = "OBSERVING"
    VERIFYING = "VERIFYING"
    REPLANNING = "REPLANNING"
    PAUSED = "PAUSED"
    GOAL_COMPLETED = "GOAL_COMPLETED"
    OWNER_INPUT_REQUIRED = "OWNER_INPUT_REQUIRED"
    AUTHORIZATION_BLOCKED = "AUTHORIZATION_BLOCKED"
    SCOPE_BLOCKED = "SCOPE_BLOCKED"
    RESOURCE_BLOCKED = "RESOURCE_BLOCKED"
    RECOVERY_REQUIRED = "RECOVERY_REQUIRED"
    SAFETY_BLOCKED = "SAFETY_BLOCKED"
    FAILED_RETRY_EXHAUSTED = "FAILED_RETRY_EXHAUSTED"
    CANCELLED = "CANCELLED"


TERMINAL_MISSION_STATUSES = frozenset({
    MissionStatus.GOAL_COMPLETED, MissionStatus.OWNER_INPUT_REQUIRED,
    MissionStatus.AUTHORIZATION_BLOCKED, MissionStatus.SCOPE_BLOCKED,
    MissionStatus.RESOURCE_BLOCKED, MissionStatus.RECOVERY_REQUIRED, MissionStatus.SAFETY_BLOCKED,
    MissionStatus.FAILED_RETRY_EXHAUSTED, MissionStatus.CANCELLED,
})


@dataclass
class Mission:
    mission_id: str
    owner_request: str
    objective: str
    status: MissionStatus
    plan: Plan
    current_step: int = 0
    progress: dict[str, Any] = field(default_factory=dict)
    observations: list[dict[str, Any]] = field(default_factory=list)
    evidence: list[dict[str, Any]] = field(default_factory=list)
    artifacts: list[dict[str, Any]] = field(default_factory=list)
    failures: list[dict[str, Any]] = field(default_factory=list)
    authorization_context: dict[str, Any] | None = None
    scope_snapshot: dict[str, Any] | None = None
    completion_criteria: list[dict[str, Any]] = field(default_factory=list)
    verification_state: dict[str, Any] = field(default_factory=dict)
    completion_proof: dict[str, Any] | None = None
    checkpoint: dict[str, Any] = field(default_factory=dict)
    plan_history: list[dict[str, Any]] = field(default_factory=list)
    action_history: list[dict[str, Any]] = field(default_factory=list)
    transitions: list[dict[str, Any]] = field(default_factory=list)
    retry_count: int = 0
    max_iterations: int = 50
    iteration_count: int = 0
    error: str = ""
    request_id: str = ""
    owner_identity_ref: str = ""
    owner_instruction: str = ""
    policy_snapshot: dict[str, Any] | None = None
    authorization_snapshot: dict[str, Any] | None = None
    provenance: dict[str, Any] = field(default_factory=dict)
    trajectory: list[dict[str, Any]] = field(default_factory=list)
    hypotheses: list[dict[str, Any]] = field(default_factory=list)
    strategy_state: dict[str, Any] = field(default_factory=dict)
    knowledge_context: list[dict[str, Any]] = field(default_factory=list)
    interpretations: list[dict[str, Any]] = field(default_factory=list)
    strategy_decisions: list[dict[str, Any]] = field(default_factory=list)
    replan_history: list[dict[str, Any]] = field(default_factory=list)
    verification_history: list[dict[str, Any]] = field(default_factory=list)
    recovery_events: list[dict[str, Any]] = field(default_factory=list)
    semantic_intent: dict[str, Any] = field(default_factory=dict)
    integrity_hash: str = ""

    @classmethod
    def create(cls, owner_request: str, objective: str, plan: Plan, *, mission_id: str | None = None, authorization_context: dict[str, Any] | None = None, scope_snapshot: dict[str, Any] | None = None, completion_criteria: list[dict[str, Any]] | None = None, max_iterations: int = 50, request_id: str = "", owner_identity_ref: str = "", owner_instruction: str = "", policy_snapshot: dict[str, Any] | None = None, authorization_snapshot: dict[str, Any] | None = None, provenance: dict[str, Any] | None = None) -> "Mission":
        plan.validate_dependency_graph()
        mission = cls(mission_id or uuid.uuid4().hex, owner_request, objective, MissionStatus.CREATED, plan, authorization_context=authorization_context, scope_snapshot=scope_snapshot, completion_criteria=completion_criteria or [], max_iterations=max_iterations, request_id=request_id, owner_identity_ref=owner_identity_ref, owner_instruction=owner_instruction or owner_request, policy_snapshot=policy_snapshot, authorization_snapshot=authorization_snapshot, provenance=provenance or {})
        mission.plan_history = [{"version": plan.version, "fingerprint": plan.fingerprint, "reason": "created"}]
        mission.transition(MissionStatus.PLANNING, "mission created")
        mission.emit(EventType.MISSION_STARTED, data={"objective": mission.objective})
        mission.emit(EventType.PLAN_CREATED, data={"version": plan.version, "fingerprint": plan.fingerprint})
        return mission

    @property
    def is_terminal(self) -> bool:
        return self.status in TERMINAL_MISSION_STATUSES

    @property
    def current_plan_step(self):
        return self.plan.steps[self.current_step] if self.current_step < len(self.plan.steps) else None

    def transition(self, target: MissionStatus, reason: str, **data: Any) -> None:
        if not isinstance(target, MissionStatus):
            raise TypeError("mission transition requires MissionStatus")
        if self.status is MissionStatus.RECOVERY_REQUIRED and target not in {MissionStatus.RECOVERY_REQUIRED, MissionStatus.READY}:
            raise ValueError("recovery requires reconciliation before continuation")
        if target is MissionStatus.PAUSED and self.status not in {MissionStatus.CREATED, MissionStatus.PLANNING, MissionStatus.READY, MissionStatus.RUNNING, MissionStatus.OBSERVING, MissionStatus.VERIFYING, MissionStatus.REPLANNING, MissionStatus.PAUSED}:
            raise ValueError("mission cannot be paused from its current state")
        if self.status is MissionStatus.PAUSED and target not in {MissionStatus.PAUSED, MissionStatus.READY, MissionStatus.CANCELLED, MissionStatus.OWNER_INPUT_REQUIRED}:
            raise ValueError("paused mission must be resumed before execution")
        recovery_reconciled = self.status is MissionStatus.RECOVERY_REQUIRED and target is MissionStatus.READY
        owner_intervention = self.status in {MissionStatus.OWNER_INPUT_REQUIRED, MissionStatus.AUTHORIZATION_BLOCKED} and target in {MissionStatus.AUTHORIZATION_BLOCKED, MissionStatus.READY}
        if self.is_terminal and target is not self.status and not recovery_reconciled and not owner_intervention:
            raise ValueError(f"terminal mission cannot transition {self.status.value}->{target.value}")
        if target is MissionStatus.GOAL_COMPLETED:
            verification = data.get("verification")
            if not (isinstance(verification, dict) and verification == self.verification_state and verification.get("verified") is True and not verification.get("missing_criteria")):
                raise ValueError("GOAL_COMPLETED requires the runtime's exact verified state")
            if not self.completion_proof_is_valid():
                raise ValueError("GOAL_COMPLETED requires a valid system-signed completion proof")
        self.status = target
        self.transitions.append({"from": self.transitions[-1]["to"] if self.transitions else "CREATED", "to": target.value, "reason": reason, "data": data, "iteration": self.iteration_count})

    def emit(self, event_type: EventType, *, step_id: str = "", data: dict[str, Any] | None = None) -> None:
        previous_hash = str(self.trajectory[-1].get("event_hash", "")) if self.trajectory else ""
        event = TrajectoryEvent(event_type, self.mission_id, self.request_id, step_id=step_id, provenance=dict(self.provenance), data=data or {}, previous_hash=previous_hash)
        self.trajectory.append(event.to_dict())

    def record_observation(self, observation: dict[str, Any]) -> None:
        self.observations.append(dict(observation))
        self.progress["last_observation"] = observation.get("type", "observation")
        self.emit(EventType.OBSERVATION_RECEIVED, step_id=str(observation.get("step_id", "")), data={"status": observation.get("status", observation.get("success")), "action_id": observation.get("action_id", "")})

    def record_action(self, action_id: str, step_id: str, status: str, observation: dict[str, Any] | None = None, *, plan_fingerprint: str = "") -> None:
        existing = next((item for item in self.action_history if item.get("action_id") == action_id), None)
        if existing is not None:
            existing_fingerprint = str(existing.get("plan_fingerprint", ""))
            if existing_fingerprint and plan_fingerprint and existing_fingerprint != plan_fingerprint:
                raise ValueError("action ID is already bound to a different plan")
            if existing.get("status") == "completed":
                if not existing_fingerprint and plan_fingerprint:
                    existing["plan_fingerprint"] = plan_fingerprint
                return
            if status != "completed":
                return
            existing.update({"step_id": step_id, "status": status, "observation": observation or {}})
            if plan_fingerprint:
                existing["plan_fingerprint"] = plan_fingerprint
            self.emit(EventType.TOOL_EXECUTED, step_id=step_id, data={"action_id": action_id, "status": status})
            return
        item = {"action_id": action_id, "step_id": step_id, "status": status, "observation": observation or {}}
        if plan_fingerprint:
            item["plan_fingerprint"] = plan_fingerprint
        self.action_history.append(item)
        self.emit(EventType.TOOL_EXECUTED, step_id=step_id, data={"action_id": action_id, "status": status})

    def _verified_system_evidence(self) -> list[dict[str, Any]]:
        from security.truthfulness import EvidenceRecord, system_issuer
        issuer = system_issuer()
        actions = {str(item.get("action_id", "")): item for item in self.action_history if item.get("status") == "completed"}
        known_plan_hashes = {str(item.get("fingerprint", "")) for item in self.plan_history}
        accepted: list[dict[str, Any]] = []
        for item in self.evidence:
            if not isinstance(item, dict) or item.get("passed") is not True:
                continue
            raw = item.get("system_evidence")
            if not isinstance(raw, dict):
                continue
            try:
                record = EvidenceRecord(**dict(raw))
            except (TypeError, ValueError):
                continue
            if not issuer.verify(record) or record.origin != "execution_runtime" or record.kind != "mission_criterion_evidence":
                continue
            payload = record.payload
            action_id = str(payload.get("action_id", ""))
            action = actions.get(action_id)
            if action is None:
                continue
            if (
                payload.get("mission_id") != self.mission_id
                or payload.get("request_id") != self.request_id
                or payload.get("owner_identity_ref") != self.owner_identity_ref
                or payload.get("criterion_id") != item.get("criterion_id")
                or payload.get("result_hash") != _fingerprint(item.get("result", {}))
                or payload.get("tool") != action.get("observation", {}).get("source")
                or payload.get("plan_fingerprint") not in known_plan_hashes
            ):
                continue
            accepted.append({**item, "verified_provenance": asdict(record)})
        return accepted

    def _completion_binding_payload(self) -> dict[str, Any]:
        verified = self._verified_system_evidence()
        required = sorted(str(item.get("criterion_id", "")) for item in self.completion_criteria if item.get("required", True))
        verified_ids = sorted({str(item.get("criterion_id", "")) for item in verified})
        return {
            "mission_id": self.mission_id,
            "request_id": self.request_id,
            "owner_identity_ref": self.owner_identity_ref,
            "objective_hash": _fingerprint(self.objective),
            "plan_fingerprint": self.plan.fingerprint,
            "authorization_snapshot_hash": str((self.authorization_snapshot or {}).get("authorization_hash", "")),
            "criteria_hash": _fingerprint(self.completion_criteria),
            "evidence_hash": _fingerprint([item.get("verified_provenance") for item in verified]),
            "verification_state_hash": _fingerprint(self.verification_state),
            "required_criteria": required,
            "verified_criteria": verified_ids,
            "verified": bool(self.verification_state.get("verified") is True),
        }

    def completion_proof_is_valid(self) -> bool:
        if not isinstance(self.completion_proof, dict) or not self.completion_criteria:
            return False
        if self.verification_state.get("verified") is not True or self.verification_state.get("missing_criteria"):
            return False
        try:
            from security.truthfulness import EvidenceRecord, system_issuer
            record = EvidenceRecord(**dict(self.completion_proof))
            if not system_issuer().verify(record) or record.origin != "execution_runtime" or record.kind != "mission_completion":
                return False
            required = {str(item.get("criterion_id", "")) for item in self.completion_criteria if item.get("required", True)}
            verified = {str(item.get("criterion_id", "")) for item in self._verified_system_evidence()}
            return bool(required) and required.issubset(verified) and record.payload == self._completion_binding_payload()
        except (KeyError, TypeError, ValueError, PermissionError):
            return False

    def _unsigned_dict(self) -> dict[str, Any]:
        return {"mission_id": self.mission_id, "owner_request": self.owner_request, "objective": self.objective, "status": self.status.value, "plan": self.plan.to_dict(), "current_step": self.current_step, "progress": self.progress, "observations": self.observations, "evidence": self.evidence, "artifacts": self.artifacts, "failures": self.failures, "authorization_context": self.authorization_context, "scope_snapshot": self.scope_snapshot, "completion_criteria": self.completion_criteria, "verification_state": self.verification_state, "completion_proof": self.completion_proof, "checkpoint": self.checkpoint, "plan_history": self.plan_history, "action_history": self.action_history, "transitions": self.transitions, "retry_count": self.retry_count, "max_iterations": self.max_iterations, "iteration_count": self.iteration_count, "error": self.error, "request_id": self.request_id, "owner_identity_ref": self.owner_identity_ref, "owner_instruction": self.owner_instruction, "policy_snapshot": self.policy_snapshot, "authorization_snapshot": self.authorization_snapshot, "provenance": self.provenance, "trajectory": self.trajectory, "hypotheses": self.hypotheses, "strategy_state": self.strategy_state, "knowledge_context": self.knowledge_context, "interpretations": self.interpretations, "strategy_decisions": self.strategy_decisions, "replan_history": self.replan_history, "verification_history": self.verification_history, "recovery_events": self.recovery_events, "semantic_intent": self.semantic_intent}

    def to_dict(self) -> dict[str, Any]:
        payload = self._unsigned_dict()
        payload["integrity_hash"] = hashlib.sha256(json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str).encode()).hexdigest()
        return payload

    def to_public_dict(self) -> dict[str, Any]:
        """Serialize backend mission truth without exposing bearer session IDs."""
        payload = json.loads(json.dumps(self.to_dict(), ensure_ascii=False, default=str))

        def redact(value: Any) -> Any:
            if isinstance(value, dict):
                return {key: redact(item) for key, item in value.items() if key not in {"session_id", "owner_session_id"}}
            if isinstance(value, list):
                return [redact(item) for item in value]
            return value

        return redact(payload)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Mission":
        raw = dict(data)
        supplied_hash = str(raw.pop("integrity_hash", "") or "")
        if supplied_hash:
            expected_hash = hashlib.sha256(json.dumps(raw, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str).encode()).hexdigest()
            if supplied_hash != expected_hash:
                raise ValueError("mission_integrity_hash_mismatch")
        trajectory = raw.get("trajectory") or []
        if trajectory and any("event_hash" in item for item in trajectory):
            if not all("event_hash" in item for item in trajectory) or not verify_trajectory(trajectory):
                raise ValueError("trajectory_integrity_mismatch")
        plan_data = raw.pop("plan")
        from .planning import PlanStep
        steps = tuple(PlanStep(**{**step, "prerequisites": tuple(step.get("prerequisites", ())), "verification": tuple(step.get("verification", ()))}) for step in plan_data.get("steps", []))
        raw["plan"] = Plan(version=plan_data["version"], objective=plan_data["objective"], assumptions=tuple(plan_data.get("assumptions", ())), steps=steps, dependencies=tuple(plan_data.get("dependencies", ())), completion_criteria=tuple(plan_data.get("completion_criteria", ())), risk=plan_data.get("risk", "unknown"), created_from=plan_data.get("created_from", ""))
        raw["plan"].validate_dependency_graph()
        raw["status"] = MissionStatus(raw["status"])
        raw["integrity_hash"] = supplied_hash
        mission = cls(**raw)
        if mission.status is MissionStatus.GOAL_COMPLETED and not mission.completion_proof_is_valid():
            raise ValueError("refusing to load GOAL_COMPLETED without a valid system-signed completion proof")
        return mission


class MissionStore:
    """Durable JSON-backed SQLite store; the HTTP request is never the mission lifetime."""

    def __init__(self, db_path):
        import os
        import stat
        import sqlite3
        from pathlib import Path
        path = Path(db_path).expanduser()
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        fd = os.open(path, os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0), 0o600)
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid():
                raise PermissionError("mission database must be a regular file owned by the application user")
            if stat.S_IMODE(info.st_mode) & 0o077:
                os.fchmod(fd, 0o600)
        finally:
            os.close(fd)
        self.db_path = str(path.resolve())
        with sqlite3.connect(self.db_path) as db:
            db.execute("CREATE TABLE IF NOT EXISTS missions (mission_id TEXT PRIMARY KEY, payload TEXT NOT NULL)")

    def issue_criterion_evidence(self, mission: Mission, criterion_id: str, action_id: str) -> dict[str, Any] | None:
        """Mint evidence only after an independent action-specific system check.

        Supported checks are deliberately narrow. A tool's success flag,
        criterion name, model narrative, or caller-supplied reconciliation
        payload is never sufficient by itself.
        """
        from security.truthfulness import system_issuer
        criterion = next((item for item in mission.completion_criteria if str(item.get("criterion_id", "")) == str(criterion_id)), None)
        action = next((item for item in mission.action_history if str(item.get("action_id", "")) == str(action_id) and item.get("status") == "completed"), None)
        if criterion is None or action is None:
            return None
        observation = action.get("observation", {})
        tool = str(observation.get("source", ""))
        check = str(criterion.get("check", ""))
        if check == "system_online" and tool == "status":
            from core.engine import status as read_system_status
            current = read_system_status()
            if not isinstance(current, dict) or current.get("online") is not True or not current.get("service") or not current.get("version"):
                return None
            result = {"service": str(current["service"]), "version": str(current["version"]), "online": True}
            evidence_ref = "independent_core_status_read"
        elif check == "project_tests_pass" and tool == "run_project_tests":
            from agent.evidence import EvidenceChainStore
            evidence_path = Path(self.db_path).with_name("evidence_chain.db")
            chain = EvidenceChainStore(evidence_path)
            if not chain.verify():
                return None
            snapshot_hash = str((mission.authorization_snapshot or {}).get("authorization_hash", ""))
            matching = []
            for item in chain.list(request_id=mission.request_id):
                event = item.get("evidence") if isinstance(item.get("evidence"), dict) else {}
                command = tuple(str(part) for part in event.get("command", ()))
                pytest_command = "-m" in command and command[command.index("-m") + 1:command.index("-m") + 3] == ("pytest", "-q")
                if (
                    event.get("mission_id") == mission.mission_id
                    and event.get("request_id") == mission.request_id
                    and event.get("tool_id") == "run_project_tests"
                    and event.get("action_id") == str(action_id)
                    and event.get("authorization_hash") == snapshot_hash
                    and event.get("operation") == "process"
                    and event.get("result") == "success"
                    and event.get("exit_code") == 0
                    and pytest_command
                ):
                    matching.append(item)
            if not matching:
                return None
            event_record = matching[-1]
            result = {"exit_code": 0, "tool_id": "run_project_tests", "workspace_event_hash": str(event_record.get("current_hash", ""))}
            evidence_ref = str(event_record.get("current_hash", ""))
        else:
            return None

        evidence = {
            "criterion_id": str(criterion_id),
            "passed": True,
            "source": check,
            "result": result,
            "provenance": {"mission_id": mission.mission_id, "request_id": mission.request_id, "action_id": str(action_id), "verification": evidence_ref},
        }
        payload = {
            "mission_id": mission.mission_id,
            "request_id": mission.request_id,
            "owner_identity_ref": mission.owner_identity_ref,
            "criterion_id": str(criterion_id),
            "action_id": str(action_id),
            "tool": tool,
            "check": check,
            "plan_fingerprint": mission.plan.fingerprint,
            "result_hash": _fingerprint(result),
            "verification_ref": evidence_ref,
            "passed": True,
        }
        from dataclasses import asdict
        record = system_issuer().mint("execution_runtime", "mission_criterion_evidence", payload)
        evidence["system_evidence"] = asdict(record)
        return evidence

    def issue_completion_proof(self, mission: Mission) -> dict[str, Any]:
        """Recompute criterion coverage from signed system evidence before signing completion."""
        from security.truthfulness import system_issuer
        from .planning import GoalVerification, VerificationCriterion, evidence_for
        criteria = tuple(
            VerificationCriterion(str(item["criterion_id"]), str(item.get("description", item["criterion_id"])), str(item.get("check", "")), bool(item.get("required", True)))
            for item in mission.completion_criteria
        )
        trusted = mission._verified_system_evidence()
        evidence = tuple(evidence_for(str(item["criterion_id"]), True, str(item.get("source", "")), item.get("result", {}), provenance=item.get("provenance", {})) for item in trusted)
        verification = GoalVerification.evaluate(mission.objective, criteria, evidence)
        if not verification.verified:
            raise ValueError("cannot issue completion proof without signed evidence for every required criterion")
        mission.verification_state = {"verified": True, "missing_criteria": [], "evidence_count": len(evidence)}
        from dataclasses import asdict
        proof = system_issuer().mint("execution_runtime", "mission_completion", mission._completion_binding_payload())
        mission.completion_proof = asdict(proof)
        return dict(mission.verification_state)

    def save(self, mission: Mission) -> Mission:
        import json, sqlite3
        if mission.status is MissionStatus.GOAL_COMPLETED and not mission.completion_proof_is_valid():
            raise ValueError("refusing to persist GOAL_COMPLETED without a valid system-signed completion proof")
        with sqlite3.connect(self.db_path) as db:
            payload = mission.to_dict()
            encoded = json.dumps(payload, ensure_ascii=False)
            existing = db.execute("SELECT payload FROM missions WHERE mission_id=?", (mission.mission_id,)).fetchone()
            if existing is None:
                db.execute("INSERT INTO missions(mission_id,payload) VALUES(?,?)", (mission.mission_id, encoded))
            else:
                current_hash = str(json.loads(existing[0]).get("integrity_hash", ""))
                if not mission.integrity_hash or current_hash != mission.integrity_hash:
                    raise ValueError("stale mission write rejected")
                updated = db.execute("UPDATE missions SET payload=? WHERE mission_id=? AND payload=?", (encoded, mission.mission_id, existing[0]))
                if updated.rowcount != 1:
                    raise ValueError("concurrent mission write rejected")
            mission.integrity_hash = str(payload["integrity_hash"])
        return mission

    def load(self, mission_id: str) -> Mission | None:
        import json, sqlite3
        with sqlite3.connect(self.db_path) as db:
            row = db.execute("SELECT payload FROM missions WHERE mission_id=?", (mission_id,)).fetchone()
        return Mission.from_dict(json.loads(row[0])) if row else None

    def load_for_owner(self, mission_id: str, owner_identity: str) -> Mission | None:
        mission = self.load(mission_id)
        if mission is None or mission.owner_identity_ref != str(owner_identity):
            return None
        return mission

    def list_for_owner(self, owner_identity: str, *, limit: int = 100) -> list[dict[str, Any]]:
        import json, sqlite3
        if not 1 <= int(limit) <= 500:
            raise ValueError("mission list limit must be between 1 and 500")
        with sqlite3.connect(self.db_path) as db:
            rows = db.execute("SELECT payload FROM missions ORDER BY rowid DESC").fetchall()
        result = []
        for (encoded,) in rows:
            mission = Mission.from_dict(json.loads(encoded))
            if mission.owner_identity_ref == str(owner_identity):
                result.append(mission.to_public_dict())
                if len(result) >= int(limit):
                    break
        return result


__all__ = ["Mission", "MissionStatus", "MissionStore", "TERMINAL_MISSION_STATUSES"]
