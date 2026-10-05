"""Owner-authorized Skill management over immutable declarative revisions.

This service never executes a Skill procedure. Candidate provenance is derived from
an integrity-verified, successfully completed Owner Mission and the server's durable
fenced evidence chain; client-supplied evidence claims are not accepted.
"""
from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import hmac
import json
from pathlib import Path
import re
import sqlite3
from typing import Any, Mapping
from urllib.parse import quote
import uuid

from agent.evidence import EvidenceChainStore
from agent.execution_fence import authorization_digest
from agent.intelligence_layer.skills import (
    SkillApprovalGrant,
    SkillAuthorizationError,
    SkillCandidateEvidence,
    SkillCritique,
    SkillDefinition,
    SkillError,
    SkillLearningPipeline,
    SkillRegistry,
    SkillRevision,
    SkillStatus,
    validate_skill_definition,
)
from agent.mission import Mission, MissionStatus
from agent.trajectory import verify_trajectory
from agent.verification import VerificationPlan, VerificationResult
from security.mission_authorization import MissionAuthorizationSnapshot


_SKILL_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_MAX_CHAIN_RECORDS = 50_000
_MAX_CHAIN_BYTES = 64_000_000


class OwnerSkillService:
    """Owner-scoped read, candidate submission, approval, revocation and detail."""

    _CRITIC_ID = "verified-mission-trajectory-critic-v1"
    _VALIDATOR_ID = "verified-mission-evidence-chain-validator-v1"

    def __init__(self, db_path: str | Path, mission_service: Any):
        self.db_path = Path(db_path).expanduser().resolve()
        self.mission_service = mission_service
        self.registry = SkillRegistry(self.db_path)

    def _owner_ref(self, owner_session_token: str) -> str:
        return self.mission_service._owner_identity_ref(owner_session_token)

    @staticmethod
    def _public_revision(revision: SkillRevision, *, active: bool, source_mission_id: str = "") -> dict[str, Any]:
        definition = revision.definition
        return {
            "skill_id": definition.skill_id,
            "name": definition.name,
            "description": definition.description,
            "version": definition.version,
            "status": revision.status.value,
            "active": bool(active),
            "content_hash": definition.content_hash,
            "created_at": definition.created_at,
            "expires_at": definition.expires_at,
            "capabilities": list(definition.capabilities),
            "required_tools": list(definition.required_tools),
            "allowed_scope": list(definition.allowed_scope),
            "preconditions": list(definition.preconditions),
            "postconditions": list(definition.postconditions),
            # Deliberately exclude argument bindings, constants, examples, tests,
            # and provenance text: they may contain sensitive or hostile data.
            "procedure": [
                {
                    "step_id": step.step_id,
                    "tool_name": step.tool_name,
                    "action": step.action,
                    "description": step.description,
                    "expects_evidence": step.expects_evidence,
                    "timeout_seconds": step.timeout_seconds,
                }
                for step in definition.procedure
            ],
            "source_mission_id": source_mission_id,
            "execution_mode": "untrusted_guidance_only",
        }

    def _source_evidence(self, owner_ref: str, skill_id: str, version: int) -> SkillCandidateEvidence:
        events = self.registry.events(owner_ref, skill_id)
        matches = [
            event for event in events
            if event.get("action") == "candidate_registered" and int(event.get("version", 0)) == version
        ]
        if len(matches) != 1:
            raise SkillAuthorizationError("Skill candidate has no unique server-verified provenance record")
        raw = (matches[0].get("details") or {}).get("candidate_evidence")
        if not isinstance(raw, dict):
            raise SkillAuthorizationError("Skill candidate provenance is unavailable")
        try:
            payload = dict(raw)
            payload["evidence_refs"] = tuple(payload.get("evidence_refs", ()))
            return SkillCandidateEvidence(**payload)
        except (TypeError, ValueError) as exc:
            raise SkillAuthorizationError("Skill candidate provenance is invalid") from exc

    def list_revisions(self, owner_session_token: str) -> list[dict[str, Any]]:
        owner_ref = self._owner_ref(owner_session_token)
        revisions = self.registry.list_owner_revisions(owner_ref, limit=200)
        active_versions: dict[str, int] = {}
        for skill_id in {item.definition.skill_id for item in revisions}:
            active = self.registry.get_active(owner_ref, skill_id)
            if active is not None:
                active_versions[skill_id] = active.definition.version
        output = []
        for revision in revisions:
            evidence = self._source_evidence(owner_ref, revision.definition.skill_id, revision.definition.version)
            output.append(self._public_revision(
                revision,
                active=active_versions.get(revision.definition.skill_id) == revision.definition.version,
                source_mission_id=evidence.mission_id,
            ))
        return output

    def detail(self, owner_session_token: str, skill_id: str, version: int) -> dict[str, Any]:
        owner_ref = self._owner_ref(owner_session_token)
        revision = self._get_revision(owner_ref, skill_id, version)
        evidence = self._source_evidence(owner_ref, skill_id, version)
        active = self.registry.get_active(owner_ref, skill_id)
        return self._public_revision(
            revision,
            active=bool(active and active.definition.version == version),
            source_mission_id=evidence.mission_id,
        )

    def _get_revision(self, owner_ref: str, skill_id: str, version: int) -> SkillRevision:
        if not _SKILL_ID.fullmatch(str(skill_id)):
            raise KeyError("unknown_skill")
        if isinstance(version, bool) or not isinstance(version, int) or version < 1:
            raise KeyError("unknown_skill_revision")
        revision = self.registry.get_revision(owner_ref, skill_id, version)
        if revision is None:
            raise KeyError("unknown_skill_revision")
        return revision

    def _authorized_mission(
        self,
        owner_session_token: str,
        mission_id: str,
        *,
        require_verified_completion: bool = True,
    ) -> tuple[Mission, str, MissionAuthorizationSnapshot]:
        if not isinstance(mission_id, str) or not mission_id or len(mission_id) > 128:
            raise ValueError("invalid_mission_id")
        bounded_loader = getattr(self.mission_service, "load_authorized_mission", None)
        if not callable(bounded_loader):
            raise SkillAuthorizationError("bounded Owner-filtered Mission loading is unavailable")
        try:
            mission, owner_ref = bounded_loader(mission_id, owner_session_token)
        except KeyError as exc:
            # The bounded loader uses the same result for absent and foreign rows.
            raise PermissionError("mission access denied") from exc
        canonical_owner = self._owner_ref(owner_session_token)
        if owner_ref != canonical_owner or mission.owner_identity_ref != canonical_owner:
            raise SkillAuthorizationError("Mission does not belong to the current canonical Owner")
        if not mission.verify_integrity():
            raise SkillAuthorizationError("Mission integrity verification failed")
        if require_verified_completion and mission.status is not MissionStatus.GOAL_COMPLETED:
            raise SkillError("Skill candidates require a successfully completed Mission")
        if require_verified_completion and (
            not isinstance(mission.verification_state, dict)
            or mission.verification_state.get("verified") is not True
        ):
            raise SkillError("Skill candidates require server-verified Mission completion")
        try:
            snapshot = MissionAuthorizationSnapshot.from_dict(dict(mission.authorization_snapshot or {}))
            target = str((mission.scope_snapshot or {}).get("target_id") or snapshot.target_identity)
            version = int(mission.provenance.get("authorization_snapshot_version", 1))
            valid, _reason = snapshot.validate_for_mission(
                mission_id=mission.mission_id,
                owner_identity=canonical_owner,
                target_identity=target,
                version=version,
            )
        except (KeyError, TypeError, ValueError, PermissionError) as exc:
            raise SkillAuthorizationError("Mission authorization snapshot is invalid") from exc
        if not valid:
            raise SkillAuthorizationError("Mission authorization snapshot is invalid")
        if not verify_trajectory(mission.trajectory):
            raise SkillAuthorizationError("Mission trajectory integrity verification failed")
        return mission, canonical_owner, snapshot

    def analyze_mission(self, owner_session_token: str, mission_id: str) -> dict[str, Any]:
        """Return bounded learning eligibility signals; never synthesize or approve a Skill."""
        mission, owner_ref, snapshot = self._authorized_mission(
            owner_session_token,
            mission_id,
            require_verified_completion=False,
        )
        status = mission.status
        verification = mission.verification_state
        verified = (
            status is MissionStatus.GOAL_COMPLETED
            and isinstance(verification, dict)
            and verification.get("verified") is True
        )
        trajectory_types = [
            item.get("event") for item in mission.trajectory
            if isinstance(item, dict) and isinstance(item.get("event"), str)
        ] if isinstance(mission.trajectory, (list, tuple)) else []
        trajectory_qualified = (
            "MissionStarted" in trajectory_types
            and "GoalVerified" in trajectory_types
            and bool(trajectory_types)
            and trajectory_types[-1] == "MissionCompleted"
            and trajectory_types.index("MissionStarted") <= trajectory_types.index("GoalVerified")
            and trajectory_types.index("GoalVerified") <= trajectory_types.index("MissionCompleted")
        )

        if not mission.is_terminal:
            outcome_class, reason_code = "in_progress", "mission_not_terminal"
        elif status is MissionStatus.GOAL_COMPLETED and not verified:
            outcome_class, reason_code = "unverified_completion", "mission_not_verified"
        elif status is MissionStatus.GOAL_COMPLETED:
            outcome_class, reason_code = "verified_success", "no_completed_tool_steps"
        elif status is MissionStatus.CANCELLED:
            outcome_class, reason_code = "cancelled", "mission_cancelled"
        elif status in {MissionStatus.FAILED_RETRY_EXHAUSTED}:
            outcome_class, reason_code = "failed", "mission_failed"
        elif status in {MissionStatus.OWNER_INPUT_REQUIRED, MissionStatus.OWNER_REAUTH_REQUIRED}:
            outcome_class, reason_code = "owner_intervention", "owner_intervention_required"
        else:
            outcome_class, reason_code = "blocked", "mission_not_successfully_verified"

        completed_ids = {
            str(item.get("step_id", ""))
            for item in mission.action_history
            if isinstance(item, dict) and item.get("status") == "completed"
        } if isinstance(mission.action_history, (list, tuple)) else set()
        tool_sequence: list[str] = []
        tool_step_ids: list[str] = []
        sequence_overflow = False
        for step in getattr(mission.plan, "steps", ()):
            tool_name = getattr(step, "action", "")
            step_id = getattr(step, "step_id", "")
            if not isinstance(tool_name, str) or not isinstance(step_id, str):
                continue
            if step_id not in completed_ids or tool_name not in self.registry.tool_specs:
                continue
            if len(tool_sequence) >= 32:
                sequence_overflow = True
                break
            tool_sequence.append(tool_name)
            tool_step_ids.append(step_id)

        evidence_count = 0
        evidence_digest = ""
        candidate_seed_eligible = False
        if outcome_class == "verified_success":
            if not trajectory_qualified:
                reason_code = "completion_trajectory_not_qualified"
            elif sequence_overflow:
                reason_code = "completed_tool_sequence_exceeds_limit"
            elif not tool_step_ids:
                reason_code = "no_completed_tool_steps"
            else:
                try:
                    evidence_records = self._trusted_mission_evidence(
                        mission,
                        owner_ref,
                        snapshot,
                        set(tool_step_ids),
                    )
                except (SkillError, SkillAuthorizationError, PermissionError, TypeError, ValueError):
                    reason_code = "completed_tool_sequence_not_fully_evidenced"
                else:
                    evidence_count = len(evidence_records)
                    evidence_digest = hashlib.sha256(
                        json.dumps(
                            sorted(str(record.get("current_hash", "")) for record in evidence_records),
                            separators=(",", ":"),
                        ).encode("utf-8")
                    ).hexdigest()
                    candidate_seed_eligible = bool(evidence_count)
                    reason_code = "ready_for_owner_authored_candidate" if candidate_seed_eligible else "fenced_evidence_unavailable"

        failure_classes: list[str] = []
        failures = mission.failures if isinstance(mission.failures, (list, tuple)) else ()
        for failure in failures[:32]:
            if not isinstance(failure, dict):
                continue
            label = str(failure.get("class", "")).upper()
            if re.fullmatch(r"[A-Z_]{1,32}", label) and label not in failure_classes:
                failure_classes.append(label)
            if len(failure_classes) >= 8:
                break

        digest_payload = {
            "analysis_version": 1,
            "mission_integrity_hash": mission.integrity_hash,
            "owner_identity_ref": owner_ref,
            "status": status.value,
            "outcome_class": outcome_class,
            "verified": verified,
            "tool_sequence": tool_sequence,
            "failure_classes": failure_classes,
            "evidence_count": evidence_count,
            "evidence_digest": evidence_digest,
            "candidate_seed_eligible": candidate_seed_eligible,
            "reason_code": reason_code,
        }
        analysis_digest = hashlib.sha256(
            json.dumps(digest_payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest()
        return {
            "analysis_version": 1,
            "status": status.value,
            "outcome_class": outcome_class,
            "verified": verified,
            "completed_tool_sequence": tool_sequence,
            "failure_classes": failure_classes,
            "evidence_count": evidence_count,
            "candidate_seed_eligible": candidate_seed_eligible,
            "reason_code": reason_code,
            "analysis_digest": analysis_digest,
        }

    def _trusted_mission_evidence(
        self,
        mission: Mission,
        owner_ref: str,
        snapshot: MissionAuthorizationSnapshot,
        task_ids: set[str],
    ) -> list[dict[str, Any]]:
        mission_db = Path(self.mission_service.runtime.store.db_path).expanduser().resolve()
        evidence_db = mission_db.with_name("evidence_chain.db")
        if not evidence_db.is_file():
            raise SkillError("verified durable Mission evidence is unavailable")
        uri = "file:" + quote(str(evidence_db.resolve()), safe="/:") + "?mode=ro"
        try:
            with sqlite3.connect(uri, uri=True, timeout=5) as conn:
                rows = conn.execute(
                    "SELECT payload FROM evidence_chain ORDER BY sequence LIMIT ?",
                    (_MAX_CHAIN_RECORDS + 1,),
                ).fetchall()
            if len(rows) > _MAX_CHAIN_RECORDS:
                raise SkillError("Mission evidence chain exceeds the candidate verification bound")
            total_bytes = sum(len(str(row[0]).encode("utf-8")) for row in rows)
            if total_bytes > _MAX_CHAIN_BYTES:
                raise SkillError("Mission evidence chain exceeds the candidate verification bound")
            records = [json.loads(row[0]) for row in rows]
        except SkillError:
            raise
        except (sqlite3.Error, json.JSONDecodeError, TypeError, ValueError) as exc:
            raise SkillError("durable Mission evidence could not be verified") from exc
        if not all(isinstance(item, dict) for item in records):
            raise SkillError("durable Mission evidence chain is malformed")
        if not EvidenceChainStore.verify_records(
            records,
            mission_store=self.mission_service.runtime.store,
            require_execution_fence=False,
        ):
            raise SkillError("durable Mission evidence chain integrity verification failed")
        refs = mission.progress.get("execution_evidence_refs", [])
        if not isinstance(refs, list):
            raise SkillError("Mission execution evidence references are invalid")
        receipt_ids = {
            str(item.get("evidence_id"))
            for item in refs
            if isinstance(item, dict) and item.get("evidence_id")
        }
        exact = [
            record for record in records
            if record.get("mission_id") == mission.mission_id
            and record.get("request_id") == mission.request_id
            and record.get("owner_identity_ref", owner_ref) == owner_ref
            and record.get("fence_id")
            and record.get("authorization_hash") == authorization_digest(snapshot)
            and record.get("task_id") in task_ids
            and record.get("evidence_id") in receipt_ids
            and record.get("verification") in {"observed", "verified"}
        ]
        if not exact:
            raise SkillError("Mission has no fenced evidence for its completed tool steps")
        by_task = {task_id: False for task_id in task_ids}
        for record in exact:
            by_task[str(record.get("task_id"))] = True
        if not all(by_task.values()):
            raise SkillError("every Skill procedure step must have exact fenced Mission evidence")
        if len(exact) > 256:
            raise SkillError("Mission evidence references exceed the candidate verification bound")
        return exact

    def _candidate_steps(
        self,
        mission: Mission,
        snapshot: MissionAuthorizationSnapshot,
        definition: SkillDefinition,
    ) -> list[Any]:
        validate_skill_definition(definition, self.registry.tool_specs)
        if not definition.procedure:
            raise SkillError("candidate Skill procedure must contain bounded declarative steps")
        procedure_tools = {step.tool_name for step in definition.procedure}
        if procedure_tools != set(definition.required_tools):
            raise SkillError("candidate tool ceiling must exactly match its declarative steps")
        if procedure_tools - set(snapshot.allowed_tools) or procedure_tools - set(snapshot.allowed_actions):
            raise SkillAuthorizationError("candidate tools exceed the Owner Mission authorization")
        if definition.allowed_scope and not set(definition.allowed_scope).issubset(set(snapshot.scope)):
            raise SkillAuthorizationError("candidate Skill scope exceeds the completed Mission scope")
        completed_ids = {
            str(item.get("step_id", ""))
            for item in mission.action_history
            if isinstance(item, dict) and item.get("status") == "completed"
        }
        completed_steps = [
            step for step in mission.plan.steps
            if step.step_id in completed_ids and step.action != "__planning_failure__"
        ]
        matched: list[Any] = []
        cursor = 0
        for skill_step in definition.procedure:
            found = None
            for index in range(cursor, len(completed_steps)):
                plan_step = completed_steps[index]
                if plan_step.action == skill_step.tool_name and plan_step.action == skill_step.action:
                    found = (index, plan_step)
                    break
            if found is None:
                raise SkillError("candidate procedure is not an ordered subset of successfully completed Mission tools")
            cursor, plan_step = found
            matched.append(plan_step)
            cursor += 1
            spec = self.registry.tool_specs.get(skill_step.tool_name)
            if spec is None:
                raise SkillError("candidate references an unknown canonical tool")
            scope = set(definition.allowed_scope) if definition.allowed_scope else set(snapshot.scope)
            requirements = set(getattr(spec, "scope_requirements", ()))
            if getattr(spec, "scope_required", False) and not requirements.issubset(scope):
                raise SkillAuthorizationError("candidate scope does not satisfy canonical tool requirements")
            if getattr(spec, "scope_required", False) and not requirements.issubset(set(snapshot.scope)):
                raise SkillAuthorizationError("Owner Mission scope does not satisfy canonical tool requirements")
            if plan_step.scope_requirement and plan_step.scope_requirement not in scope:
                raise SkillAuthorizationError("candidate scope is wider than the completed Mission step scope")
        return matched

    @staticmethod
    def _digest_json(value: Any) -> str:
        encoded = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")
        return hashlib.sha256(encoded).hexdigest()

    def _qualified_candidate_source(
        self,
        owner_session_token: str,
        mission_id: str,
        definition: SkillDefinition,
    ) -> tuple[Mission, str, MissionAuthorizationSnapshot, list[Any], list[dict[str, Any]]]:
        mission, owner_ref, snapshot = self._authorized_mission(owner_session_token, mission_id)
        matched_steps = self._candidate_steps(mission, snapshot, definition)
        records = self._trusted_mission_evidence(
            mission,
            owner_ref,
            snapshot,
            {step.step_id for step in matched_steps},
        )
        return mission, owner_ref, snapshot, matched_steps, records

    def submit_candidate(
        self,
        owner_session_token: str,
        mission_id: str,
        definition_payload: Mapping[str, Any],
    ) -> dict[str, Any]:
        if not isinstance(definition_payload, Mapping):
            raise ValueError("skill_definition_required")
        if len(json.dumps(dict(definition_payload), ensure_ascii=False, default=str).encode("utf-8")) > 32_000:
            raise ValueError("skill_definition_too_large")
        definition = SkillDefinition.from_dict(definition_payload)
        if definition.expires_at is not None:
            from agent.intelligence_layer.skills import _parse_expiry
            if _parse_expiry(definition.expires_at) <= datetime.now(timezone.utc):
                raise SkillError("candidate Skill expiry must be in the future")
        mission, owner_ref, _snapshot, matched_steps, records = self._qualified_candidate_source(
            owner_session_token,
            mission_id,
            definition,
        )
        evidence_refs = tuple(str(item["evidence_id"]) for item in records)
        task_ids = {step.step_id for step in matched_steps}

        def critic(candidate_mission_id, candidate, trajectory, evidence):
            passed = (
                candidate_mission_id == mission.mission_id
                and self._digest_json(trajectory) == self._digest_json(mission.trajectory)
                and {str(item.get("evidence_id", "")) for item in evidence} == set(evidence_refs)
            )
            try:
                passed = passed and self._candidate_steps(mission, _snapshot, candidate) == matched_steps
            except (SkillError, SkillAuthorizationError, ValueError):
                passed = False
            return SkillCritique(
                self._CRITIC_ID,
                bool(passed),
                "Candidate tools are an ordered subset of successfully completed, Owner-authorized Mission steps." if passed else "Candidate did not match verified Mission steps.",
            )

        trusted_by_id = {str(item["evidence_id"]): item for item in records}
        required_sources = tuple(sorted({str(item.get("source", "")) for item in records if item.get("source")}))

        def validator(claim, evidence):
            if claim.target != mission.mission_id or not evidence:
                return VerificationResult.FAIL
            seen = set()
            for record in evidence:
                evidence_id = str(record.get("evidence_id", ""))
                trusted = trusted_by_id.get(evidence_id)
                if (
                    trusted is None
                    or trusted.get("current_hash") != record.get("current_hash")
                    or trusted.get("mission_id") != mission.mission_id
                    or trusted.get("request_id") != mission.request_id
                    or trusted.get("authorization_hash") != authorization_digest(_snapshot)
                    or trusted.get("task_id") not in task_ids
                ):
                    return VerificationResult.FAIL
                seen.add(evidence_id)
            return VerificationResult.PASS if seen == set(evidence_refs) else VerificationResult.FAIL

        pipeline = SkillLearningPipeline(
            self.registry,
            critic=critic,
            verification_plan=VerificationPlan(self._VALIDATOR_ID, required_sources, validator),
            mission_owner_resolver=lambda mid: owner_ref if mid == mission.mission_id else "",
        )
        revision = pipeline.propose_candidate(
            owner_ref,
            mission.mission_id,
            definition,
            trajectory=mission.trajectory,
            evidence=records,
            evidence_refs=evidence_refs,
        )
        evidence = self._source_evidence(owner_ref, revision.definition.skill_id, revision.definition.version)
        return self._public_revision(revision, active=False, source_mission_id=evidence.mission_id)

    def _revalidate_candidate_source(
        self,
        owner_session_token: str,
        revision: SkillRevision,
        candidate_evidence: SkillCandidateEvidence,
    ) -> None:
        definition = revision.definition
        if (
            candidate_evidence.owner_identity_ref != revision.owner_identity_ref
            or candidate_evidence.candidate_sha256 != definition.content_hash
            or candidate_evidence.critic_id != self._CRITIC_ID
            or candidate_evidence.validator_id != self._VALIDATOR_ID
        ):
            raise SkillAuthorizationError("candidate provenance digest or verifier identity does not match")
        mission, owner_ref, _snapshot, matched_steps, records = self._qualified_candidate_source(
            owner_session_token,
            candidate_evidence.mission_id,
            definition,
        )
        evidence_refs = tuple(str(item["evidence_id"]) for item in records)
        if tuple(candidate_evidence.evidence_refs) != evidence_refs:
            raise SkillAuthorizationError("candidate evidence references no longer match the verified Mission")
        if self._digest_json(mission.trajectory) != candidate_evidence.trajectory_sha256:
            raise SkillAuthorizationError("candidate trajectory digest no longer matches its source Mission")
        if self._digest_json(records) != candidate_evidence.verification_evidence_sha256:
            raise SkillAuthorizationError("candidate evidence digest no longer matches its source Mission")
        if not matched_steps or owner_ref != revision.owner_identity_ref:
            raise SkillAuthorizationError("candidate source Mission no longer qualifies")

    def _decision_registry(
        self,
        owner_ref: str,
        action: str,
        skill_id: str,
        version: int,
        decision_id: str,
    ) -> SkillRegistry:
        def authorize(requested_action, requested_owner, requested_skill, requested_version):
            if (requested_action, requested_owner, requested_skill, requested_version) != (action, owner_ref, skill_id, version):
                return None
            return SkillApprovalGrant(owner_ref, owner_ref, action, decision_id)
        return SkillRegistry(self.db_path, approval_authorizer=authorize)

    def approve(
        self,
        owner_session_token: str,
        skill_id: str,
        version: int,
        content_hash: str,
    ) -> dict[str, Any]:
        owner_ref = self._owner_ref(owner_session_token)
        revision = self._get_revision(owner_ref, skill_id, version)
        if revision.status is not SkillStatus.CANDIDATE:
            raise SkillError("only a current candidate can be approved")
        if not _SHA256.fullmatch(str(content_hash)) or not hmac.compare_digest(revision.definition.content_hash, content_hash):
            raise SkillAuthorizationError("Skill candidate content digest changed")
        evidence = self._source_evidence(owner_ref, skill_id, version)
        self._revalidate_candidate_source(owner_session_token, revision, evidence)
        approved = self._decision_registry(owner_ref, "approve", skill_id, version, "owner-skill-approve:" + uuid.uuid4().hex).approve(owner_ref, skill_id, version)
        return self._public_revision(approved, active=True, source_mission_id=evidence.mission_id)

    def revoke(
        self,
        owner_session_token: str,
        skill_id: str,
        version: int,
        content_hash: str,
    ) -> dict[str, Any]:
        owner_ref = self._owner_ref(owner_session_token)
        revision = self._get_revision(owner_ref, skill_id, version)
        if revision.status is not SkillStatus.APPROVED:
            raise SkillError("only a currently approved Skill revision can be revoked")
        if not _SHA256.fullmatch(str(content_hash)) or not hmac.compare_digest(revision.definition.content_hash, content_hash):
            raise SkillAuthorizationError("Skill revision content digest changed")
        evidence = self._source_evidence(owner_ref, skill_id, version)
        self._decision_registry(owner_ref, "revoke", skill_id, version, "owner-skill-revoke:" + uuid.uuid4().hex).revoke(owner_ref, skill_id, version)
        updated = self.registry.get_revision(owner_ref, skill_id, version)
        if updated is None:
            raise SkillAuthorizationError("Skill revision disappeared after revocation")
        return self._public_revision(updated, active=False, source_mission_id=evidence.mission_id)


__all__ = ["OwnerSkillService"]
