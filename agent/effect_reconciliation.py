from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
import hashlib
import json
import re
from typing import Any, Callable, Mapping, Protocol

from .external_effects import EffectState, ExternalEffect, ExternalEffectLedger
from .execution_fence import authorization_snapshot_matches_mission
from .mission import Mission, MissionStatus, MissionStore
from security.authorization_context import AuthorizationContext, AuthorizationDecision
from security.mission_authorization import MissionAuthorizationSnapshot


_CONTROL_TOOL = "reconcile_external_effect"
_PROVIDER_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")


class EffectReconciliationError(PermissionError):
    """A reconciliation request is invalid, unauthorized, or unsafe to apply."""


class EffectReconciliationAction(str, Enum):
    RECONCILE = "RECONCILE"
    PROVIDER_LOOKUP = "PROVIDER_LOOKUP"
    OWNER_CONFIRM_APPLIED = "OWNER_CONFIRM_APPLIED"
    OWNER_CONFIRM_NO_EFFECT = "OWNER_CONFIRM_NO_EFFECT"


class ProviderEffectStatus(str, Enum):
    APPLIED = "APPLIED"
    CONFIRMED_NO_EFFECT = "CONFIRMED_NO_EFFECT"
    UNKNOWN = "UNKNOWN"


class ReconciliationStatus(str, Enum):
    RETRY_ELIGIBLE = "RETRY_ELIGIBLE"
    RETRY_NOT_PERMITTED = "RETRY_NOT_PERMITTED"
    ALREADY_SUCCEEDED = "ALREADY_SUCCEEDED"
    PROVIDER_CONFIRMED_APPLIED = "PROVIDER_CONFIRMED_APPLIED"
    PROVIDER_CONFIRMED_NO_EFFECT = "PROVIDER_CONFIRMED_NO_EFFECT"
    OWNER_CONFIRMED_APPLIED = "OWNER_CONFIRMED_APPLIED"
    OWNER_CONFIRMED_NO_EFFECT = "OWNER_CONFIRMED_NO_EFFECT"
    OWNER_RECONCILIATION_REQUIRED = "OWNER_RECONCILIATION_REQUIRED"
    RECOVERY_REQUIRED = "RECOVERY_REQUIRED"


def _canonical(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str)


def _sha256(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _authenticated_owner_ref(context: AuthorizationContext) -> str:
    if not isinstance(context, AuthorizationContext) or not context.session_id:
        raise EffectReconciliationError("an active Owner session is required")
    from security.owner_password import authenticated_owner
    owner = authenticated_owner(context.session_id)
    if not isinstance(owner, dict) or owner.get("owner_id") is None:
        raise EffectReconciliationError("active Owner session could not be resolved")
    return f"owner:{int(owner['owner_id'])}"


def _reference_digest(reference: str, *, required: bool) -> str:
    if not isinstance(reference, str) or len(reference) > 512:
        raise EffectReconciliationError("evidence reference is invalid")
    if required and not reference.strip():
        raise EffectReconciliationError("an evidence reference is required for Owner confirmation")
    return _sha256(reference) if reference else ""


def _provider_observation_digest(effect: ExternalEffect, observation: Any) -> str:
    payload: dict[str, Any] = {
        "effect_id": effect.effect_id,
        "dispatch_id": effect.dispatch_id,
        "provider": effect.provider,
    }
    if isinstance(observation, EffectProviderObservation):
        payload.update(
            {
                "observed_effect_id": observation.effect_id,
                "operation_fingerprint": observation.operation_fingerprint,
                "argument_sha256": observation.argument_sha256,
                "idempotency_key_sha256": observation.idempotency_key_sha256,
                "status": observation.status.value,
                "proof_sha256": _sha256(observation.provider_proof),
                "evidence_reference_sha256": _sha256(observation.evidence_reference),
            }
        )
    else:
        payload["invalid_response_type"] = type(observation).__name__
    return _sha256(_canonical(payload))


@dataclass(frozen=True)
class EffectReconciliationAuthorization:
    """Short-lived Owner decision bound to one effect, action, and evidence digest."""

    effect_id: str
    mission_id: str
    task_id: str
    task_version: int
    execution_id: str
    origin_request_id: str
    owner_identity_ref: str
    action: EffectReconciliationAction
    evidence_sha256: str
    control_request_id: str
    context: AuthorizationContext = field(repr=False, compare=False)
    decision: AuthorizationDecision = field(repr=False, compare=False)

    @classmethod
    def issue(
        cls,
        context: AuthorizationContext,
        *,
        effect: ExternalEffect,
        owner_identity_ref: str,
        action: EffectReconciliationAction | str,
        evidence_reference: str = "",
    ) -> "EffectReconciliationAuthorization":
        if not isinstance(context, AuthorizationContext):
            raise EffectReconciliationError("reconciliation requires an authenticated Owner context")
        if not context.owner_evidence.is_valid(context.request_id, context.session_id):
            raise EffectReconciliationError("Owner evidence is missing, stale, or invalid")
        authenticated_owner_ref = _authenticated_owner_ref(context)
        if (
            not isinstance(owner_identity_ref, str)
            or not owner_identity_ref
            or owner_identity_ref != authenticated_owner_ref
            or effect.owner_identity_ref != owner_identity_ref
        ):
            raise EffectReconciliationError("Owner identity does not match the effect's durable mission owner")
        try:
            normalized_action = EffectReconciliationAction(action)
        except (TypeError, ValueError) as exc:
            raise EffectReconciliationError("unsupported reconciliation action") from exc
        evidence_sha256 = _reference_digest(
            evidence_reference,
            required=normalized_action in {
                EffectReconciliationAction.OWNER_CONFIRM_APPLIED,
                EffectReconciliationAction.OWNER_CONFIRM_NO_EFFECT,
            },
        )
        payload = cls._decision_payload(effect, owner_identity_ref, normalized_action, evidence_sha256)
        decision = AuthorizationDecision.issue(
            context,
            allowed=True,
            reason="authenticated Owner requested effect reconciliation",
            tool=_CONTROL_TOOL,
            risk_class="owner-control",
            argument=payload,
        )
        return cls(
            effect_id=effect.effect_id,
            mission_id=effect.mission_id,
            task_id=effect.task_id,
            task_version=effect.task_version,
            execution_id=effect.execution_id,
            origin_request_id=effect.request_id,
            owner_identity_ref=owner_identity_ref,
            action=normalized_action,
            evidence_sha256=evidence_sha256,
            control_request_id=context.request_id,
            context=context,
            decision=decision,
        )

    @staticmethod
    def _decision_payload(
        effect: ExternalEffect,
        owner_identity_ref: str,
        action: EffectReconciliationAction,
        evidence_sha256: str,
    ) -> dict[str, Any]:
        return {
            "effect_id": effect.effect_id,
            "mission_id": effect.mission_id,
            "task_id": effect.task_id,
            "task_version": effect.task_version,
            "execution_id": effect.execution_id,
            "origin_request_id": effect.request_id,
            "owner_identity_ref": owner_identity_ref,
            "provider": effect.provider,
            "operation": effect.operation,
            "operation_fingerprint": effect.operation_fingerprint,
            "argument_sha256": effect.argument_sha256,
            "idempotency_supported": effect.idempotency_supported,
            "idempotency_key_sha256": _sha256(effect.idempotency_key) if effect.idempotency_key else "",
            "action": action.value,
            "evidence_sha256": evidence_sha256,
        }

    @property
    def authorization_ref(self) -> str:
        payload = self.decision.to_dict()
        return _sha256(_canonical(payload))

    def validate_for(
        self,
        effect: ExternalEffect,
        *,
        owner_identity_ref: str,
        action: EffectReconciliationAction | str,
    ) -> bool:
        try:
            expected_action = EffectReconciliationAction(action)
            if not isinstance(effect, ExternalEffect):
                return False
            if not self.context.owner_evidence.is_valid(
                self.context.request_id, self.context.session_id
            ):
                return False
            authenticated_owner_ref = _authenticated_owner_ref(self.context)
            if (
                self.action != expected_action
                or self.effect_id != effect.effect_id
                or self.mission_id != effect.mission_id
                or self.task_id != effect.task_id
                or self.task_version != effect.task_version
                or self.execution_id != effect.execution_id
                or self.origin_request_id != effect.request_id
                or self.owner_identity_ref != owner_identity_ref
                or self.owner_identity_ref != effect.owner_identity_ref
                or self.owner_identity_ref != authenticated_owner_ref
                or self.control_request_id != self.context.request_id
                or self.decision.owner_evidence_fingerprint != self.context.owner_evidence_fingerprint
                or self.decision.policy_fingerprint != self.context.policy_fingerprint
            ):
                return False
            payload = self._decision_payload(effect, owner_identity_ref, expected_action, self.evidence_sha256)
            return self.decision.is_valid_for(
                _CONTROL_TOOL,
                argument=payload,
                request_id=self.context.request_id,
            )
        except (AttributeError, TypeError, ValueError):
            return False

    def assert_valid_for(
        self,
        effect: ExternalEffect,
        *,
        owner_identity_ref: str,
        action: EffectReconciliationAction | str,
    ) -> None:
        if not self.validate_for(effect, owner_identity_ref=owner_identity_ref, action=action):
            raise EffectReconciliationError("Owner reconciliation authorization is invalid or misbound")


@dataclass(frozen=True)
class EffectProviderObservation:
    provider_id: str
    effect_id: str
    operation_fingerprint: str
    argument_sha256: str
    dispatch_id: str
    idempotency_key_sha256: str
    provider_proof: str
    status: ProviderEffectStatus
    evidence_reference: str

    def __post_init__(self) -> None:
        if not isinstance(self.provider_id, str) or not _PROVIDER_ID.fullmatch(self.provider_id):
            raise ValueError("provider observation has an invalid provider id")
        if not isinstance(self.effect_id, str) or not self.effect_id.strip() or len(self.effect_id) > 128:
            raise ValueError("provider observation must bind an effect id")
        if not isinstance(self.operation_fingerprint, str) or not _SHA256.fullmatch(self.operation_fingerprint):
            raise ValueError("provider observation must bind an operation fingerprint")
        if self.argument_sha256 and not _SHA256.fullmatch(self.argument_sha256):
            raise ValueError("provider observation argument binding must be a SHA-256 digest")
        if not isinstance(self.dispatch_id, str) or not self.dispatch_id.strip() or len(self.dispatch_id) > 128:
            raise ValueError("provider observation must bind a dispatch id")
        if self.idempotency_key_sha256 and not _SHA256.fullmatch(self.idempotency_key_sha256):
            raise ValueError("provider observation idempotency binding must be a SHA-256 digest")
        if not isinstance(self.provider_proof, str) or not self.provider_proof.strip() or len(self.provider_proof) > 4096:
            raise ValueError("provider observation must include a bounded proof for adapter verification")
        if not isinstance(self.status, ProviderEffectStatus):
            raise TypeError("provider status must be a typed ProviderEffectStatus")
        if not isinstance(self.evidence_reference, str) or not self.evidence_reference.strip() or len(self.evidence_reference) > 512:
            raise ValueError("provider observation must contain a bounded evidence reference")


class EffectStatusLookupAdapter(Protocol):
    """Provider-specific lookup with mandatory cryptographic response verification."""

    provider_id: str

    def lookup_status(self, effect: ExternalEffect) -> EffectProviderObservation:
        ...

    def verify_observation(self, effect: ExternalEffect, observation: EffectProviderObservation) -> bool:
        """Verify the authenticated provider receipt is bound to this exact effect."""
        ...


@dataclass(frozen=True)
class EffectInspection:
    effect_id: str
    mission_id: str
    task_id: str
    task_version: int
    execution_id: str
    origin_request_id: str
    provider: str
    operation: str
    state: EffectState
    created_at: str
    updated_at: str
    idempotency_supported: bool
    has_idempotency_key: bool
    error_code: str
    requires_reconciliation: bool
    owner_binding_status: str


@dataclass(frozen=True)
class ReconciliationResult:
    effect_id: str
    effect_state: EffectState
    status: ReconciliationStatus
    retry_policy_allows: bool
    dispatch_authorized: bool
    owner_resume_required: bool
    reason_code: str
    resolution_source: str


class EffectReconciliationEngine:
    """Deterministic A–F reconciliation; it never dispatches a tool or retries an effect."""

    def __init__(
        self,
        *,
        ledger: ExternalEffectLedger,
        mission_store: MissionStore,
        provider_adapters: Mapping[str, EffectStatusLookupAdapter] | None = None,
        retry_policy: Callable[[ExternalEffect], bool] | None = None,
    ) -> None:
        if not isinstance(ledger, ExternalEffectLedger):
            raise TypeError("reconciliation requires ExternalEffectLedger")
        if mission_store is None or not callable(getattr(mission_store, "load", None)):
            raise TypeError("reconciliation requires the authoritative MissionStore")
        self.ledger = ledger
        self.mission_store = mission_store
        self.provider_adapters = dict(provider_adapters or {})
        for provider_id, adapter in self.provider_adapters.items():
            if (
                not isinstance(provider_id, str)
                or not _PROVIDER_ID.fullmatch(provider_id)
                or getattr(adapter, "provider_id", None) != provider_id
                or not callable(getattr(adapter, "lookup_status", None))
                or not callable(getattr(adapter, "verify_observation", None))
            ):
                raise ValueError("provider status adapter registration is invalid")
        self.retry_policy = retry_policy or (lambda _effect: False)

    def _load(self, effect_id: str) -> tuple[ExternalEffect, Mission]:
        if not isinstance(effect_id, str) or not effect_id.strip() or len(effect_id) > 128:
            raise EffectReconciliationError("effect id is invalid")
        effect = self.ledger.get(effect_id)
        if effect is None:
            raise KeyError("unknown_effect")
        mission = self.mission_store.load(effect.mission_id)
        if mission is None or mission.mission_id != effect.mission_id:
            raise EffectReconciliationError("authoritative mission record is missing")
        identity_metadata = {
            "mission_id": effect.mission_id,
            "task_id": effect.task_id,
            "task_version": effect.task_version,
            "execution_id": effect.execution_id,
            "request_id": effect.request_id,
        }
        if ExternalEffectLedger._effect_id(
            identity_metadata, effect.provider, effect.operation_fingerprint
        ) != effect.effect_id:
            raise EffectReconciliationError("effect identity does not match its deterministic key")
        try:
            snapshot = MissionAuthorizationSnapshot.from_dict(dict(mission.authorization_snapshot or {}))
        except (KeyError, TypeError, ValueError, PermissionError) as exc:
            raise EffectReconciliationError("mission authorization snapshot is invalid") from exc
        if (
            snapshot.mission_id != effect.mission_id
            or not authorization_snapshot_matches_mission(
                mission,
                effect.authorization_hash,
                at=effect.created_at,
            )
            or mission.request_id != effect.request_id
            or not mission.owner_identity_ref
            or snapshot.owner_identity != mission.owner_identity_ref
            or effect.owner_identity_ref != mission.owner_identity_ref
        ):
            raise EffectReconciliationError("effect owner or authorization is not bound to the persisted mission")
        return effect, mission

    @staticmethod
    def _assert_owner_context(context: AuthorizationContext | None, mission: Mission) -> None:
        if not isinstance(context, AuthorizationContext):
            raise EffectReconciliationError("Owner authentication is required to inspect effects")
        if not context.owner_evidence.is_valid(context.request_id, context.session_id):
            raise EffectReconciliationError("Owner evidence is missing, stale, or invalid")
        if _authenticated_owner_ref(context) != mission.owner_identity_ref:
            raise EffectReconciliationError("authenticated Owner does not own this mission")

    def inspect(self, effect_id: str, *, context: AuthorizationContext | None) -> EffectInspection:
        effect, mission = self._load(effect_id)
        self._assert_owner_context(context, mission)
        return EffectInspection(
            effect_id=effect.effect_id,
            mission_id=effect.mission_id,
            task_id=effect.task_id,
            task_version=effect.task_version,
            execution_id=effect.execution_id,
            origin_request_id=effect.request_id,
            provider=effect.provider,
            operation=effect.operation,
            state=EffectState(effect.state),
            created_at=effect.created_at,
            updated_at=effect.updated_at,
            idempotency_supported=effect.idempotency_supported,
            has_idempotency_key=bool(effect.idempotency_key),
            error_code=effect.error_code,
            requires_reconciliation=effect.requires_reconciliation,
            owner_binding_status="BOUND",
        )

    def authorize(
        self,
        effect_id: str,
        *,
        context: AuthorizationContext,
        action: EffectReconciliationAction | str,
        evidence_reference: str = "",
    ) -> EffectReconciliationAuthorization:
        """Issue an exact-effect grant only after resolving its durable mission owner."""
        effect, mission = self._load(effect_id)
        self._assert_owner_context(context, mission)
        return EffectReconciliationAuthorization.issue(
            context,
            effect=effect,
            owner_identity_ref=mission.owner_identity_ref,
            action=action,
            evidence_reference=evidence_reference,
        )

    def _assert_grant(
        self,
        authorization: EffectReconciliationAuthorization | None,
        effect: ExternalEffect,
        mission: Mission,
        *,
        actions: set[EffectReconciliationAction],
    ) -> EffectReconciliationAction:
        if not isinstance(authorization, EffectReconciliationAuthorization):
            raise EffectReconciliationError("Owner reconciliation authorization is required")
        self._assert_owner_context(authorization.context, mission)
        for action in actions:
            if authorization.validate_for(
                effect,
                owner_identity_ref=mission.owner_identity_ref,
                action=action,
            ):
                return action
        raise EffectReconciliationError("Owner reconciliation authorization is invalid or misbound")

    def _retry_allowed(self, effect: ExternalEffect) -> bool:
        try:
            return self.retry_policy(effect) is True
        except Exception:
            return False

    @staticmethod
    def _result(
        effect: ExternalEffect,
        status: ReconciliationStatus,
        *,
        retry_policy_allows: bool = False,
        owner_resume_required: bool = False,
        reason_code: str,
        resolution_source: str,
    ) -> ReconciliationResult:
        return ReconciliationResult(
            effect_id=effect.effect_id,
            effect_state=EffectState(effect.state),
            status=status,
            retry_policy_allows=retry_policy_allows,
            dispatch_authorized=False,
            owner_resume_required=owner_resume_required,
            reason_code=reason_code,
            resolution_source=resolution_source,
        )

    def _check_idle(self, effect: ExternalEffect) -> None:
        if self.ledger.has_active_worker_lease(effect.mission_id):
            raise EffectReconciliationError("active_worker_lease_blocks_reconciliation")

    @staticmethod
    def _require_checkpoint_binding(mission: Mission, effect: ExternalEffect) -> None:
        checkpoint = mission.checkpoint if isinstance(mission.checkpoint, dict) else {}
        if (
            effect.task_version != mission.plan.version
            or checkpoint.get("plan_version") != effect.task_version
        ):
            raise EffectReconciliationError("effect plan version does not match the current mission checkpoint")
        status = checkpoint.get("status")
        if status == "in_flight":
            if checkpoint.get("step_id") != effect.task_id:
                raise EffectReconciliationError("effect task does not match the durable mission checkpoint")
            action_id = checkpoint.get("action_id") or checkpoint.get("tool_call_id")
            if str(action_id or "") != effect.execution_id:
                raise EffectReconciliationError("effect execution does not match the durable mission checkpoint")
            return
        if status == "in_flight_parallel":
            execution_ids = [str(item) for item in checkpoint.get("execution_ids", ())]
            task_ids = [str(item) for item in checkpoint.get("task_ids", ())]
            if len(execution_ids) == len(task_ids) and any(
                execution_id == effect.execution_id and task_id == effect.task_id
                for execution_id, task_id in zip(execution_ids, task_ids)
            ):
                return
        raise EffectReconciliationError("effect is not bound to the current in-flight mission checkpoint")

    @classmethod
    def _require_recovery_mission(cls, mission: Mission, effect: ExternalEffect) -> None:
        if mission.status is not MissionStatus.RECOVERY_REQUIRED:
            raise EffectReconciliationError("mission_must_be_quarantined_before_reconciliation")
        cls._require_checkpoint_binding(mission, effect)

    def reconcile(
        self,
        effect_id: str,
        *,
        authorization: EffectReconciliationAuthorization | None,
    ) -> ReconciliationResult:
        effect, mission = self._load(effect_id)
        action = self._assert_grant(
            authorization,
            effect,
            mission,
            actions={EffectReconciliationAction.RECONCILE, EffectReconciliationAction.PROVIDER_LOOKUP},
        )
        self._check_idle(effect)

        state = EffectState(effect.state)
        if state is EffectState.SUCCEEDED:
            return self._result(
                effect,
                ReconciliationStatus.ALREADY_SUCCEEDED,
                reason_code="EFFECT_ALREADY_SUCCEEDED",
                resolution_source="LEDGER",
            )
        if state is EffectState.FAILED:
            self._require_checkpoint_binding(mission, effect)
            permitted = self._retry_allowed(effect)
            return self._result(
                effect,
                ReconciliationStatus.RETRY_ELIGIBLE if permitted else ReconciliationStatus.RETRY_NOT_PERMITTED,
                retry_policy_allows=permitted,
                owner_resume_required=permitted,
                reason_code="NO_EFFECT_CONFIRMED_RETRY_POLICY",
                resolution_source="LEDGER",
            )
        if state in {EffectState.PLANNED, EffectState.RESERVED}:
            self._require_checkpoint_binding(mission, effect)
            permitted = self._retry_allowed(effect)
            return self._result(
                effect,
                ReconciliationStatus.RETRY_ELIGIBLE if permitted else ReconciliationStatus.RETRY_NOT_PERMITTED,
                retry_policy_allows=permitted,
                owner_resume_required=permitted,
                reason_code="PROVIDER_DISPATCH_NOT_STARTED",
                resolution_source="LEDGER",
            )
        if state not in {
            EffectState.DISPATCHED,
            EffectState.AMBIGUOUS,
            EffectState.UNKNOWN,
            EffectState.RECOVERY_REQUIRED,
        }:
            raise EffectReconciliationError("effect state is not eligible for reconciliation")
        self._require_recovery_mission(mission, effect)
        if action is not EffectReconciliationAction.PROVIDER_LOOKUP:
            raise EffectReconciliationError("provider lookup authorization is required")

        adapter = self.provider_adapters.get(effect.provider)
        if adapter is None:
            updated = self.ledger.apply_reconciliation(
                effect.effect_id,
                target_state=EffectState.RECOVERY_REQUIRED,
                authorization=authorization,
                mission_store=self.mission_store,
                resolution_source="PROVIDER_STATUS",
                reason_code="STATUS_LOOKUP_UNAVAILABLE",
                evidence_sha256=_sha256("status-lookup-unavailable:" + effect.provider),
            )
            return self._result(
                updated,
                ReconciliationStatus.OWNER_RECONCILIATION_REQUIRED,
                reason_code="PROVIDER_STATUS_LOOKUP_UNAVAILABLE",
                resolution_source="PROVIDER_STATUS",
            )

        try:
            observation = adapter.lookup_status(effect)
        except Exception as exc:
            updated = self.ledger.apply_reconciliation(
                effect.effect_id,
                target_state=EffectState.RECOVERY_REQUIRED,
                authorization=authorization,
                mission_store=self.mission_store,
                resolution_source="PROVIDER_STATUS",
                reason_code="PROVIDER_LOOKUP_FAILED",
                evidence_sha256=_sha256("adapter-error:" + type(exc).__name__),
            )
            return self._result(
                updated,
                ReconciliationStatus.RECOVERY_REQUIRED,
                reason_code="PROVIDER_LOOKUP_FAILED",
                resolution_source="PROVIDER_STATUS",
            )

        expected_idempotency_hash = _sha256(effect.idempotency_key) if effect.idempotency_key else ""
        binding_valid = (
            isinstance(observation, EffectProviderObservation)
            and observation.provider_id == effect.provider
            and observation.effect_id == effect.effect_id
            and observation.operation_fingerprint == effect.operation_fingerprint
            and observation.argument_sha256 == effect.argument_sha256
            and observation.dispatch_id == effect.dispatch_id
            and observation.idempotency_key_sha256 == expected_idempotency_hash
            and isinstance(observation.status, ProviderEffectStatus)
        )
        proof_valid = False
        if binding_valid:
            try:
                proof_valid = adapter.verify_observation(effect, observation) is True
            except Exception:
                proof_valid = False
        if not binding_valid or not proof_valid:
            observation_status = ProviderEffectStatus.UNKNOWN
            reason_code = "INVALID_PROVIDER_PROOF" if binding_valid else "INVALID_PROVIDER_RESPONSE"
        else:
            observation_status = observation.status
            reason_code = {
                ProviderEffectStatus.APPLIED: "PROVIDER_CONFIRMED_APPLIED",
                ProviderEffectStatus.CONFIRMED_NO_EFFECT: "PROVIDER_CONFIRMED_NO_EFFECT",
                ProviderEffectStatus.UNKNOWN: "PROVIDER_STATUS_UNKNOWN",
            }[observation_status]

        target_state = {
            ProviderEffectStatus.APPLIED: EffectState.SUCCEEDED,
            ProviderEffectStatus.CONFIRMED_NO_EFFECT: EffectState.FAILED,
            ProviderEffectStatus.UNKNOWN: EffectState.RECOVERY_REQUIRED,
        }[observation_status]
        updated = self.ledger.apply_reconciliation(
            effect.effect_id,
            target_state=target_state,
            authorization=authorization,
            mission_store=self.mission_store,
            resolution_source="PROVIDER_STATUS",
            reason_code=reason_code,
            evidence_sha256=_provider_observation_digest(effect, observation),
        )
        if observation_status is ProviderEffectStatus.APPLIED:
            return self._result(
                updated,
                ReconciliationStatus.PROVIDER_CONFIRMED_APPLIED,
                reason_code=reason_code,
                resolution_source="PROVIDER_STATUS",
            )
        if observation_status is ProviderEffectStatus.CONFIRMED_NO_EFFECT:
            permitted = self._retry_allowed(updated)
            status = ReconciliationStatus.RETRY_ELIGIBLE if permitted else ReconciliationStatus.RETRY_NOT_PERMITTED
            return self._result(
                updated,
                status,
                retry_policy_allows=permitted,
                owner_resume_required=permitted,
                reason_code=reason_code,
                resolution_source="PROVIDER_STATUS",
            )
        return self._result(
            updated,
            ReconciliationStatus.RECOVERY_REQUIRED,
            reason_code=reason_code,
            resolution_source="PROVIDER_STATUS",
        )

    def apply_owner_decision(
        self,
        effect_id: str,
        *,
        authorization: EffectReconciliationAuthorization | None,
    ) -> ReconciliationResult:
        effect, mission = self._load(effect_id)
        action = self._assert_grant(
            authorization,
            effect,
            mission,
            actions={
                EffectReconciliationAction.OWNER_CONFIRM_APPLIED,
                EffectReconciliationAction.OWNER_CONFIRM_NO_EFFECT,
            },
        )
        desired_state = (
            EffectState.SUCCEEDED
            if action is EffectReconciliationAction.OWNER_CONFIRM_APPLIED
            else EffectState.FAILED
        )
        current_state = EffectState(effect.state)
        if current_state is desired_state:
            if desired_state is EffectState.SUCCEEDED:
                return self._result(
                    effect,
                    ReconciliationStatus.ALREADY_SUCCEEDED,
                    reason_code="EFFECT_ALREADY_SUCCEEDED",
                    resolution_source="OWNER",
                )
            permitted = self._retry_allowed(effect)
            return self._result(
                effect,
                ReconciliationStatus.RETRY_ELIGIBLE if permitted else ReconciliationStatus.RETRY_NOT_PERMITTED,
                retry_policy_allows=permitted,
                owner_resume_required=permitted,
                reason_code="NO_EFFECT_ALREADY_CONFIRMED",
                resolution_source="OWNER",
            )
        if current_state in {EffectState.SUCCEEDED, EffectState.FAILED}:
            raise EffectReconciliationError("Owner outcome conflicts with an immutable terminal effect state")
        self._check_idle(effect)
        self._require_recovery_mission(mission, effect)
        updated = self.ledger.apply_reconciliation(
            effect.effect_id,
            target_state=desired_state,
            authorization=authorization,
            mission_store=self.mission_store,
            resolution_source="OWNER",
            reason_code=action.value,
            evidence_sha256=authorization.evidence_sha256,
        )
        if desired_state is EffectState.SUCCEEDED:
            return self._result(
                updated,
                ReconciliationStatus.OWNER_CONFIRMED_APPLIED,
                reason_code="OWNER_CONFIRMED_APPLIED",
                resolution_source="OWNER",
            )
        permitted = self._retry_allowed(updated)
        status = ReconciliationStatus.RETRY_ELIGIBLE if permitted else ReconciliationStatus.RETRY_NOT_PERMITTED
        return self._result(
            updated,
            status,
            retry_policy_allows=permitted,
            owner_resume_required=permitted,
            reason_code="OWNER_CONFIRMED_NO_EFFECT",
            resolution_source="OWNER",
        )


__all__ = [
    "EffectProviderObservation",
    "EffectReconciliationAction",
    "EffectReconciliationAuthorization",
    "EffectReconciliationEngine",
    "EffectReconciliationError",
    "EffectStatusLookupAdapter",
    "EffectInspection",
    "ProviderEffectStatus",
    "ReconciliationResult",
    "ReconciliationStatus",
]
