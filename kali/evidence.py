from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Sequence

from kali.runtime import ToolExecutionResult

# Fixed provenance hierarchy (identical to the project-wide hierarchy).
PROVENANCE_HIERARCHY = (
    "OWNER_INSTRUCTION",
    "SYSTEM_PLATFORM",
    "OWNER_POLICY",
    "DETERMINISTIC_ENFORCEMENT",
    "AUTHORIZATION_SCOPE",
    "TOOL_RUNTIME",
    "MODEL_OUTPUT",
    "EXTERNAL_DATA",
)


class ProvenanceLayer(str):
    """A provenance layer label. Tool output is always EXTERNAL_DATA-grade
    observation material; it can never act as or become Owner authority."""


TOOL_OUTPUT_PROVENANCE = "EXTERNAL_DATA"


@dataclass(frozen=True)
class KaliExecutionEvidence:
    """Immutable execution evidence with full provenance.

    Tool output is EVIDENCE, not a new instruction. This record cannot mutate
    owner policy, authorization snapshots, or any governance state; it is a
    pure data object.
    """

    mission_id: str
    request_id: str
    tool_id: str
    tool_version: str
    execution_id: str
    authorization_snapshot_hash: str
    target_identity: str
    scope: tuple[str, ...]
    timestamp: str
    exit_status: int | None
    stdout_metadata: dict[str, Any] = field(default_factory=dict)
    stderr_metadata: dict[str, Any] = field(default_factory=dict)
    artifacts: tuple[str, ...] = ()
    observation: dict[str, Any] = field(default_factory=dict)
    provenance: str = TOOL_OUTPUT_PROVENANCE

    def __post_init__(self) -> None:
        if self.provenance in ("OWNER_INSTRUCTION", "OWNER_POLICY", "SYSTEM_PLATFORM", "DETERMINISTIC_ENFORCEMENT", "AUTHORIZATION_SCOPE"):
            raise ValueError("tool output evidence may not claim an authority provenance layer")
        for required in (self.mission_id, self.request_id, self.tool_id, self.execution_id, self.authorization_snapshot_hash, self.target_identity, self.timestamp):
            if not str(required).strip():
                raise ValueError("kali execution evidence has missing provenance fields")

    def to_dict(self) -> dict[str, Any]:
        return {
            "mission_id": self.mission_id,
            "request_id": self.request_id,
            "tool_id": self.tool_id,
            "tool_version": self.tool_version,
            "execution_id": self.execution_id,
            "authorization_snapshot_hash": self.authorization_snapshot_hash,
            "target_identity": self.target_identity,
            "scope": list(self.scope),
            "timestamp": self.timestamp,
            "exit_status": self.exit_status,
            "stdout_metadata": dict(self.stdout_metadata),
            "stderr_metadata": dict(self.stderr_metadata),
            "artifacts": list(self.artifacts),
            "observation": dict(self.observation),
            "provenance": self.provenance,
        }

    def evidence_hash(self) -> str:
        import hashlib
        import json

        payload = json.dumps(self.to_dict(), sort_keys=True, ensure_ascii=False, separators=(",", ":"))
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def evidence_from_execution(
    *,
    result: ToolExecutionResult,
    tool,
    snapshot,
    mission_id: str,
    request_id: str,
) -> KaliExecutionEvidence:
    """Build evidence from a governed execution result.

    'snapshot' must be a genuine owner MissionAuthorizationSnapshot; the
    evidence records its hash for the chain but never inherits authority.
    """
    return KaliExecutionEvidence(
        mission_id=mission_id,
        request_id=request_id,
        tool_id=result.tool_id,
        tool_version=tool.version,
        execution_id=result.execution_id,
        authorization_snapshot_hash=snapshot.authorization_hash,
        target_identity=snapshot.target_identity,
        scope=tuple(snapshot.scope),
        timestamp=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        exit_status=result.exit_status,
        stdout_metadata={"excerpt_chars": len(result.stdout_excerpt), "has_output": bool(result.stdout_excerpt)},
        stderr_metadata={"excerpt_chars": len(result.stderr_excerpt), "has_output": bool(result.stderr_excerpt)},
        artifacts=tuple(result.artifacts),
        observation={
            "exit_status": result.exit_status,
            "timed_out": result.timed_out,
            "error": result.error,
            "duration_seconds": result.duration_seconds,
            "runtime_kind": result.runtime_kind,
        },
        provenance=TOOL_OUTPUT_PROVENANCE,
    )


__all__ = [
    "PROVENANCE_HIERARCHY",
    "ProvenanceLayer",
    "TOOL_OUTPUT_PROVENANCE",
    "KaliExecutionEvidence",
    "evidence_from_execution",
]
