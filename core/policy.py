from __future__ import annotations

from dataclasses import dataclass

from .trust import TrustedRequest, is_owner_instruction


@dataclass(frozen=True)
class Decision:
    allowed: bool
    reason: str
    policy_source: str = "owner_instruction"
    enforcement_required: bool = True


def evaluate(req: TrustedRequest) -> Decision:
    """Classify a trusted Owner instruction; do not turn keywords into authority.

    This layer deliberately performs no model safety veto and no tool authorization.
    Deterministic enforcement happens later through OwnerPolicy, AuthorizationContext,
    ScopeSnapshot, and the tool registry. Host/platform safety boundaries remain
    outside this application policy classifier.
    """
    if not is_owner_instruction(req):
        return Decision(False, "الطلب ليس أمرًا موثوقًا من المالك.", policy_source="trust_boundary")
    return Decision(True, "owner-instruction-accepted-for-deterministic-enforcement", policy_source="owner_instruction")


__all__ = ["Decision", "evaluate"]
