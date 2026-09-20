from __future__ import annotations

from dataclasses import dataclass

from .trust import TrustedRequest, is_owner_instruction


@dataclass(frozen=True)
class Decision:
    allowed: bool
    reason: str


# Explicitly disallowed because this project is a defensive agent, not an
# unrestricted offensive execution framework.
BLOCKED_PATTERNS = (
    "arbitrary shell",
    "reverse shell",
    "credential theft",
    "steal credentials",
    "password dump",
    "malware deployment",
    "ransomware deployment",
    "unauthorized exploit",
    "exploit a third party",
    "bypass authentication",
    "persistence on third party",
    "disable security controls",
)


def evaluate(req: TrustedRequest) -> Decision:
    if not is_owner_instruction(req):
        return Decision(False, "الطلب ليس أمرًا موثوقًا من المالك.")
    text = req.text.casefold()
    for pattern in BLOCKED_PATTERNS:
        if pattern.casefold() in text:
            return Decision(False, "الطلب خارج حدود CyberSentinel الدفاعية المسموح بها.")
    return Decision(True, "owner-approved")
