from __future__ import annotations
from dataclasses import dataclass
from enum import Enum

class TrustLevel(str, Enum):
    OWNER = "owner"
    EXTERNAL = "external"
    SYSTEM = "system"

@dataclass(frozen=True)
class TrustedRequest:
    text: str
    source: str
    trust: TrustLevel

def owner_request(text: str, source: str = "web") -> TrustedRequest:
    return TrustedRequest(text=text, source=source, trust=TrustLevel.OWNER)

def external_content(text: str, source: str) -> dict:
    return {
        "trust": TrustLevel.EXTERNAL.value,
        "source": source,
        "content": text,
        "instruction_authority": False,
    }

def is_owner_instruction(req: TrustedRequest) -> bool:
    return req.trust is TrustLevel.OWNER and bool(req.text.strip())
