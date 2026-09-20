from __future__ import annotations
from .model_router import ModelRouter
from .evidence import observed
from security.owner_policy import policy_fingerprint

class AgentRuntime:
    def __init__(self):
        self.router=ModelRouter.from_env()

    def status(self):
        return {'policy_fingerprint':policy_fingerprint(),'models':self.router.status()}

    def verify_result(self, claim, source, evidence, confidence=10):
        return observed(claim,source,evidence,confidence)
