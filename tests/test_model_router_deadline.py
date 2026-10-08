from __future__ import annotations

import time

import pytest

from agent.model_router import ModelRouter
from agent.provider_api import ProviderCapabilities, ProviderDeployment, ProviderTimeout


class SlowProvider:
    name = "local-test"
    model = "deadline-test"
    deployment = ProviderDeployment.LOCAL
    capabilities = ProviderCapabilities(generate=True, tool_calling=True)

    def __init__(self):
        self.last_timeout = None

    def generate(self, _messages, *, temperature=0, timeout=None, **_kwargs):
        self.last_timeout = timeout
        time.sleep(0.06)
        return {"content": "late response"}

    def tool_calling(self, _messages, _tools, *, temperature=0, timeout=None, **_kwargs):
        self.last_timeout = timeout
        time.sleep(0.06)
        return {"content": "late response", "tool_calls": []}


@pytest.mark.parametrize("capability", ["generate", "tool_calling"])
def test_router_rejects_provider_success_after_deadline(capability):
    provider = SlowProvider()
    router = ModelRouter([provider])

    with pytest.raises(ProviderTimeout):
        if capability == "generate":
            router.generate([{"role": "user", "content": "bounded"}], timeout=0.02)
        else:
            router.tool_calling(
                [{"role": "user", "content": "bounded"}],
                [],
                timeout=0.02,
            )

    assert 0 < provider.last_timeout <= 0.02
