from __future__ import annotations

import os
from dataclasses import dataclass
from .providers import OpenAICompatibleProvider


@dataclass
class ModelRouter:
    providers: list[OpenAICompatibleProvider]

    @classmethod
    def from_env(cls):
        providers = []
        for name in ("LOCAL", "COLAB", "HF"):
            base = os.getenv(f"{name}_LLM_BASE_URL", "").strip()
            model = os.getenv(f"{name}_LLM_MODEL", "").strip()
            key = os.getenv(f"{name}_LLM_API_KEY", "").strip()
            if base and model:
                providers.append(OpenAICompatibleProvider(name.lower(), base, model, key))
        # Backward-compatible single endpoint configuration.
        base = os.getenv("LLM_BASE_URL", "").strip()
        model = os.getenv("LLM_MODEL", "").strip()
        key = os.getenv("LLM_API_KEY", "").strip()
        if base and model and not providers:
            providers.append(OpenAICompatibleProvider("default", base, model, key))
        return cls(providers)

    def status(self):
        return [provider.status() for provider in self.providers]

    def chat(self, messages: list[dict], temperature: float = 0) -> dict:
        errors = []
        for provider in self.providers:
            try:
                return provider.chat(messages, temperature=temperature)
            except Exception as exc:
                errors.append(f"{provider.name}: {str(exc)[:200]}")
        if errors:
            raise RuntimeError("all model providers failed: " + "; ".join(errors))
        raise RuntimeError("no model provider configured")
