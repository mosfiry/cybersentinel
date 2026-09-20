from __future__ import annotations
import os
from dataclasses import dataclass
from .providers import OpenAICompatibleProvider

@dataclass
class ModelRouter:
    providers: list

    @classmethod
    def from_env(cls):
        providers=[]
        # Any OpenAI-compatible endpoint can be used: local, Colab tunnel, or a hosted provider.
        for name in ('LOCAL','COLAB','HF'):
            base=os.getenv(f'{name}_LLM_BASE_URL','').strip()
            model=os.getenv(f'{name}_LLM_MODEL','').strip()
            key=os.getenv(f'{name}_LLM_API_KEY','').strip()
            if base and model:
                providers.append(OpenAICompatibleProvider(name.lower(),base,model,key))
        return cls(providers)

    def status(self):
        return [{'name':p.name,'model':p.model,'configured':True} for p in self.providers]

    def choose(self):
        return self.providers[0] if self.providers else None
