from __future__ import annotations

import json
import urllib.error
import urllib.request


class OpenAICompatibleProvider:
    def __init__(self, name: str, base_url: str, model: str, api_key: str = ""):
        self.name = name
        self.base_url = base_url.rstrip("/")
        self.model = model
        self.api_key = api_key
        self.failure_count = 0
        self.last_error = ""

    def status(self) -> dict:
        return {
            "name": self.name,
            "model": self.model,
            "base_url": self.base_url,
            "configured": bool(self.base_url and self.model),
            "failure_count": self.failure_count,
            "last_error": self.last_error,
        }

    def chat(self, messages: list[dict], temperature: float = 0, timeout: int = 90) -> dict:
        payload = {"model": self.model, "messages": messages, "temperature": temperature}
        req = urllib.request.Request(
            self.base_url + "/chat/completions",
            data=json.dumps(payload).encode(),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        if self.api_key:
            req.add_header("Authorization", "Bearer " + self.api_key)
        try:
            with urllib.request.urlopen(req, timeout=timeout) as response:
                data = json.loads(response.read().decode())
            content = data["choices"][0]["message"]["content"]
            if not isinstance(content, str):
                raise ValueError("provider returned non-text content")
            self.last_error = ""
            return {"content": content, "provider": self.name, "model": self.model}
        except Exception as exc:
            self.failure_count += 1
            self.last_error = str(exc)[:500]
            raise
