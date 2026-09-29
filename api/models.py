from __future__ import annotations

from typing import Any

from security import owner_password


_FORBIDDEN_MODEL_FIELDS = {
    "base_url", "endpoint", "url", "api_key", "apikey", "provider",
    "provider_id", "provider_name", "profile", "profile_id", "profile_name",
    "model", "model_selection",
}


def requested_model_id(payload: dict[str, Any], *, default: str | None = "auto") -> str | None:
    if not isinstance(payload, dict):
        raise ValueError("invalid_request")
    forbidden = {
        str(key).casefold().replace("-", "_")
        for key in payload
    }.intersection(_FORBIDDEN_MODEL_FIELDS)
    if forbidden:
        raise ValueError("only_model_id_is_accepted")
    if "model_id" not in payload:
        return default
    value = payload["model_id"]
    if type(value) is not str or len(value) > 64:
        raise ValueError("invalid_model_id")
    return value


def model_catalog(owner_session_token: str, *, router: Any | None = None) -> dict[str, list[dict[str, Any]]]:
    session = owner_password.resolve_session(owner_session_token)
    if session is None or session.get("auth_method") != "username_password":
        raise PermissionError("owner authentication required")
    if router is None:
        from core.engine import RUNTIME
        router = RUNTIME.router
    catalog = getattr(router, "catalog", None)
    if not callable(catalog):
        raise RuntimeError("model catalog is unavailable")
    return {"models": catalog()}
