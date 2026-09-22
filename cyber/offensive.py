"""Authorization-bound offensive execution planning.

This is the offensive-strength layer of the cyber specialization: it turns
an OffensiveMind campaign (or any candidate action list) into an executable
plan, and it executes NOTHING outside a typed, Owner-issued ScopeSnapshot.

Design contract (mirrors security/, Expert 2 territory — integration only):

* No typed ScopeSnapshot  ->  nothing is executable. Refusal, not exception.
* Method must be within the program's allowed_methods and not prohibited.
* URL must match an in-scope asset (host/scheme/port/path, wildcard-aware)
  and must NOT match any explicitly out-of-scope asset.
* Target identity must exist in the snapshot; excluded paths are refused.
* Program rate limits are enforced per snapshot+target.
* Poison text in any field grants nothing: authorization comes only from
  the typed snapshot; model output, tool output and external documents are
  UNTRUSTED DATA and can never widen scope.

The planner produces decisions; actual execution goes through the existing
security.authorization gates (authorize_tool / MissionRuntime), which remain
the sole execution authority.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Iterable, Sequence
from urllib.parse import urlsplit

from security.scope import ScopeSnapshot, canonical_host, canonical_url
from security.scope import _asset_matches

MAX_ACTIONS_PER_PLAN = 64
DEFAULT_RATE_WINDOW_SECONDS = 60.0


class ScopeRefusal(Exception):
    """Raised only for programmer errors (untyped input); never widens scope."""


@dataclass(frozen=True)
class OffensiveAction:
    """A candidate offensive action. UNTRUSTED until a scope decision says otherwise."""

    method: str = "GET"
    url: str = ""
    target_id: str = ""
    rationale: str = ""
    mitre_technique: str = ""
    source_step_id: str = ""

    def __post_init__(self) -> None:
        if not self.url:
            raise ValueError("an offensive action requires a url")
        self.__dict__["method"] = str(self.method or "GET").upper()


@dataclass(frozen=True)
class GuardDecision:
    allowed: bool
    reason: str
    action: OffensiveAction | None = None
    canonical_url: str | None = None
    rate_key: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "allowed": self.allowed,
            "reason": self.reason,
            "canonical_url": self.canonical_url,
            "rate_key": self.rate_key,
        }


class ScopeGuard:
    """Evaluates one candidate action against a typed ScopeSnapshot.

    Poison immunity is structural: nothing read from the action influences
    the scope itself — only the typed snapshot's authorization and targets
    decide, and the decision never depends on action-supplied text.
    """

    def __init__(self) -> None:
        # In-memory per-planner rate window. Durable rate limiting across
        # restarts is the scope store's job (security/, Expert 2); this is
        # documented as a per-run limitation.
        self._events: dict[str, list[float]] = {}

    def _rate_count(self, rate_key: str, now: float, window: float) -> int:
        events = [ts for ts in self._events.get(rate_key, ()) if ts >= now - window]
        self._events[rate_key] = events
        return len(events)

    def evaluate(self, action: OffensiveAction, snapshot: ScopeSnapshot | None) -> GuardDecision:
        if not isinstance(snapshot, ScopeSnapshot):
            return GuardDecision(False, "offensive execution requires a typed ScopeSnapshot", action)
        auth = snapshot.authorization
        method = action.method
        if method in auth.prohibited_methods:
            return GuardDecision(False, "method is prohibited by the program authorization", action)
        if auth.allowed_methods and method not in auth.allowed_methods:
            return GuardDecision(False, "method is not in the program's allowed methods", action)
        try:
            canonical = canonical_url(action.url)
        except Exception:
            return GuardDecision(False, "invalid url", action)
        try:
            parts = urlsplit(canonical)
            host = canonical_host(parts.hostname)
            port = parts.port
        except Exception:
            return GuardDecision(False, "invalid target host", action)
        scheme = parts.scheme.lower()
        path = parts.path or "/"
        matched_asset = None
        for asset in auth.in_scope_assets:
            if _asset_matches(asset, host, scheme, port, path):
                matched_asset = asset
                break
        if matched_asset is None:
            return GuardDecision(False, "target is not within the authorized scope", action, canonical)
        for asset in auth.out_of_scope_assets:
            if _asset_matches(asset, host, scheme, port, path):
                return GuardDecision(False, "target is explicitly out of scope", action, canonical)
        target = next((t for t in snapshot.targets if t.host == host), None)
        if target is None:
            return GuardDecision(False, "no target identity in the snapshot covers this host", action, canonical)
        if action.target_id and action.target_id != target.target_id:
            return GuardDecision(False, "action target identity mismatch", action, canonical)
        for excluded in target.excluded_paths:
            if path == excluded or path.startswith(str(excluded).rstrip("/") + "/"):
                return GuardDecision(False, "target path is excluded by the target identity", action, canonical)
        rate_key = "{}/{}".format(snapshot.snapshot_id, host)
        limit = auth.rate_limits.get("requests_per_minute") if auth.rate_limits else None
        now = time.time()
        if limit is not None:
            if self._rate_count(rate_key, now, DEFAULT_RATE_WINDOW_SECONDS) >= int(limit):
                return GuardDecision(False, "program rate limit exceeded", action, canonical, rate_key)
            self._events.setdefault(rate_key, []).append(now)
        return GuardDecision(True, "within authorized scope", action, canonical, rate_key)


class OffensiveExecutionPlanner:
    """Turns candidate offensive strength into an authorization-bound plan."""

    def __init__(self, guard: ScopeGuard | None = None):
        self.guard = guard or ScopeGuard()

    def plan_actions(
        self, actions: Iterable[OffensiveAction], snapshot: ScopeSnapshot | None
    ) -> dict[str, Any]:
        executable: list[OffensiveAction] = []
        refusals: list[dict[str, Any]] = []
        for action in actions:
            decision = self.guard.evaluate(action, snapshot)
            if decision.allowed and len(executable) < MAX_ACTIONS_PER_PLAN:
                executable.append(action)
            elif decision.allowed:
                refusals.append({"url": action.url, "reason": "plan action limit reached"})
            else:
                refusals.append({"url": action.url, "reason": decision.reason})
        return {
            "executable": executable,
            "refusals": refusals,
            "authorization_bound": True,
            "note": "decisions only; execution remains under security.authorization authority",
        }

    def plan_from_campaign(self, campaign: Any, snapshot: ScopeSnapshot | None) -> dict[str, Any]:
        """Map an OffensiveMind campaign to in-scope candidate actions.

        Steps whose target asset is not covered by the snapshot are refused —
        the campaign may think whatever it likes; the snapshot decides.
        """
        actions: list[OffensiveAction] = []
        for step in getattr(campaign, "steps", ()):
            target_asset = str(getattr(step, "target_asset", "") or "").strip()
            if not target_asset:
                continue
            actions.append(
                OffensiveAction(
                    method="GET",
                    url="https://{}/".format(target_asset),
                    rationale=str(getattr(step, "description", "")),
                    mitre_technique=str(getattr(step, "mitre_technique", "")),
                    source_step_id=str(getattr(step, "step_id", "")),
                )
            )
        return self.plan_actions(actions, snapshot)
