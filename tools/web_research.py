"""Mission-scoped, read-only web research over the existing search provider.

Search snippets and fetched pages remain explicitly untrusted. Only exact
Owner-authorized target URLs are fetched; raw prompts, provider bodies, and
credentials are never persisted.
"""
from __future__ import annotations

from datetime import datetime, timezone
from html.parser import HTMLParser
import hashlib
import re
import threading
import unicodedata
from typing import Any, Callable
from urllib.parse import parse_qsl, urlsplit

from agent.intelligence_layer.specialist_memory import redact_specialist_text


MAX_QUERY_CHARS = 512
MAX_RESULTS = 3
MAX_RESPONSE_BYTES = 512_000
MAX_EXCERPT_CHARS = 2_000
SEARCH_TIMEOUT_SECONDS = 8.0
FETCH_TIMEOUT_SECONDS = 4.0
SENSITIVE_QUERY_KEYS = frozenset({
    "access_token", "api_key", "apikey", "auth", "authorization", "code",
    "client_secret", "key", "password", "passwd", "refresh_token", "secret",
    "session", "signature", "token",
})
_ALLOWED_CONTENT_TYPES = frozenset({"text/html", "application/xhtml+xml", "text/plain"})
_BLOCKED_HTML = frozenset({"script", "style", "noscript", "template", "svg", "canvas", "form"})
_BLOCK_TAGS = frozenset({"address", "article", "blockquote", "br", "dd", "div", "dl", "dt", "fieldset", "figcaption", "figure", "footer", "h1", "h2", "h3", "h4", "h5", "h6", "header", "hr", "li", "main", "nav", "ol", "p", "pre", "section", "table", "td", "th", "tr", "ul"})


class _VisibleText(HTMLParser):
    """Extract bounded visible text without executing or retaining active markup."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self._blocked: list[str] = []
        self._parts: list[str] = []
        self._title_parts: list[str] = []
        self._in_title = False

    def handle_starttag(self, tag: str, _attrs: list[tuple[str, str | None]]) -> None:
        name = tag.casefold()
        if name in _BLOCKED_HTML:
            self._blocked.append(name)
        if name == "title" and not self._blocked:
            self._in_title = True
        if not self._blocked and name in _BLOCK_TAGS:
            self._parts.append("\n")

    def handle_endtag(self, tag: str) -> None:
        name = tag.casefold()
        if name == "title":
            self._in_title = False
        if name in _BLOCKED_HTML:
            for index in range(len(self._blocked) - 1, -1, -1):
                if self._blocked[index] == name:
                    del self._blocked[index:]
                    break
        if not self._blocked and name in _BLOCK_TAGS:
            self._parts.append("\n")

    def handle_data(self, data: str) -> None:
        if self._blocked:
            return
        if self._in_title:
            self._title_parts.append(data)
        self._parts.append(data)

    def extract(self) -> tuple[str, str]:
        text = " ".join(self._parts)
        title = " ".join(self._title_parts)
        return text, title


def _clean_text(value: str, limit: int) -> str:
    value = unicodedata.normalize("NFC", value)
    value = redact_specialist_text(value)
    value = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", " ", value)
    value = re.sub(r"\s+", " ", value).strip()
    return value[:limit]


def _clean_query(value: str) -> str:
    text = redact_specialist_text(value)
    text = re.sub(
        r"(?i)\b(?:api[_ -]?key|access[_ -]?token|refresh[_ -]?token|password|passwd|secret|authorization|credential|private[_ -]?key)\b\s*[:=]\s*\[REDACTED(?:_[A-Z]+)?\]",
        " ",
        text,
    )
    text = re.sub(r"(?i)\bBearer\s+\[REDACTED\]", " ", text)
    text = re.sub(r"\[REDACTED(?:_[A-Z]+)?\]", " ", text)
    return re.sub(r"\s+", " ", unicodedata.normalize("NFC", text)).strip()[:MAX_QUERY_CHARS]


def _has_sensitive_url_query(url: str) -> bool:
    try:
        if redact_specialist_text(url) != url:
            return True
        return any(
            key.casefold() in SENSITIVE_QUERY_KEYS or redact_specialist_text(value) != value
            for key, value in parse_qsl(urlsplit(url).query, keep_blank_values=True)
        )
    except ValueError:
        return True


def _parse_page(body: bytes, content_type: str) -> tuple[str, str] | None:
    if not isinstance(body, bytes) or not body or len(body) > MAX_RESPONSE_BYTES:
        return None
    # Unknown/invalid UTF-8 bytes are replaced, never executed or interpreted as code.
    decoded = body.decode("utf-8", errors="replace")
    if content_type == "text/plain":
        text, title = decoded, ""
    else:
        parser = _VisibleText()
        try:
            parser.feed(decoded)
            parser.close()
        except Exception:
            return None
        text, title = parser.extract()
    cleaned = _clean_text(text, MAX_EXCERPT_CHARS)
    clean_title = _clean_text(title, 256)
    return (cleaned, clean_title) if cleaned else None


class WebResearchService:
    """Search, scope-check, fetch and cite a small set of authorized web sources."""

    def __init__(self, *, searcher: Any | None = None, fetcher: Callable[..., Any] | None = None):
        if searcher is None:
            from search.service import get_search_service
            searcher = get_search_service()
        self._searcher = searcher
        self._fetcher = fetcher or self._pinned_fetch

    @staticmethod
    def _pinned_fetch(url: str, *, timeout: float, max_response_bytes: int):
        from security.pinned_http import pinned_http_request
        return pinned_http_request(
            url,
            method="GET",
            headers={"Accept": "text/html,application/xhtml+xml,text/plain;q=0.9"},
            timeout=timeout,
            max_response_bytes=max_response_bytes,
            allow_redirect_response=False,
        )

    @staticmethod
    def _active(context: Any) -> None:
        context.assert_active()
        cancellation = getattr(context, "cancellation_event", None)
        if cancellation is not None and cancellation.is_set():
            raise PermissionError("web_research_cancelled")

    def run(self, argument: dict[str, Any], context: Any) -> dict[str, Any]:
        if not isinstance(argument, dict) or set(argument) - {"query", "max_results"}:
            raise ValueError("invalid_web_research_arguments")
        raw_query = argument.get("query")
        count = argument.get("max_results", MAX_RESULTS)
        if not isinstance(raw_query, str) or not raw_query.strip() or len(raw_query) > MAX_QUERY_CHARS:
            raise ValueError("invalid_web_research_query")
        if isinstance(count, bool) or not isinstance(count, int) or not 1 <= count <= MAX_RESULTS:
            raise ValueError("invalid_web_research_result_limit")
        query = _clean_query(raw_query)
        if not query:
            raise ValueError("web_research_query_redacted")

        self._active(context)
        query_digest = hashlib.sha256(query.encode("utf-8")).hexdigest()
        base = {
            "record_type": "UNTRUSTED_WEB_RESEARCH_BATCH",
            "trust": "untrusted_data",
            "authority": "none",
            "mission_id": str(context.mission_id),
            "task_id": str(context.execution_fence.task_id),
            "query_sha256": query_digest,
            "results": [],
            "rejected_out_of_scope": 0,
            "failed_fetches": 0,
        }
        try:
            from search.providers import SearchScope
            response = self._searcher.search(
                query,
                scope=SearchScope.WEB,
                max_results=min(MAX_RESULTS, count),
                timeout=SEARCH_TIMEOUT_SECONDS,
                use_cache=False,
            )
        except Exception:
            base.update(status="provider_unavailable", failure_code="web_search_provider_error")
            return base
        self._active(context)
        if not bool(getattr(response, "success", False)):
            base.update(status="provider_unavailable", failure_code="web_search_provider_unavailable")
            return base

        raw_records = getattr(response, "results", ())
        if not isinstance(raw_records, (list, tuple)):
            base.update(status="provider_unavailable", failure_code="invalid_search_response")
            return base
        records = raw_records[:count]
        if not records:
            base.update(status="no_results")
            return base

        scope = getattr(context, "scope_snapshot", None)
        if not isinstance(scope, dict):
            base.update(status="scope_unavailable", failure_code="mission_scope_missing")
            return base
        required_scope = {"scope_snapshot_id", "target_id", "program_id"}
        if not required_scope.issubset(scope):
            base.update(status="scope_unavailable", failure_code="mission_scope_incomplete")
            return base
        target_id = str(context.target_identity)
        if str(scope["target_id"]) != target_id:
            base.update(status="scope_denied", failure_code="target_binding_mismatch")
            return base

        from security.scope_resolver import resolve
        seen_urls: set[str] = set()
        fetch_errors: dict[str, int] = {}
        for search_result in records:
            self._active(context)
            if str(getattr(search_result, "source", "")) != "web":
                fetch_errors["invalid_search_provenance"] = fetch_errors.get("invalid_search_provenance", 0) + 1
                continue
            raw_url = getattr(search_result, "url", None)
            if not isinstance(raw_url, str) or not raw_url or len(raw_url) > 2048 or _has_sensitive_url_query(raw_url):
                fetch_errors["unsafe_source_url"] = fetch_errors.get("unsafe_source_url", 0) + 1
                continue
            try:
                scope_decision = resolve(
                    str(scope["scope_snapshot_id"]),
                    str(scope["target_id"]),
                    raw_url,
                    method="GET",
                    expected_program_id=str(scope["program_id"]),
                    consume_rate=True,
                )
            except Exception:
                base.update(status="scope_unavailable", failure_code="scope_resolver_error")
                return base
            if (
                not scope_decision.allowed
                or not scope_decision.canonical_url
                or scope_decision.program_id != str(scope["program_id"])
                or scope_decision.target_id != str(scope["target_id"])
                or scope_decision.snapshot_id != str(scope["scope_snapshot_id"])
            ):
                base["rejected_out_of_scope"] += 1
                continue
            url = scope_decision.canonical_url
            if url in seen_urls:
                continue
            seen_urls.add(url)
            if _has_sensitive_url_query(url):
                fetch_errors["unsafe_source_url"] = fetch_errors.get("unsafe_source_url", 0) + 1
                continue
            self._active(context)
            try:
                fetched = self._fetcher(url, timeout=FETCH_TIMEOUT_SECONDS, max_response_bytes=MAX_RESPONSE_BYTES)
            except Exception:
                fetch_errors["fetch_failed"] = fetch_errors.get("fetch_failed", 0) + 1
                continue
            body = getattr(fetched, "body", None)
            status = getattr(fetched, "status", None)
            headers = getattr(fetched, "headers", {})
            if not isinstance(body, bytes) or len(body) > MAX_RESPONSE_BYTES or not isinstance(status, int) or not 200 <= status < 300:
                fetch_errors["invalid_http_response"] = fetch_errors.get("invalid_http_response", 0) + 1
                continue
            content_type_header = ""
            if isinstance(headers, dict):
                content_type_header = str(headers.get("content-type", headers.get("Content-Type", "")))
            content_type = content_type_header.split(";", 1)[0].strip().casefold()
            if content_type not in _ALLOWED_CONTENT_TYPES:
                fetch_errors["unsupported_content_type"] = fetch_errors.get("unsupported_content_type", 0) + 1
                continue
            parsed = _parse_page(body, content_type)
            if parsed is None:
                fetch_errors["empty_or_unparseable_content"] = fetch_errors.get("empty_or_unparseable_content", 0) + 1
                continue
            excerpt, title = parsed
            raw_hash = hashlib.sha256(body).hexdigest()
            excerpt_hash = hashlib.sha256(excerpt.encode("utf-8")).hexdigest()
            retrieved_at = datetime.now(timezone.utc).isoformat()
            result_number = len(base["results"]) + 1
            citation = f"[W{result_number}]"
            provider = str(getattr(response, "provider", "search_service"))[:64]
            result_content = str(getattr(search_result, "content", ""))[:4096]
            source_result_hash = hashlib.sha256(result_content.encode("utf-8")).hexdigest()
            provenance = {
                "search_provider": provider,
                "search_result_sha256": source_result_hash,
                "query_sha256": query_digest,
                "scope_snapshot_id": str(scope["scope_snapshot_id"]),
                "target_id": target_id,
                "mission_id": str(context.mission_id),
                "task_id": str(context.execution_fence.task_id),
                "execution_id": str(context.execution_id),
                "tool_id": str(context.tool_id),
                "http_status": status,
                "content_type": content_type,
                "raw_content_sha256": raw_hash,
                "excerpt_sha256": excerpt_hash,
                "redirects_followed": 0,
                "network_transport": "dns_pinned_http",
            }
            evidence_payload = {
                "claim": f"Fetched the untrusted source at {url}; page facts are not independently verified.",
                "source": "web_research:scope_fetched_page",
                "evidence": {
                    "record_type": "UNTRUSTED_WEB_RESEARCH_RESULT",
                    "trust": "untrusted_data",
                    "authority": "none",
                    "citation": citation,
                    "url": url,
                    "source": "existing_web_search_provider",
                    "retrieved_at": retrieved_at,
                    "content_sha256": raw_hash,
                    "excerpt_sha256": excerpt_hash,
                    "title": title,
                    "excerpt": "[UNTRUSTED_WEB_CONTENT] " + excerpt,
                    "confidence": {"value": None, "status": "not_assessed", "reason": "retrieval_integrity_only; factual_validity_not_assessed"},
                    "provenance": provenance,
                },
                "verification": "retrieval_only_untrusted",
                "confidence": 0,
                "timestamp": retrieved_at,
                "request_id": str(context.request_id),
                "mission_id": str(context.mission_id),
                "task_id": str(context.execution_fence.task_id),
                "chain": (f"mission:{context.mission_id}", f"task:{context.execution_fence.task_id}", f"target:{target_id}"),
            }
            self._active(context)
            receipt = context.evidence_store.append(evidence_payload, execution_fence=context.execution_fence)
            receipt_digest = str(receipt.get("current_hash", "")) if isinstance(receipt, dict) else ""
            receipt_ref = hashlib.sha256(
                (str(context.mission_id) + "\0" + str(context.execution_fence.task_id) + "\0" + receipt_digest).encode("utf-8")
            ).hexdigest() if len(receipt_digest) == 64 else ""
            base["results"].append({
                "citation": citation,
                "evidence_ref": receipt_ref,
                "url": url,
                "retrieved_at": retrieved_at,
                "content_sha256": raw_hash,
                "excerpt_sha256": excerpt_hash,
                "title": title,
                "excerpt": "[UNTRUSTED_WEB_CONTENT] " + excerpt,
                "confidence": {"value": None, "status": "not_assessed", "reason": "retrieval_integrity_only; factual_validity_not_assessed"},
                "provenance": provenance,
            })

        base["failed_fetches"] = sum(fetch_errors.values())
        base["failure_categories"] = fetch_errors
        if base["results"]:
            base["status"] = "completed"
        elif base["rejected_out_of_scope"]:
            base["status"] = "no_in_scope_sources"
        elif fetch_errors:
            base["status"] = "fetch_unavailable"
        else:
            base["status"] = "no_results"
        return base


_SERVICE: WebResearchService | None = None
_SERVICE_LOCK = threading.Lock()


def get_web_research_service() -> WebResearchService:
    global _SERVICE
    if _SERVICE is None:
        with _SERVICE_LOCK:
            if _SERVICE is None:
                _SERVICE = WebResearchService()
    return _SERVICE


def web_research(argument: dict[str, Any], *, execution_context: Any) -> dict[str, Any]:
    """ToolRegistry entry point. The canonical Registry supplies the live context."""
    return get_web_research_service().run(argument, execution_context)


__all__ = ["WebResearchService", "get_web_research_service", "web_research", "MAX_QUERY_CHARS", "MAX_RESULTS", "MAX_RESPONSE_BYTES", "MAX_EXCERPT_CHARS"]
