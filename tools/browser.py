"""Mission-bound, read-only browser automation backed by real Chromium.

Every page request is intercepted and fetched through security.pinned_http;
Chromium itself is given a dead proxy so it cannot create direct network paths.
Page content is untrusted, form values never submit, and files are stored only
as opaque UNVALIDATED Mission artifacts.
"""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutureTimeout
from dataclasses import dataclass, field
from hashlib import sha256
import atexit
import json
import mimetypes
import os
from pathlib import Path
import re
import shutil
import tempfile
import threading
import time
from typing import Any
from urllib.parse import urljoin, urlsplit, urlunsplit
import uuid

from core.context import ExecutionContext

MAX_URL_CHARS = 2048
MAX_SELECTOR_CHARS = 256
MAX_FORM_VALUE_CHARS = 512
MAX_TEXT_CHARS = 6000
MAX_ITEM_CHARS = 600
MAX_LINKS = 30
MAX_DOM_NODES = 20
MAX_ARTIFACT_BYTES = 4 * 1024 * 1024
MAX_RESPONSE_BYTES = 1 * 1024 * 1024
MAX_SESSION_NETWORK_BYTES = 12 * 1024 * 1024
MAX_SESSION_REQUESTS = 64
MAX_SESSIONS = 8
SESSION_TTL_SECONDS = 15 * 60
NAVIGATION_TIMEOUT_MS = 12_000
ACTION_TIMEOUT_MS = 5_000

SAFE_REQUEST_HEADERS = frozenset({
    "accept", "accept-language", "user-agent", "cookie", "if-none-match",
    "if-modified-since", "range", "sec-fetch-dest", "sec-fetch-mode",
    "sec-fetch-site",
})
SAFE_RESPONSE_HEADERS = frozenset({
    "accept-ranges", "access-control-allow-credentials", "access-control-allow-headers",
    "access-control-allow-methods", "access-control-allow-origin", "access-control-expose-headers",
    "cache-control", "content-disposition", "content-encoding", "content-language",
    "content-length", "content-range", "content-security-policy", "content-type",
    "etag", "expires", "last-modified", "location", "pragma", "referrer-policy",
    "set-cookie", "vary", "x-content-type-options",
})
FORBIDDEN_DOWNLOAD_SUFFIXES = frozenset({
    ".app", ".bat", ".bz2", ".class", ".cmd", ".com", ".dmg", ".dll", ".exe",
    ".gz", ".iso", ".jar", ".js", ".mjs", ".cjs", ".msi", ".ps1", ".rar",
    ".scr", ".sh", ".so", ".tar", ".vbs", ".zip", ".7z", ".desktop",
})
SENSITIVE_QUERY_NAMES = frozenset({
    "access_token", "api_key", "apikey", "auth", "authorization", "client_secret",
    "credential", "id_token", "key", "password", "passwd", "private_key",
    "refresh_token", "secret", "session", "signature", "sig", "token",
})


class BrowserOperationError(RuntimeError):
    """Stable, non-content error that can safely be returned to a Mission."""

    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


@dataclass
class _NetworkBudget:
    request_count: int = 0
    byte_count: int = 0


@dataclass
class _BrowserSession:
    session_id: str
    owner_identity: str
    owner_session_id: str
    mission_id: str
    scope_snapshot_id: str
    target_id: str
    context: Any
    page: Any
    current_context: ExecutionContext | None = None
    network_enabled: bool = True
    created_at: float = field(default_factory=time.monotonic)
    last_access: float = field(default_factory=time.monotonic)
    budget: _NetworkBudget = field(default_factory=_NetworkBudget)
    redirect_count: int = 0
    last_response_status: int | None = None
    last_block_code: str = ""


_URL_REDACTOR = re.compile(
    r"(?i)(?:bearer\s+|(?:api[_-]?key|access[_-]?token|refresh[_-]?token|id[_-]?token|"
    r"client[_-]?secret|private[_-]?key|password|passwd|secret|credential|signature|sig)"
    r"\s*[:=]\s*)[A-Za-z0-9_./+=-]{6,}"
)


def _scrub_text(value: str, limit: int = MAX_ITEM_CHARS) -> str:
    """Apply the existing strict specialist secret scrubber to untrusted text."""
    try:
        from agent.intelligence_layer.specialist_memory import redact_specialist_text
        value = redact_specialist_text(value)
    except Exception:
        value = _URL_REDACTOR.sub("[REDACTED]", value)
    return str(value)[:limit]


def _safe_url(url: str) -> str:
    """Return an origin/path citation without query, fragment, or secret-like values."""
    try:
        parts = urlsplit(url)
        host = parts.hostname or ""
        if ":" in host and not host.startswith("["):
            host = f"[{host}]"
        port = parts.port
        default = 443 if parts.scheme.casefold() == "https" else 80
        authority = host if port in (None, default) else f"{host}:{port}"
        path = _scrub_text(parts.path or "/", 800)
        return _scrub_text(urlunsplit((parts.scheme.casefold(), authority, path, "", "")), 1024)
    except (TypeError, ValueError):
        return "[invalid-url]"


def _url_digest(url: str) -> str:
    return sha256(url.encode("utf-8", errors="replace")).hexdigest()


def _validate_input_url(url: Any, *, test_local_origins: frozenset[str]) -> str:
    if not isinstance(url, str) or not url or len(url) > MAX_URL_CHARS or any(ord(ch) < 0x20 for ch in url):
        raise BrowserOperationError("url_invalid")
    try:
        parts = urlsplit(url)
        host = parts.hostname
        port = parts.port
    except ValueError as exc:
        raise BrowserOperationError("url_invalid") from exc
    scheme = parts.scheme.casefold()
    if scheme not in {"http", "https"} or not host or parts.username is not None or parts.password is not None:
        raise BrowserOperationError("url_authority_not_allowed")
    origin = f"{scheme}://{host.casefold()}:{port or (443 if scheme == 'https' else 80)}"
    if scheme != "https" and origin not in test_local_origins:
        raise BrowserOperationError("cleartext_http_not_allowed")
    for name, _value in __import__("urllib.parse", fromlist=["parse_qsl"]).parse_qsl(parts.query, keep_blank_values=True):
        if re.sub(r"[^a-z0-9_-]", "", name.casefold()) in SENSITIVE_QUERY_NAMES:
            raise BrowserOperationError("sensitive_query_parameter_not_allowed")
    try:
        from agent.intelligence_layer.specialist_memory import redact_specialist_text
        if redact_specialist_text(url) != url:
            raise BrowserOperationError("secret_like_url_not_allowed")
    except BrowserOperationError:
        raise
    except Exception:
        if _URL_REDACTOR.search(url):
            raise BrowserOperationError("secret_like_url_not_allowed")
    # Fragments are browser-local and never needed for the remote request.
    return urlunsplit((scheme, parts.netloc, parts.path or "/", parts.query, ""))


def _origin(url: str) -> str:
    parts = urlsplit(url)
    host = (parts.hostname or "").casefold()
    port = parts.port or (443 if parts.scheme.casefold() == "https" else 80)
    return f"{parts.scheme.casefold()}://{host}:{port}"


def _scrub_request_headers(headers: dict[str, str]) -> dict[str, str]:
    selected = {}
    for name, value in headers.items():
        key = str(name).casefold()
        if key not in SAFE_REQUEST_HEADERS:
            continue
        if key == "user-agent":
            selected["User-Agent"] = "CyberSentinel-ScopedBrowser/1.0"
        elif key == "cookie":
            # Cookies can only be those set by this isolated target-origin context.
            selected["Cookie"] = str(value)[:4096]
        elif key == "accept":
            selected["Accept"] = str(value)[:512]
        elif key == "accept-language":
            selected["Accept-Language"] = str(value)[:128]
        elif key == "range":
            selected["Range"] = str(value)[:128]
        elif key in {"if-none-match", "if-modified-since"}:
            selected["If-None-Match" if key == "if-none-match" else "If-Modified-Since"] = str(value)[:256]
        elif key.startswith("sec-fetch-"):
            selected[key] = str(value)[:64]
    selected.setdefault("User-Agent", "CyberSentinel-ScopedBrowser/1.0")
    selected.setdefault("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
    return selected


def _safe_response_headers(headers: dict[str, str], body: bytes, status: int) -> dict[str, str]:
    selected = {
        str(name).casefold(): str(value)[:8192]
        for name, value in headers.items()
        if str(name).casefold() in SAFE_RESPONSE_HEADERS
    }
    selected.pop("transfer-encoding", None)
    if status in {204, 304}:
        selected.pop("content-length", None)
    else:
        selected["content-length"] = str(len(body))
    return selected


def _append_evidence(context: ExecutionContext, action: str, details: dict[str, Any]) -> dict[str, Any]:
    context.assert_active()
    payload = {
        "claim": f"Scoped browser {action} observation captured",
        "source": f"browser:{action}",
        "evidence": {
            "record_type": "UNTRUSTED_BROWSER_OBSERVATION",
            "trust": "untrusted_data",
            "authority": "none",
            "scope_snapshot_id": str(context.scope_snapshot.get("scope_snapshot_id", "")),
            "target_id": str(context.scope_snapshot.get("target_id", "")),
            **details,
        },
        "verification": "observed",
        "confidence": 5,
        "request_id": context.request_id,
    }
    record = context.evidence_store.append(payload, execution_fence=context.execution_fence)
    return {
        "evidence_id": str(record.get("evidence_id", "")),
        "sequence": int(record.get("sequence", 0)),
        "current_hash": str(record.get("current_hash", "")),
    }


def _artifact(context: ExecutionContext, *, content: bytes, kind_name: str, filename: str, media_type: str,
              source_url: str, validation: Any) -> dict[str, Any]:
    if context.artifact_store is None:
        raise BrowserOperationError("mission_artifact_store_unavailable")
    if len(content) > MAX_ARTIFACT_BYTES:
        raise BrowserOperationError("artifact_size_limit_exceeded")
    from agent.intelligence_layer.artifacts import ArtifactKind, ArtifactSensitivity
    kind = ArtifactKind(kind_name)
    safe_name = _scrub_text(Path(filename).name, 200) or "browser-artifact"
    record = context.artifact_store.put(
        owner_identity_ref=context.owner_identity,
        mission_id=context.mission_id,
        task_id=str(context.execution_fence.task_id),
        kind=kind,
        content=content,
        filename=safe_name,
        media_type=media_type,
        sensitivity=ArtifactSensitivity.SENSITIVE,
        validation=validation,
        confidence=0.0,
        scope=(str(context.scope_snapshot.get("scope_snapshot_id", "")), str(context.scope_snapshot.get("target_id", ""))),
        provenance={
            "source": "scoped-browser",
            "tool_id": context.tool_id,
            "url_origin": _origin(source_url),
            "url_sha256": _url_digest(source_url),
            "scope_snapshot_id": str(context.scope_snapshot.get("scope_snapshot_id", "")),
            "execution_id": context.execution_id,
        },
        metadata={"trust": "untrusted_data", "authority": "none"},
    )
    return {
        "artifact_id": record.artifact_id,
        "sha256": record.content_sha256,
        "size_bytes": record.size_bytes,
        "kind": record.kind.value,
        "validation": record.validation.value,
    }


class BrowserService:
    """One serialized real Chromium runtime with mission-isolated in-memory sessions."""

    def __init__(self, *, test_local_origins: set[str] | frozenset[str] | None = None):
        # This constructor option exists only for local integration tests. The
        # production singleton is constructed without loopback exceptions.
        self._test_local_origins = frozenset(str(item).casefold() for item in (test_local_origins or set()))
        self._executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="cybersentinel-browser")
        self._playwright = None
        self._browser = None
        self._sessions: dict[str, _BrowserSession] = {}
        self._download_root: Path | None = None
        self._stopped = False
        self._lock = threading.Lock()

    def _configured_executable(self) -> str | None:
        if self._playwright is not None:
            bundled = str(self._playwright.chromium.executable_path)
            if Path(bundled).is_file():
                return bundled
        return None

    def _ensure_browser(self) -> None:
        if self._browser is not None and self._browser.is_connected():
            return
        # Chromium's OS sandbox is part of the isolation boundary for untrusted
        # page code. Refuse root execution rather than launching unsandboxed.
        if os.name != "nt" and hasattr(os, "geteuid") and os.geteuid() == 0:
            raise BrowserOperationError("chromium_sandbox_requires_unprivileged_user")
        try:
            from playwright.sync_api import sync_playwright
        except Exception as exc:
            raise BrowserOperationError("playwright_runtime_unavailable") from exc
        if self._playwright is None:
            self._playwright = sync_playwright().start()
        executable = self._configured_executable()
        if self._download_root is None:
            self._download_root = Path(tempfile.mkdtemp(prefix="cybersentinel-browser-downloads-"))
            try:
                os.chmod(self._download_root, 0o700)
            except OSError:
                pass
        args = [
            "--disable-background-networking",
            "--disable-component-update",
            "--disable-default-apps",
            "--disable-extensions",
            "--disable-sync",
            "--disable-features=MediaRouter,WebRtcHideLocalIpsWithMdns",
            "--force-webrtc-ip-handling-policy=disable_non_proxied_udp",
            "--js-flags=--max-old-space-size=128",
            # A dead proxy fails closed for any Chromium request that somehow
            # escapes Playwright routing. The Python transport is independent.
            "--proxy-server=http://127.0.0.1:9",
            "--proxy-bypass-list=<-loopback>",
        ]
        if os.name != "nt":
            args.append("--disable-dev-shm-usage")
        try:
            launch_options = {
                "headless": True,
                "chromium_sandbox": True,
                "downloads_path": str(self._download_root),
                "args": args,
            }
            if executable:
                launch_options["executable_path"] = executable
            self._browser = self._playwright.chromium.launch(**launch_options)
        except Exception as exc:
            self._stop_runtime()
            raise BrowserOperationError("chromium_launch_failed") from exc

    def _submit(self, callback, context: ExecutionContext, timeout: float = 24.0):
        with self._lock:
            if self._stopped:
                raise BrowserOperationError("browser_runtime_stopped")
            future = self._executor.submit(callback)
        try:
            return future.result(timeout=timeout)
        except FutureTimeout as exc:
            if context.cancellation_event is not None:
                context.cancellation_event.set()
            future.cancel()
            raise BrowserOperationError("browser_operation_timeout") from exc

    def _session_binding(self, context: ExecutionContext) -> tuple[str, str, str, str, str]:
        return (
            context.owner_identity,
            str(context.owner_session_id or ""),
            context.mission_id,
            str(context.scope_snapshot.get("scope_snapshot_id", "")),
            str(context.scope_snapshot.get("target_id", "")),
        )

    def _close_session(self, session: _BrowserSession) -> None:
        self._sessions.pop(session.session_id, None)
        try:
            if session.page is not None and not session.page.is_closed():
                session.page.close(run_before_unload=False)
        except Exception:
            pass
        try:
            session.context.close()
        except Exception:
            pass

    def _sweep(self) -> None:
        now = time.monotonic()
        for session in list(self._sessions.values()):
            if now - session.last_access > SESSION_TTL_SECONDS:
                self._close_session(session)

    def _new_session(self, context: ExecutionContext, session_id: str) -> _BrowserSession:
        self._ensure_browser()
        self._sweep()
        if len(self._sessions) >= MAX_SESSIONS:
            raise BrowserOperationError("browser_session_limit_reached")
        session_context = self._browser.new_context(
            accept_downloads=True,
            ignore_https_errors=False,
            service_workers="block",
        )
        session = _BrowserSession(
            session_id=session_id,
            owner_identity=context.owner_identity,
            owner_session_id=str(context.owner_session_id or ""),
            mission_id=context.mission_id,
            scope_snapshot_id=str(context.scope_snapshot.get("scope_snapshot_id", "")),
            target_id=str(context.scope_snapshot.get("target_id", "")),
            context=session_context,
            page=None,
            current_context=context,
        )
        session_context.route("**/*", lambda route: self._route(session, route))
        if hasattr(session_context, "route_web_socket"):
            session_context.route_web_socket(
                "**/*",
                lambda socket_route: socket_route.close(code=1008, reason="WebSocket is disabled by scoped browser policy"),
            )
        session.page = session_context.new_page()
        session.page.set_default_timeout(ACTION_TIMEOUT_MS)
        session.page.set_default_navigation_timeout(NAVIGATION_TIMEOUT_MS)
        session.page.on("dialog", lambda dialog: dialog.dismiss())
        self._sessions[session_id] = session
        return session

    def _get_session(self, context: ExecutionContext, session_id: str) -> _BrowserSession:
        if not isinstance(session_id, str) or not re.fullmatch(r"bs_[a-f0-9]{32}", session_id):
            raise BrowserOperationError("session_id_invalid")
        session = self._sessions.get(session_id)
        if session is None:
            raise BrowserOperationError("browser_session_not_found")
        if self._session_binding(context) != (
            session.owner_identity, session.owner_session_id, session.mission_id,
            session.scope_snapshot_id, session.target_id,
        ):
            raise BrowserOperationError("browser_session_scope_mismatch")
        try:
            current_url = self._assert_user_url(session.page.url)
            scope = context.scope_snapshot
            from security.scope_resolver import resolve
            decision = resolve(
                str(scope["scope_snapshot_id"]),
                str(scope["target_id"]),
                current_url,
                method="GET",
                expected_program_id=str(scope["program_id"]),
                consume_rate=False,
            )
            if not decision.allowed:
                raise BrowserOperationError("browser_session_scope_mismatch")
        except BrowserOperationError:
            self._close_session(session)
            raise
        except Exception as exc:
            self._close_session(session)
            raise BrowserOperationError("browser_session_scope_mismatch") from exc
        session.last_access = time.monotonic()
        session.current_context = context
        return session

    def _route(self, session: _BrowserSession, route: Any) -> None:
        request = route.request
        try:
            context = session.current_context
            if context is None or not session.network_enabled:
                session.last_block_code = "network_disabled"
                route.abort("blockedbyclient")
                return
            context.assert_active()
            method = str(request.method).upper()
            if method not in {"GET", "HEAD"} or request.post_data:
                session.last_block_code = "method_not_read_only"
                route.abort("blockedbyclient")
                return
            if request.resource_type not in {"document", "stylesheet", "script", "image", "font", "fetch", "xhr", "other"}:
                session.last_block_code = "resource_type_not_allowed"
                route.abort("blockedbyclient")
                return
            url = str(request.url)
            parts = urlsplit(url)
            if parts.scheme.casefold() not in {"https", "http"} or parts.username is not None or parts.password is not None:
                session.last_block_code = "scheme_not_allowed"
                route.abort("blockedbyclient")
                return
            from security.scope_resolver import resolve
            scope = context.scope_snapshot
            decision = resolve(
                str(scope["scope_snapshot_id"]),
                str(scope["target_id"]),
                url,
                method=method,
                expected_program_id=str(scope["program_id"]),
                consume_rate=True,
            )
            if not decision.allowed:
                session.last_block_code = "scope_denied"
                route.abort("blockedbyclient")
                return
            if session.budget.request_count >= MAX_SESSION_REQUESTS:
                session.last_block_code = "request_budget_exceeded"
                route.abort("blockedbyclient")
                return
            remaining = MAX_SESSION_NETWORK_BYTES - session.budget.byte_count
            if remaining <= 0:
                session.last_block_code = "session_byte_budget_exceeded"
                route.abort("blockedbyclient")
                return
            session.budget.request_count += 1
            from security.pinned_http import pinned_http_request
            response = pinned_http_request(
                url,
                method=method,
                headers=_scrub_request_headers(dict(request.all_headers())),
                timeout=4.0,
                max_response_bytes=min(MAX_RESPONSE_BYTES, remaining),
                allow_loopback=_origin(url) in self._test_local_origins,
                allow_redirect_response=True,
            )
            session.budget.byte_count += len(response.body)
            session.last_response_status = response.status
            if 300 <= response.status < 400:
                location = response.headers.get("location", "")
                if not location or session.redirect_count >= 10:
                    session.last_block_code = "redirect_limit_or_location_invalid"
                    route.abort("blockedbyclient")
                    return
                redirected_url = urljoin(url, location)
                try:
                    redirected_url = self._assert_user_url(redirected_url)
                except BrowserOperationError:
                    session.last_block_code = "redirect_destination_denied"
                    route.abort("blockedbyclient")
                    return
                redirected_scope = resolve(
                    str(scope["scope_snapshot_id"]),
                    str(scope["target_id"]),
                    redirected_url,
                    method="GET",
                    expected_program_id=str(scope["program_id"]),
                    consume_rate=True,
                )
                if not redirected_scope.allowed:
                    session.last_block_code = "redirect_destination_out_of_scope"
                    route.abort("blockedbyclient")
                    return
                session.redirect_count += 1
            context.assert_active()
            route.fulfill(
                status=response.status,
                headers=_safe_response_headers(response.headers, response.body, response.status),
                body=response.body,
            )
        except Exception as exc:
            session.last_block_code = getattr(exc, "code", "network_request_failed")
            try:
                route.abort("blockedbyclient")
            except Exception:
                pass

    def _assert_user_url(self, url: Any) -> str:
        normalized = _validate_input_url(url, test_local_origins=self._test_local_origins)
        return normalized

    def _append(self, context: ExecutionContext, action: str, details: dict[str, Any]) -> dict[str, Any]:
        return _append_evidence(context, action, details)

    def open(self, arguments: dict[str, Any], context: ExecutionContext) -> dict[str, Any]:
        url = self._assert_user_url(arguments.get("url"))
        requested_session = arguments.get("session_id")

        def command():
            context.assert_active()
            if requested_session:
                session = self._get_session(context, requested_session)
            else:
                session_id = "bs_" + uuid.uuid4().hex
                session = self._new_session(context, session_id)
            session.current_context = context
            session.network_enabled = True
            session.last_block_code = ""
            try:
                response = session.page.goto(url, wait_until="domcontentloaded", timeout=NAVIGATION_TIMEOUT_MS)
                context.assert_active()
                title = _scrub_text(session.page.title(), 250)
                text = _scrub_text(session.page.locator("body").inner_text(timeout=ACTION_TIMEOUT_MS), MAX_TEXT_CHARS)
                links = self._extract_links(session, limit=10)
                evidence = self._append(context, "open", {
                    "url_origin": _origin(url),
                    "url_sha256": _url_digest(url),
                    "http_status": int(response.status) if response is not None else session.last_response_status,
                    "title_sha256": sha256(title.encode("utf-8")).hexdigest(),
                    "text_sha256": sha256(text.encode("utf-8")).hexdigest(),
                    "text_chars": len(text),
                    "link_count": len(links),
                    "request_count": session.budget.request_count,
                    "response_bytes": session.budget.byte_count,
                    "browser_version": str(self._browser.version)[:40],
                })
                return {
                    "ok": True,
                    "session_id": session.session_id,
                    "url": _safe_url(session.page.url),
                    "title": title,
                    "text": text,
                    "links": links,
                    "trust": "untrusted_page_data",
                    "authority": "none",
                    "scope_enforced": True,
                    "network_transport": "dns_pinned",
                    "evidence_ref": evidence,
                }
            except Exception as exc:
                self._close_session(session)
                if isinstance(exc, BrowserOperationError):
                    raise
                raise BrowserOperationError("navigation_failed_or_out_of_scope") from exc

        return self._submit(command, context)

    def _extract_links(self, session: _BrowserSession, *, limit: int) -> list[dict[str, str]]:
        count = max(1, min(int(limit), MAX_LINKS))
        raw = session.page.locator("a[href]").evaluate_all(
            "(nodes, limit) => nodes.slice(0, limit).map(n => ({href: n.href || '', text: n.innerText || n.getAttribute('aria-label') || ''}))",
            count,
        )
        links: list[dict[str, str]] = []
        for item in raw:
            href = str(item.get("href", ""))
            if not href.startswith(("http://", "https://")):
                continue
            links.append({"url": _safe_url(href), "url_sha256": _url_digest(href), "text": _scrub_text(str(item.get("text", "")), 240)})
        return links

    def links(self, arguments: dict[str, Any], context: ExecutionContext) -> dict[str, Any]:
        limit = int(arguments.get("max_items", 20))

        def command():
            context.assert_active()
            session = self._get_session(context, arguments.get("session_id"))
            raw_links = self._extract_links(session, limit=limit)
            payload = json.dumps(raw_links, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
            from agent.intelligence_layer.artifacts import ArtifactValidation
            artifact = _artifact(
                context, content=payload, kind_name="extracted_data", filename="browser-links.json",
                media_type="application/json", source_url=session.page.url, validation=ArtifactValidation.UNVALIDATED,
            )
            evidence = self._append(context, "links", {
                "url_origin": _origin(session.page.url), "url_sha256": _url_digest(session.page.url),
                "link_count": len(raw_links), "artifact_id": artifact["artifact_id"],
                "artifact_sha256": artifact["sha256"],
            })
            return {"ok": True, "session_id": session.session_id, "links": raw_links,
                    "artifact_ref": artifact, "evidence_ref": evidence,
                    "trust": "untrusted_page_data", "authority": "none"}

        return self._submit(command, context)

    def extract(self, arguments: dict[str, Any], context: ExecutionContext) -> dict[str, Any]:
        selector = arguments.get("selector", "body")
        if not isinstance(selector, str) or not selector.strip() or len(selector) > MAX_SELECTOR_CHARS:
            raise BrowserOperationError("selector_invalid")
        limit = int(arguments.get("max_items", 10))
        max_chars = int(arguments.get("max_chars", MAX_TEXT_CHARS))

        def command():
            context.assert_active()
            session = self._get_session(context, arguments.get("session_id"))
            locators = session.page.locator(selector)
            count = min(locators.count(), max(1, min(limit, 20)))
            items = [_scrub_text(locators.nth(index).inner_text(timeout=ACTION_TIMEOUT_MS), min(max_chars, MAX_ITEM_CHARS)) for index in range(count)]
            encoded = json.dumps(items, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
            from agent.intelligence_layer.artifacts import ArtifactValidation
            artifact = _artifact(
                context, content=encoded, kind_name="extracted_data", filename="browser-extract.json",
                media_type="application/json", source_url=session.page.url, validation=ArtifactValidation.UNVALIDATED,
            )
            evidence = self._append(context, "extract", {
                "url_origin": _origin(session.page.url), "url_sha256": _url_digest(session.page.url),
                "selector_sha256": sha256(selector.encode("utf-8")).hexdigest(),
                "item_count": len(items), "artifact_id": artifact["artifact_id"],
                "artifact_sha256": artifact["sha256"],
            })
            return {"ok": True, "session_id": session.session_id, "items": items,
                    "artifact_ref": artifact, "evidence_ref": evidence,
                    "trust": "untrusted_page_data", "authority": "none"}

        return self._submit(command, context)

    def inspect(self, arguments: dict[str, Any], context: ExecutionContext) -> dict[str, Any]:
        selector = arguments.get("selector")
        if not isinstance(selector, str) or not selector.strip() or len(selector) > MAX_SELECTOR_CHARS:
            raise BrowserOperationError("selector_invalid")
        limit = int(arguments.get("max_items", 10))
        allowed_attributes = {"alt", "aria-label", "class", "href", "id", "name", "role", "title", "type"}
        requested = arguments.get("attributes", ["id", "name", "role", "type", "title", "aria-label", "href"])
        if not isinstance(requested, list) or any(not isinstance(name, str) or name not in allowed_attributes for name in requested):
            raise BrowserOperationError("dom_attribute_not_allowed")

        def command():
            context.assert_active()
            session = self._get_session(context, arguments.get("session_id"))
            raw = session.page.locator(selector).evaluate_all(
                "(nodes, cfg) => nodes.slice(0, cfg.limit).map(n => ({tag: n.tagName.toLowerCase(), text: (n.innerText || '').slice(0, cfg.textLimit), attributes: Object.fromEntries(cfg.attrs.filter(k => n.hasAttribute(k)).map(k => [k, n.getAttribute(k)]))}))",
                {"limit": max(1, min(limit, MAX_DOM_NODES)), "textLimit": MAX_ITEM_CHARS, "attrs": requested},
            )
            nodes = []
            for item in raw:
                attrs = {key: (_safe_url(value) if key == "href" and value.startswith(("http://", "https://")) else _scrub_text(value, 160))
                         for key, value in dict(item.get("attributes", {})).items()}
                nodes.append({"tag": str(item.get("tag", ""))[:32], "text": _scrub_text(str(item.get("text", "")), MAX_ITEM_CHARS), "attributes": attrs})
            encoded = json.dumps(nodes, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
            from agent.intelligence_layer.artifacts import ArtifactValidation
            artifact = _artifact(
                context, content=encoded, kind_name="extracted_data", filename="browser-dom-inspection.json",
                media_type="application/json", source_url=session.page.url, validation=ArtifactValidation.UNVALIDATED,
            )
            evidence = self._append(context, "inspect", {
                "url_origin": _origin(session.page.url), "url_sha256": _url_digest(session.page.url),
                "selector_sha256": sha256(selector.encode("utf-8")).hexdigest(),
                "node_count": len(nodes), "artifact_id": artifact["artifact_id"],
                "artifact_sha256": artifact["sha256"],
            })
            return {"ok": True, "session_id": session.session_id, "nodes": nodes,
                    "artifact_ref": artifact, "evidence_ref": evidence,
                    "trust": "untrusted_page_data", "authority": "none"}

        return self._submit(command, context)

    def screenshot(self, arguments: dict[str, Any], context: ExecutionContext) -> dict[str, Any]:
        def command():
            context.assert_active()
            session = self._get_session(context, arguments.get("session_id"))
            content = session.page.screenshot(type="png", full_page=False, animations="disabled", timeout=ACTION_TIMEOUT_MS)
            if len(content) > MAX_ARTIFACT_BYTES:
                raise BrowserOperationError("screenshot_size_limit_exceeded")
            from agent.intelligence_layer.artifacts import ArtifactValidation
            artifact = _artifact(
                context, content=content, kind_name="screenshot", filename="browser-screenshot.png",
                media_type="image/png", source_url=session.page.url, validation=ArtifactValidation.UNVALIDATED,
            )
            evidence = self._append(context, "screenshot", {
                "url_origin": _origin(session.page.url), "url_sha256": _url_digest(session.page.url),
                "artifact_id": artifact["artifact_id"], "artifact_sha256": artifact["sha256"],
                "size_bytes": len(content), "browser_version": str(self._browser.version)[:40],
            })
            return {"ok": True, "session_id": session.session_id, "artifact_ref": artifact,
                    "evidence_ref": evidence, "trust": "untrusted_page_data", "authority": "none"}

        return self._submit(command, context)

    def fill(self, arguments: dict[str, Any], context: ExecutionContext) -> dict[str, Any]:
        selector, value = arguments.get("selector"), arguments.get("value")
        if not isinstance(selector, str) or not selector.strip() or len(selector) > MAX_SELECTOR_CHARS:
            raise BrowserOperationError("selector_invalid")
        if not isinstance(value, str) or len(value) > MAX_FORM_VALUE_CHARS:
            raise BrowserOperationError("form_value_invalid")
        try:
            from agent.intelligence_layer.specialist_memory import redact_specialist_text
            if redact_specialist_text(value) != value:
                raise BrowserOperationError("secret_like_form_value_not_allowed")
        except BrowserOperationError:
            raise
        except Exception:
            if _URL_REDACTOR.search(value):
                raise BrowserOperationError("secret_like_form_value_not_allowed")

        def command():
            context.assert_active()
            session = self._get_session(context, arguments.get("session_id"))
            locator = session.page.locator(selector).first
            try:
                field = locator.evaluate("el => ({tag: el.tagName.toLowerCase(), type: (el.getAttribute('type') || 'text').toLowerCase(), name: (el.getAttribute('name') || '').toLowerCase(), autocomplete: (el.getAttribute('autocomplete') || '').toLowerCase(), id: (el.id || '').toLowerCase()})")
            except Exception as exc:
                raise BrowserOperationError("form_field_not_found") from exc
            denied_words = ("password", "passwd", "secret", "token", "credential", "auth", "credit", "card", "cvv", "cvc", "email", "phone", "address")
            if field["tag"] not in {"input", "textarea"} or field["type"] not in {"text", "search", "url", "number"}:
                raise BrowserOperationError("form_field_type_not_allowed")
            if any(word in " ".join((field["name"], field["autocomplete"], field["id"])) for word in denied_words):
                raise BrowserOperationError("sensitive_form_field_not_allowed")
            # No page-triggered request (even GET) is permitted while a caller
            # value is present. Do not submit, click, or retain the filled page.
            session.network_enabled = False
            try:
                locator.fill(value, timeout=ACTION_TIMEOUT_MS)
                context.assert_active()
                evidence = self._append(context, "fill", {
                    "url_origin": _origin(session.page.url), "url_sha256": _url_digest(session.page.url),
                    "selector_sha256": sha256(selector.encode("utf-8")).hexdigest(),
                    "field_type": field["type"], "value_chars": len(value),
                    "value_sha256": sha256(value.encode("utf-8")).hexdigest(),
                    "submission": "not_performed", "network_during_fill": "blocked",
                })
                return {"ok": True, "session_id": session.session_id, "filled": True,
                        "field_type": field["type"], "value_chars": len(value),
                        "submission": "not_performed", "network_during_fill": "blocked",
                        "session_closed": True, "evidence_ref": evidence,
                        "trust": "local_dom_interaction", "authority": "none"}
            finally:
                self._close_session(session)

        return self._submit(command, context)

    def download(self, arguments: dict[str, Any], context: ExecutionContext) -> dict[str, Any]:
        url = self._assert_user_url(arguments.get("url"))

        def command():
            context.assert_active()
            session = self._get_session(context, arguments.get("session_id"))
            session.current_context = context
            session.network_enabled = True
            try:
                with session.page.expect_download(timeout=NAVIGATION_TIMEOUT_MS) as download_info:
                    session.page.evaluate(
                        "url => { const a = document.createElement('a'); a.href = url; a.rel = 'noreferrer noopener'; document.body.appendChild(a); a.click(); a.remove(); }",
                        url,
                    )
                download = download_info.value
                filename = Path(str(download.suggested_filename or "download.bin")).name
                path = Path(download.path())
                if Path(filename).suffix.casefold() in FORBIDDEN_DOWNLOAD_SUFFIXES:
                    try:
                        path.unlink(missing_ok=True)
                    except OSError:
                        pass
                    raise BrowserOperationError("active_or_archive_download_not_allowed")
                if not path.is_file() or path.stat().st_size > MAX_ARTIFACT_BYTES:
                    try:
                        path.unlink(missing_ok=True)
                    except OSError:
                        pass
                    raise BrowserOperationError("download_size_limit_exceeded")
                content = path.read_bytes()
                if len(content) > MAX_ARTIFACT_BYTES:
                    try:
                        path.unlink(missing_ok=True)
                    except OSError:
                        pass
                    raise BrowserOperationError("download_size_limit_exceeded")
                media_type = mimetypes.guess_type(filename)[0] or "application/octet-stream"
                from agent.intelligence_layer.artifacts import ArtifactValidation
                artifact = _artifact(
                    context, content=content, kind_name="source", filename=filename,
                    media_type=media_type, source_url=url, validation=ArtifactValidation.UNVALIDATED,
                )
                evidence = self._append(context, "download", {
                    "url_origin": _origin(url), "url_sha256": _url_digest(url),
                    "artifact_id": artifact["artifact_id"], "artifact_sha256": artifact["sha256"],
                    "size_bytes": len(content), "media_type": media_type,
                    "validation": "unvalidated",
                })
                return {"ok": True, "session_id": session.session_id,
                        "filename": _scrub_text(filename, 200), "artifact_ref": artifact,
                        "evidence_ref": evidence, "trust": "untrusted_download",
                        "authority": "none", "execution": "never"}
            except BrowserOperationError:
                raise
            except Exception as exc:
                raise BrowserOperationError("download_failed_or_out_of_scope") from exc

        return self._submit(command, context)

    def close(self, arguments: dict[str, Any], context: ExecutionContext) -> dict[str, Any]:
        def command():
            context.assert_active()
            session = self._get_session(context, arguments.get("session_id"))
            url = str(session.page.url or "")
            self._close_session(session)
            evidence = self._append(context, "close", {
                "url_origin": _origin(url) if url else "",
                "url_sha256": _url_digest(url) if url else "",
                "session_state": "closed",
            })
            return {"ok": True, "closed": True, "evidence_ref": evidence, "authority": "none"}

        return self._submit(command, context)

    def _stop_runtime(self) -> None:
        for session in list(self._sessions.values()):
            self._close_session(session)
        if self._browser is not None:
            try:
                self._browser.close()
            except Exception:
                pass
            self._browser = None
        if self._playwright is not None:
            try:
                self._playwright.stop()
            except Exception:
                pass
            self._playwright = None
        if self._download_root is not None:
            shutil.rmtree(self._download_root, ignore_errors=True)
            self._download_root = None

    def shutdown(self) -> None:
        with self._lock:
            if self._stopped:
                return
            self._stopped = True
        stopped_cleanly = False
        try:
            self._executor.submit(self._stop_runtime).result(timeout=10)
            stopped_cleanly = True
        except Exception:
            pass
        self._executor.shutdown(wait=stopped_cleanly, cancel_futures=True)


_DEFAULT_SERVICE: BrowserService | None = None
_DEFAULT_LOCK = threading.Lock()


def get_browser_service() -> BrowserService:
    global _DEFAULT_SERVICE
    with _DEFAULT_LOCK:
        if _DEFAULT_SERVICE is None or _DEFAULT_SERVICE._stopped:
            _DEFAULT_SERVICE = BrowserService()
        return _DEFAULT_SERVICE


def shutdown_browser_service() -> None:
    global _DEFAULT_SERVICE
    with _DEFAULT_LOCK:
        service = _DEFAULT_SERVICE
        _DEFAULT_SERVICE = None
    if service is not None:
        service.shutdown()


def _handler(action: str, arguments: dict[str, Any], *, execution_context: ExecutionContext) -> dict[str, Any]:
    context = execution_context
    context.assert_active()
    service = get_browser_service()
    return getattr(service, action)(arguments, context)


def browser_open(arguments: dict[str, Any], *, execution_context: ExecutionContext) -> dict[str, Any]:
    return _handler("open", arguments, execution_context=execution_context)


def browser_extract(arguments: dict[str, Any], *, execution_context: ExecutionContext) -> dict[str, Any]:
    return _handler("extract", arguments, execution_context=execution_context)


def browser_links(arguments: dict[str, Any], *, execution_context: ExecutionContext) -> dict[str, Any]:
    return _handler("links", arguments, execution_context=execution_context)


def browser_inspect(arguments: dict[str, Any], *, execution_context: ExecutionContext) -> dict[str, Any]:
    return _handler("inspect", arguments, execution_context=execution_context)


def browser_screenshot(arguments: dict[str, Any], *, execution_context: ExecutionContext) -> dict[str, Any]:
    return _handler("screenshot", arguments, execution_context=execution_context)


def browser_fill(arguments: dict[str, Any], *, execution_context: ExecutionContext) -> dict[str, Any]:
    return _handler("fill", arguments, execution_context=execution_context)


def browser_read(arguments: dict[str, Any], *, execution_context: ExecutionContext) -> dict[str, Any]:
    """Compact Registry dispatch for separately validated read-only operations."""
    if not isinstance(arguments, dict):
        raise BrowserOperationError("browser_arguments_invalid")
    operation = arguments.get("operation")
    fields = {
        "open": ({"url", "session_id"}, {"url"}, "open"),
        "navigate": ({"url", "session_id"}, {"url", "session_id"}, "open"),
        "extract": ({"session_id", "selector", "max_items", "max_chars"}, {"session_id"}, "extract"),
        "links": ({"session_id", "max_items"}, {"session_id"}, "links"),
        "inspect": ({"session_id", "selector", "max_items", "attributes"}, {"session_id", "selector"}, "inspect"),
        "structured_extract": ({"session_id", "selector", "max_items", "attributes"}, {"session_id", "selector"}, "inspect"),
        "screenshot": ({"session_id"}, {"session_id"}, "screenshot"),
        "download": ({"session_id", "url"}, {"session_id", "url"}, "download"),
        "close": ({"session_id"}, {"session_id"}, "close"),
    }
    contract = fields.get(operation)
    if contract is None:
        raise BrowserOperationError("browser_operation_not_allowed")
    allowed, required, action = contract
    supplied = set(arguments) - {"operation"}
    if supplied - allowed or required - supplied:
        raise BrowserOperationError("browser_arguments_invalid")
    payload = {key: value for key, value in arguments.items() if key in allowed}
    return _handler(action, payload, execution_context=execution_context)


def browser_download(arguments: dict[str, Any], *, execution_context: ExecutionContext) -> dict[str, Any]:
    return _handler("download", arguments, execution_context=execution_context)


def browser_close(arguments: dict[str, Any], *, execution_context: ExecutionContext) -> dict[str, Any]:
    return _handler("close", arguments, execution_context=execution_context)


atexit.register(shutdown_browser_service)

__all__ = [
    "BrowserOperationError", "BrowserService", "browser_close", "browser_download",
    "browser_extract", "browser_fill", "browser_inspect", "browser_links",
    "browser_open", "browser_screenshot", "get_browser_service", "shutdown_browser_service",
]
