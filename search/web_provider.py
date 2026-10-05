"""Read-only public-web search using a bounded DNS-pinned transport.

Search results and snippets are untrusted data. The provider never fetches result
URLs, follows redirects, or treats remote content as authorization or policy.
"""
from __future__ import annotations

import hashlib
import re
from html.parser import HTMLParser
from urllib.parse import parse_qs, urljoin, urlsplit

from security.pinned_http import PinnedRequestError, PinnedSession

from .exceptions import (
    InvalidRequestError,
    NetworkError,
    ParseError,
    ParseError,
    ProviderError,
    ProviderTimeoutError,
    ProviderUnavailableError,
    RateLimitError,
    ResponseTooLargeError,
    SSRFError,
)
from .providers import (
    ProviderCapability,
    ProviderStatus,
    SearchProvider,
    SearchRequest,
    SearchResponse,
    SearchResult,
    SearchScope,
)


class _SearchResultsParser(HTMLParser):
    """Extract only DuckDuckGo result titles, links, and snippets as plain text."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.titles: list[tuple[str, str]] = []
        self.snippets: list[str] = []
        self._title: dict[str, object] | None = None
        self._snippet: dict[str, object] | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        values = dict(attrs)
        classes = set((values.get("class") or "").split())
        if tag == "a" and "result__a" in classes:
            self._title = {"href": values.get("href") or "", "parts": []}
        if "result__snippet" in classes:
            self._snippet = {"tag": tag, "parts": []}

    def handle_data(self, data: str) -> None:
        if self._title is not None:
            self._title["parts"].append(data)
        elif self._snippet is not None:
            self._snippet["parts"].append(data)

    @staticmethod
    def _clean(parts: list[str]) -> str:
        return re.sub(r"\s+", " ", " ".join(parts)).strip()

    def handle_endtag(self, tag: str) -> None:
        if self._title is not None and tag == "a":
            self.titles.append((str(self._title["href"]), self._clean(self._title["parts"])))
            self._title = None
        if self._snippet is not None and tag == self._snippet["tag"]:
            self.snippets.append(self._clean(self._snippet["parts"]))
            self._snippet = None


class WebSearchProvider(SearchProvider):
    """Anonymous, read-only web search through DuckDuckGo's HTML interface.

    Availability reports whether the local pinned HTTP transport is configured;
    it deliberately does not make an outbound probe. Endpoint reachability is
    established only by an actual bounded search request.
    """

    name = "web"
    scope = SearchScope.WEB
    capabilities = frozenset({ProviderCapability.SEARCH, ProviderCapability.READ_ONLY})

    ENDPOINT = "https://html.duckduckgo.com/html/"
    max_results = 10
    max_response_bytes = 100_000
    max_result_chars = 4_000
    timeout = 15.0
    max_query_chars = 512
    status = ProviderStatus.IMPLEMENTED

    def __init__(self, *, session: PinnedSession | None = None) -> None:
        self._session = session or PinnedSession(
            headers={
                "Accept": "text/html,application/xhtml+xml",
                "Accept-Language": "en-US,en;q=0.8",
                "User-Agent": "CyberSentinel-X/1.0 (read-only web research)",
            },
            timeout=self.timeout,
            max_response_bytes=self.max_response_bytes,
        )
        self._status = ProviderStatus.IMPLEMENTED
        self.status = self._status

    def check_availability(self) -> ProviderStatus:
        """Report local transport availability without making a network probe."""
        return self._status

    @staticmethod
    def _safe_result_url(href: str) -> str | None:
        url = urljoin(WebSearchProvider.ENDPOINT, href.strip())
        parsed = urlsplit(url)
        if (
            parsed.scheme.casefold() not in {"http", "https"}
            or not parsed.hostname
            or parsed.username is not None
            or parsed.password is not None
            or len(url) > 4096
            or any(ord(char) < 0x20 for char in url)
        ):
            return None
        if parsed.hostname.casefold() in {"duckduckgo.com", "www.duckduckgo.com"} and parsed.path == "/l/":
            destination = parse_qs(parsed.query, keep_blank_values=False).get("uddg", [""])[0]
            if not destination:
                return None
            url = destination
            parsed = urlsplit(url)
            if (
                parsed.scheme.casefold() not in {"http", "https"}
                or not parsed.hostname
                or parsed.username is not None
                or parsed.password is not None
                or len(url) > 4096
            ):
                return None
        return url

    def _parse_results(self, body: bytes, query: str, limit: int) -> list[SearchResult]:
        try:
            html = body.decode("utf-8", errors="strict")
        except UnicodeDecodeError as exc:
            raise ParseError("Web search response is not valid UTF-8", provider=self.name) from exc
        parser = _SearchResultsParser()
        try:
            parser.feed(html)
            parser.close()
        except Exception as exc:
            raise ParseError("Web search response could not be parsed", provider=self.name) from exc

        query_hash = hashlib.sha256(query.encode("utf-8")).hexdigest()
        results: list[SearchResult] = []
        for index, (href, title) in enumerate(parser.titles):
            url = self._safe_result_url(href)
            title = self.sanitize_content(re.sub(r"\s+", " ", title).strip())
            snippet = parser.snippets[index].strip() if index < len(parser.snippets) else ""
            if not url or not title:
                continue
            prefix = "[UNTRUSTED_WEB_RESULT] "
            text_limit = max(0, self.max_result_chars - len(prefix))
            text = self.sanitize_content(snippet)
            if len(text) > text_limit:
                marker = "...[TRUNCATED]"
                text = text[: max(0, text_limit - len(marker))] + marker[:text_limit]
            text = prefix + text
            digest = hashlib.sha256((title + "\n" + text).encode("utf-8")).hexdigest()
            url_id = hashlib.sha256(url.encode("utf-8")).hexdigest()[:24]
            results.append(SearchResult(
                result_id=f"web:duckduckgo:{url_id}",
                title=title[:512],
                content=text,
                source="web",
                source_type="web_search_result",
                url=url,
                content_hash=digest,
                provenance={
                    "source": "web",
                    "provider": self.name,
                    "backend": "duckduckgo_html",
                    "trust": "untrusted_data",
                    "query_sha256": query_hash,
                    "retrieved_at_source": "search_response",
                },
                metadata={
                    "query_sha256": query_hash,
                    "result_index": index,
                    "content_sha256": digest,
                },
            ))
            if len(results) >= limit:
                break
        return results

    def search(self, request: SearchRequest) -> SearchResponse:
        if request.scope is not None and request.scope is not SearchScope.WEB:
            raise InvalidRequestError(
                f"Web provider only supports WEB scope, got {request.scope}", provider=self.name
            )
        if not isinstance(request.query, str):
            raise InvalidRequestError("Query must be text", provider=self.name)
        query = request.query.strip()
        if not query:
            raise InvalidRequestError("Query must not be empty", provider=self.name)
        if len(query) > self.max_query_chars:
            raise InvalidRequestError("Query exceeds the web search length limit", provider=self.name)
        if not isinstance(request.max_results, int) or isinstance(request.max_results, bool) or request.max_results < 1:
            raise InvalidRequestError("Result limit must be a positive integer", provider=self.name)

        limit = min(request.max_results, self.max_results)
        timeout = min(float(request.timeout), self.timeout)
        try:
            response = self._session.get(
                self.ENDPOINT,
                params={"q": query, "kl": "us-en"},
                timeout=timeout,
            )
        except PinnedRequestError as exc:
            message = str(exc).casefold()
            if "response exceeds" in message:
                raise ResponseTooLargeError("Web search response exceeds the configured size limit", provider=self.name) from exc
            if "timed out" in message or "timeout" in message:
                raise ProviderTimeoutError("Web search request timed out", provider=self.name) from exc
            raise SSRFError("Web search request was rejected by the pinned network policy", provider=self.name) from exc
        except TimeoutError as exc:
            raise ProviderTimeoutError("Web search request timed out", provider=self.name) from exc
        except Exception as exc:
            raise NetworkError("Web search request failed", provider=self.name) from exc

        status = int(response.status_code)
        if status == 202:
            raise ProviderUnavailableError(
                "Web search endpoint returned an anti-automation response",
                provider=self.name,
            )
        if status == 429:
            raise RateLimitError("Web search provider rate limited the request", provider=self.name)
        if status >= 500:
            raise ProviderError(f"Web search provider returned HTTP {status}", provider=self.name)
        if status != 200:
            raise ProviderError(f"Web search provider returned HTTP {status}", provider=self.name)
        content_type = str(response.headers.get("content-type", "")).casefold()
        if "text/html" not in content_type and "application/xhtml+xml" not in content_type:
            raise ParseError("Web search provider returned an unexpected content type", provider=self.name)
        body = response.body
        if not isinstance(body, bytes):
            raise ParseError("Web search response body is not bytes", provider=self.name)
        if len(body) > self.max_response_bytes:
            raise ResponseTooLargeError("Web search response exceeds the configured size limit", provider=self.name)

        results = self._parse_results(body, query, limit)
        return SearchResponse(
            request=request,
            results=results,
            total_results=len(results),
            provider=self.name,
            metadata={
                "backend": "duckduckgo_html",
                "response_bytes": len(body),
                "query_sha256": hashlib.sha256(query.encode("utf-8")).hexdigest(),
                "trust": "untrusted_data",
                "remote_fetch_performed": False,
            },
        )


class WebSearchProviderUnavailable(WebSearchProvider):
    """Deprecated compatibility name; use :class:`WebSearchProvider` directly."""
