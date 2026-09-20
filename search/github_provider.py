"""
GitHub Search Provider

Read-only GitHub search provider for repositories, code, issues, and pull requests.
All results are UNTRUSTED_DATA.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
from datetime import datetime, timezone
from typing import Any

from .providers import (
    SearchProvider,
    SearchRequest,
    SearchResponse,
    SearchResult,
    SearchScope,
    ProviderStatus,
    ProviderCapability,
)
from .exceptions import (
    ProviderUnavailableError,
    AuthenticationError,
    RateLimitError,
    ProviderTimeoutError,
    InvalidRequestError,
    SSRFError,
    ParseError,
    NetworkError,
    ResponseTooLargeError,
)
from .ssrf import check_url_ssrf


class GitHubProvider(SearchProvider):
    """GitHub search provider with read-only capabilities.
    
    This provider searches:
    - Repositories
    - Code
    - Issues
    - Pull requests
    
    All results are UNTRUSTED_DATA.
    All operations are READ-ONLY in Phase 4.
    """
    
    name = "github"
    scope = SearchScope.GITHUB
    capabilities = frozenset({
        ProviderCapability.SEARCH,
        ProviderCapability.READ_ONLY,
    })
    
    # Configuration
    GITHUB_API_URL = "https://api.github.com"
    GITHUB_TOKEN_ENV = "GITHUB_TOKEN"
    
    # Limits
    max_results = 30  # GitHub API max per request
    max_response_bytes = 500000  # 500KB
    max_result_chars = 20000
    timeout = 15.0
    
    def __init__(self):
        """Initialize provider and check token availability."""
        self._token = self._get_token()
        self._session = None
        self._status = self._check_availability()
    
    def _get_token(self) -> str | None:
        """Get GitHub token from environment."""
        token = os.getenv(self.GITHUB_TOKEN_ENV, "").strip()
        if token:
            return token
        return None
    
    def _get_session(self) -> Any:
        """Get or create HTTP session with proper headers."""
        if self._session is None:
            try:
                import httpx
                headers = {
                    "Accept": "application/vnd.github+json",
                    "X-GitHub-Api-Version": "2022-11-28",
                }
                if self._token:
                    headers["Authorization"] = f"Bearer {self._token}"
                self._session = httpx.Client(
                    headers=headers,
                    timeout=self.timeout,
                    follow_redirects=False,
                )
            except ImportError:
                try:
                    import requests
                    from requests.adapters import HTTPAdapter
                    from urllib3.util.retry import Retry
                    
                    headers = {
                        "Accept": "application/vnd.github+json",
                        "X-GitHub-Api-Version": "2022-11-28",
                    }
                    if self._token:
                        headers["Authorization"] = f"Bearer {self._token}"
                    
                    retry = Retry(
                        total=3,
                        backoff_factor=0.5,
                        status_forcelist=[429, 500, 502, 503, 504],
                    )
                    adapter = HTTPAdapter(max_retries=retry)
                    self._session = requests.Session()
                    self._session.mount("https://", adapter)
                    self._session.mount("http://", adapter)
                    self._session.headers.update(headers)
                except ImportError:
                    raise ProviderUnavailableError(
                        "No HTTP library available (neither httpx nor requests)",
                        provider=self.name,
                    )
        return self._session
    
    def _check_availability(self) -> ProviderStatus:
        """Check if provider is available."""
        # Check if we have token
        if not self._token:
            # Can still do unauthenticated searches but with lower limits
            return ProviderStatus.AVAILABLE
        
        # Verify token is valid
        try:
            session = self._get_session()
            if hasattr(session, 'get'):
                # httpx or requests
                response = session.get(
                    f"{self.GITHUB_API_URL}/user",
                    timeout=5.0,
                )
                if response.status_code == 401:
                    return ProviderStatus.NOT_CONFIGURED
                elif response.status_code == 403:
                    # Check rate limit
                    rate_limit_remaining = int(
                        response.headers.get("X-RateLimit-Remaining", 0)
                    )
                    if rate_limit_remaining == 0:
                        return ProviderStatus.RATE_LIMITED
                    return ProviderStatus.AVAILABLE
                elif response.status_code == 200:
                    return ProviderStatus.CONFIGURED
            return ProviderStatus.UNAVAILABLE
        except Exception as e:
            # Network error or other issue
            return ProviderStatus.UNAVAILABLE
    
    def check_availability(self) -> ProviderStatus:
        """Check if provider is available."""
        self._status = self._check_availability()
        return self._status
    
    def _make_api_request(
        self,
        endpoint: str,
        params: dict[str, Any] | None = None,
        method: str = "GET",
    ) -> tuple[dict[str, Any], int, dict[str, str]]:
        """Make a request to GitHub API.
        
        Returns:
            tuple of (response_data, status_code, headers)
        """
        import httpx
        import requests
        
        url = f"{self.GITHUB_API_URL}{endpoint}"
        
        # Validate URL for SSRF
        check_url_ssrf(url, raise_on_block=True)
        
        session = self._get_session()
        
        try:
            if isinstance(session, httpx.Client):
                response = session.request(
                    method,
                    url,
                    params=params,
                    timeout=self.timeout,
                )
                status_code = response.status_code
                headers = dict(response.headers)
                response_data = response.json()
            elif isinstance(session, requests.Session):
                response = session.request(
                    method,
                    url,
                    params=params,
                    timeout=self.timeout,
                )
                status_code = response.status_code
                headers = dict(response.headers)
                response_data = response.json()
            else:
                raise ProviderUnavailableError(
                    "No valid HTTP session",
                    provider=self.name,
                )
        except Exception as e:
            if isinstance(e, httpx.TimeoutException) or isinstance(e, requests.exceptions.Timeout):
                raise ProviderTimeoutError(
                    f"GitHub API request timed out: {e}",
                    provider=self.name,
                )
            elif isinstance(e, httpx.ConnectError) or isinstance(e, requests.exceptions.ConnectionError):
                raise NetworkError(
                    f"Failed to connect to GitHub API: {e}",
                    provider=self.name,
                )
            else:
                raise NetworkError(
                    f"GitHub API request failed: {e}",
                    provider=self.name,
                )
        
        return response_data, status_code, headers
    
    def _handle_rate_limit(self, headers: dict[str, str]) -> None:
        """Check and handle rate limiting."""
        rate_limit_remaining = int(headers.get("X-RateLimit-Remaining", 0))
        rate_limit_reset = int(headers.get("X-RateLimit-Reset", 0))
        
        if rate_limit_remaining == 0:
            raise RateLimitError(
                f"GitHub rate limit exceeded. Reset at {datetime.fromtimestamp(rate_limit_reset)}",
                provider=self.name,
            )
    
    def _search_repositories(
        self,
        query: str,
        max_results: int,
    ) -> list[SearchResult]:
        """Search GitHub repositories."""
        results = []
        per_page = min(max_results, 100)  # GitHub max per page
        
        endpoint = "/search/repositories"
        params = {
            "q": query,
            "per_page": per_page,
            "sort": "relevance",
        }
        
        response_data, status_code, headers = self._make_api_request(
            endpoint,
            params=params,
        )
        
        self._handle_rate_limit(headers)
        
        if status_code == 401:
            raise AuthenticationError(
                "GitHub authentication failed",
                provider=self.name,
            )
        elif status_code == 403:
            raise RateLimitError(
                "GitHub rate limit exceeded",
                provider=self.name,
            )
        elif status_code != 200:
            raise ProviderError(
                f"GitHub API returned status {status_code}",
                provider=self.name,
            )
        
        items = response_data.get("items", [])
        for repo in items[:max_results]:
            result = self._normalize_repository(repo)
            if result:
                results.append(result)
        
        return results
    
    def _search_code(
        self,
        query: str,
        max_results: int,
    ) -> list[SearchResult]:
        """Search GitHub code."""
        results = []
        per_page = min(max_results, 100)
        
        endpoint = "/search/code"
        params = {
            "q": query,
            "per_page": per_page,
            "sort": "relevance",
        }
        
        response_data, status_code, headers = self._make_api_request(
            endpoint,
            params=params,
        )
        
        self._handle_rate_limit(headers)
        
        if status_code == 401:
            raise AuthenticationError(
                "GitHub authentication failed",
                provider=self.name,
            )
        elif status_code == 403:
            raise RateLimitError(
                "GitHub rate limit exceeded",
                provider=self.name,
            )
        elif status_code != 200:
            raise ProviderError(
                f"GitHub API returned status {status_code}",
                provider=self.name,
            )
        
        items = response_data.get("items", [])
        for code_result in items[:max_results]:
            result = self._normalize_code(code_result)
            if result:
                results.append(result)
        
        return results
    
    def _search_issues_and_prs(
        self,
        query: str,
        max_results: int,
    ) -> list[SearchResult]:
        """Search GitHub issues and pull requests."""
        results = []
        per_page = min(max_results, 100)
        
        endpoint = "/search/issues"
        params = {
            "q": query,
            "per_page": per_page,
            "sort": "relevance",
        }
        
        response_data, status_code, headers = self._make_api_request(
            endpoint,
            params=params,
        )
        
        self._handle_rate_limit(headers)
        
        if status_code == 401:
            raise AuthenticationError(
                "GitHub authentication failed",
                provider=self.name,
            )
        elif status_code == 403:
            raise RateLimitError(
                "GitHub rate limit exceeded",
                provider=self.name,
            )
        elif status_code != 200:
            raise ProviderError(
                f"GitHub API returned status {status_code}",
                provider=self.name,
            )
        
        items = response_data.get("items", [])
        for issue in items[:max_results]:
            result = self._normalize_issue(issue)
            if result:
                results.append(result)
        
        return results
    
    def _normalize_repository(self, repo: dict[str, Any]) -> SearchResult | None:
        """Normalize a GitHub repository into SearchResult."""
        try:
            title = repo.get("full_name", "")
            description = repo.get("description", "")
            html_url = repo.get("html_url", "")
            
            content = f"{title}\n{description}"
            content = self.truncate_result(content)
            content = self.sanitize_content(content)
            
            # Calculate hash
            content_bytes = content.encode('utf-8')
            content_hash = hashlib.sha256(content_bytes).hexdigest()
            
            return SearchResult(
                result_id=f"github:repo:{repo.get('id', '')}",
                title=title or "Untitled Repository",
                content=content,
                source="github",
                source_type="repository",
                url=html_url,
                provenance={
                    "source": "github",
                    "type": "repository",
                    "provider": self.name,
                },
                metadata={
                    "repo_id": repo.get("id"),
                    "full_name": repo.get("full_name"),
                    "private": repo.get("private", False),
                    "fork": repo.get("fork", False),
                    "stargazers_count": repo.get("stargazers_count", 0),
                    "open_issues_count": repo.get("open_issues_count", 0),
                    "language": repo.get("language"),
                    "created_at": repo.get("created_at"),
                    "updated_at": repo.get("updated_at"),
                    "content_hash": content_hash,
                },
            )
        except Exception:
            return None
    
    def _normalize_code(self, code: dict[str, Any]) -> SearchResult | None:
        """Normalize a GitHub code search result into SearchResult."""
        try:
            repo_name = code.get("repository", {}).get("full_name", "")
            path = code.get("path", "")
            html_url = code.get("html_url", "")
            
            # Truncate content to avoid huge files
            raw_content = code.get("content", "") or ""
            content = self.truncate_result(raw_content[:10000])
            content = self.sanitize_content(content)
            
            # Calculate hash
            content_bytes = content.encode('utf-8')
            content_hash = hashlib.sha256(content_bytes).hexdigest()
            
            return SearchResult(
                result_id=f"github:code:{code.get('sha', '')}",
                title=f"{repo_name}:{path}" if repo_name and path else "Untitled Code",
                content=content,
                source="github",
                source_type="code",
                url=html_url,
                provenance={
                    "source": "github",
                    "type": "code",
                    "provider": self.name,
                },
                metadata={
                    "repo_name": repo_name,
                    "path": path,
                    "sha": code.get("sha"),
                    "html_url": html_url,
                    "content_hash": content_hash,
                },
            )
        except Exception:
            return None
    
    def _normalize_issue(self, issue: dict[str, Any]) -> SearchResult | None:
        """Normalize a GitHub issue/PR into SearchResult."""
        try:
            title = issue.get("title", "")
            body = issue.get("body", "")
            html_url = issue.get("html_url", "")
            repo_name = issue.get("repository", {}).get("full_name", "")
            
            content = f"{title}\n\n{body}"
            content = self.truncate_result(content)
            content = self.sanitize_content(content)
            
            # Calculate hash
            content_bytes = content.encode('utf-8')
            content_hash = hashlib.sha256(content_bytes).hexdigest()
            
            is_pr = issue.get("pull_request", {}).get("html_url") is not None
            item_type = "pull_request" if is_pr else "issue"
            
            return SearchResult(
                result_id=f"github:{item_type}:{issue.get('id', '')}",
                title=title or f"Untitled {item_type}",
                content=content,
                source="github",
                source_type=item_type,
                url=html_url,
                provenance={
                    "source": "github",
                    "type": item_type,
                    "provider": self.name,
                },
                metadata={
                    "repo_name": repo_name,
                    "issue_number": issue.get("number"),
                    "state": issue.get("state"),
                    "locked": issue.get("locked", False),
                    "comments": issue.get("comments", 0),
                    "created_at": issue.get("created_at"),
                    "updated_at": issue.get("updated_at"),
                    "is_pr": is_pr,
                    "content_hash": content_hash,
                },
            )
        except Exception:
            return None
    
    def search(self, request: SearchRequest) -> SearchResponse:
        """Execute a GitHub search request.
        
        Supports searching:
        - Repositories
        - Code
        - Issues and pull requests
        
        Query format: "type:repo <query>" or "type:code <query>" or "type:issue <query>"
        Default: repositories
        """
        # Validate scope
        if request.scope and request.scope != SearchScope.GITHUB:
            raise InvalidRequestError(
                f"GitHub provider only supports GITHUB scope, got {request.scope}",
                provider=self.name,
            )
        
        # Check availability
        self.check_availability()
        if self._status in (ProviderStatus.UNAVAILABLE, ProviderStatus.NOT_CONFIGURED):
            raise ProviderUnavailableError(
                f"GitHub provider is {self._status.value}",
                provider=self.name,
            )
        
        # Parse query type
        query = request.query.strip()
        search_type = "repo"  # default
        
        # Check for type prefix
        type_match = re.match(r'^type:(\w+)\s+(.*)', query, re.IGNORECASE)
        if type_match:
            search_type = type_match.group(1).lower()
            query = type_match.group(2)
        
        # Build GitHub search query
        github_query = query
        
        # Execute search based on type
        try:
            if search_type in ("repo", "repository", "repositories"):
                results = self._search_repositories(github_query, request.max_results)
            elif search_type in ("code",):
                results = self._search_code(github_query, request.max_results)
            elif search_type in ("issue", "issues", "pr", "pull", "pull_request", "pullrequests"):
                results = self._search_issues_and_prs(github_query, request.max_results)
            else:
                # Default to repositories
                results = self._search_repositories(github_query, request.max_results)
        except AuthenticationError:
            raise
        except RateLimitError:
            raise
        except ProviderTimeoutError:
            raise
        except Exception as e:
            return SearchResponse(
                request=request,
                results=[],
                total_results=0,
                provider=self.name,
                error=str(e),
                error_type="provider_error",
                metadata={"status": self._status.value},
            )
        
        return SearchResponse(
            request=request,
            results=results[:request.max_results],
            total_results=len(results),
            provider=self.name,
            metadata={
                "search_type": search_type,
                "query": github_query,
                "status": self._status.value,
            },
        )


# Provider error for compatibility
class ProviderError(Exception):
    """Generic provider error."""
    def __init__(self, message: str, provider: str | None = None):
        super().__init__(message)
        self.message = message
        self.provider = provider
