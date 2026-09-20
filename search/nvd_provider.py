"""
NVD/CVE Search Provider

Read-only NVD/CVE search provider for vulnerability data.
All results are UNTRUSTED_DATA.
"""

from __future__ import annotations

import hashlib
import json
import os
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
    ProviderTimeoutError,
    RateLimitError,
    InvalidRequestError,
    ParseError,
    NetworkError,
    ResponseTooLargeError,
)
from .ssrf import check_url_ssrf
from core.config import NVD_CVE_API


class NVDProvider(SearchProvider):
    """NVD/CVE search provider with read-only capabilities.
    
    This provider searches the NVD API for CVE information.
    All results are UNTRUSTED_DATA.
    All operations are READ-ONLY in Phase 4.
    """
    
    name = "nvd"
    scope = SearchScope.NVD
    capabilities = frozenset({
        ProviderCapability.SEARCH,
        ProviderCapability.GET_BY_ID,
        ProviderCapability.READ_ONLY,
    })
    
    # Configuration
    NVD_API_URL = NVD_CVE_API
    
    # Limits
    max_results = 50  # NVD API max per request
    max_response_bytes = 2000000  # 2MB
    max_result_chars = 50000
    timeout = 30.0
    
    def __init__(self):
        """Initialize provider."""
        self._session = None
        self._status = self._check_availability()
    
    def _get_session(self) -> Any:
        """Get or create HTTP session with proper headers."""
        if self._session is None:
            try:
                import httpx
                headers = {
                    "Accept": "application/json",
                }
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
                        "Accept": "application/json",
                    }
                    
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
        # NVD API is always available (public API)
        # But we should check if we can reach it
        try:
            session = self._get_session()
            if hasattr(session, 'get'):
                import httpx
                import requests
                
                # Try a simple HEAD request to check API availability
                if isinstance(session, httpx.Client):
                    response = session.head(
                        self.NVD_API_URL,
                        timeout=5.0,
                    )
                elif isinstance(session, requests.Session):
                    response = session.head(
                        self.NVD_API_URL,
                        timeout=5.0,
                    )
                else:
                    return ProviderStatus.UNAVAILABLE
                
                # NVD may return 403 if rate limited, but that means it's available
                if response.status_code in (200, 403, 400):
                    return ProviderStatus.AVAILABLE
                return ProviderStatus.UNAVAILABLE
        except Exception:
            # Network error - API might be down
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
        """Make a request to NVD API.
        
        Returns:
            tuple of (response_data, status_code, headers)
        """
        import httpx
        import requests
        
        url = f"{self.NVD_API_URL}{endpoint}"
        
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
                    f"NVD API request timed out: {e}",
                    provider=self.name,
                )
            elif isinstance(e, httpx.ConnectError) or isinstance(e, requests.exceptions.ConnectionError):
                raise NetworkError(
                    f"Failed to connect to NVD API: {e}",
                    provider=self.name,
                )
            else:
                raise NetworkError(
                    f"NVD API request failed: {e}",
                    provider=self.name,
                )
        
        return response_data, status_code, headers
    
    def _handle_rate_limit(self, headers: dict[str, str]) -> None:
        """Check and handle rate limiting."""
        # NVD uses different rate limit headers
        rate_limit_remaining = headers.get("X-RateLimit-Remaining")
        rate_limit_reset = headers.get("X-RateLimit-Reset")
        
        # Check for NVD-specific rate limit headers
        if "RateLimit-Remaining" in headers:
            rate_limit_remaining = headers.get("RateLimit-Remaining")
        
        if rate_limit_remaining and int(rate_limit_remaining) == 0:
            raise RateLimitError(
                "NVD rate limit exceeded",
                provider=self.name,
            )
    
    def _search_by_cve_id(
        self,
        cve_id: str,
    ) -> list[SearchResult]:
        """Search for a specific CVE by ID."""
        results = []
        
        endpoint = f"/cves/{cve_id}"
        
        response_data, status_code, headers = self._make_api_request(
            endpoint,
            params={"includeVulnerability": "true"},
        )
        
        self._handle_rate_limit(headers)
        
        if status_code == 404:
            # CVE not found
            return []
        elif status_code == 403:
            raise RateLimitError(
                "NVD rate limit exceeded",
                provider=self.name,
            )
        elif status_code != 200:
            raise ParseError(
                f"NVD API returned status {status_code}",
                provider=self.name,
            )
        
        # Parse response
        cve_data = response_data.get("vulnerabilities", [])
        for vuln in cve_data:
            result = self._normalize_cve(vuln.get("cve", {}))
            if result:
                results.append(result)
        
        return results
    
    def _search_cves(
        self,
        query: str,
        max_results: int,
    ) -> list[SearchResult]:
        """Search CVEs by keyword."""
        results = []
        
        # Build search parameters
        # NVD API supports keyword search
        params = {
            "keywordSearch": query,
            "resultsPerPage": min(max_results, 2000),  # NVD max
        }
        
        endpoint = ""
        
        response_data, status_code, headers = self._make_api_request(
            endpoint,
            params=params,
        )
        
        self._handle_rate_limit(headers)
        
        if status_code == 403:
            raise RateLimitError(
                "NVD rate limit exceeded",
                provider=self.name,
            )
        elif status_code != 200:
            raise ParseError(
                f"NVD API returned status {status_code}",
                provider=self.name,
            )
        
        # Parse response
        cve_items = response_data.get("vulnerabilities", [])
        for item in cve_items[:max_results]:
            cve = item.get("cve", {})
            result = self._normalize_cve(cve)
            if result:
                results.append(result)
        
        return results
    
    def _normalize_cve(self, cve: dict[str, Any]) -> SearchResult | None:
        """Normalize a CVE into SearchResult."""
        try:
            cve_id = cve.get("id", "")
            if not cve_id:
                return None
            
            # Extract description
            descriptions = cve.get("descriptions", [])
            description = ""
            if descriptions:
                # Prefer English description
                for desc in descriptions:
                    if desc.get("lang") == "en":
                        description = desc.get("value", "")
                        break
                else:
                    description = descriptions[0].get("value", "")
            
            # Extract published and last modified dates
            published = cve.get("published", "")
            last_modified = cve.get("lastModified", "")
            
            # Extract CVSS scores
            metrics = cve.get("metrics", {})
            cvss_scores = self._extract_cvss_scores(metrics)
            
            # Extract references
            references = cve.get("references", [])
            ref_urls = [ref.get("url", "") for ref in references[:5]]
            
            # Build content
            content = f"CVE ID: {cve_id}\n\n"
            content += f"Description: {description}\n\n"
            content += f"Published: {published}\n"
            content += f"Last Modified: {last_modified}\n\n"
            
            if cvss_scores:
                content += "CVSS Scores:\n"
                for version, score in cvss_scores.items():
                    content += f"  {version}: {score}\n"
                content += "\n"
            
            if ref_urls:
                content += "References:\n"
                for url in ref_urls:
                    content += f"  - {url}\n"
            
            content = self.truncate_result(content)
            content = self.sanitize_content(content)
            
            # Calculate hash
            content_bytes = content.encode('utf-8')
            content_hash = hashlib.sha256(content_bytes).hexdigest()
            
            return SearchResult(
                result_id=f"nvd:cve:{cve_id}",
                title=f"CVE-{cve_id}" if cve_id.startswith("CVE-") else cve_id,
                content=content,
                source="nvd",
                source_type="cve",
                url=f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                provenance={
                    "source": "nvd",
                    "type": "cve",
                    "provider": self.name,
                },
                metadata={
                    "cve_id": cve_id,
                    "published": published,
                    "last_modified": last_modified,
                    "cvss_scores": cvss_scores,
                    "references": ref_urls,
                    "content_hash": content_hash,
                },
            )
        except Exception:
            return None
    
    def _extract_cvss_scores(self, metrics: dict[str, Any]) -> dict[str, str]:
        """Extract CVSS scores from metrics."""
        scores = {}
        
        # Handle both formats (v2 and v3)
        if "cvssMetricV2" in metrics:
            v2_metrics = metrics["cvssMetricV2"]
            if isinstance(v2_metrics, list):
                for metric in v2_metrics:
                    base_score = metric.get("cvssData", {}).get("baseScore")
                    if base_score:
                        scores["CVSS v2"] = str(base_score)
            elif isinstance(v2_metrics, dict):
                base_score = v2_metrics.get("cvssData", {}).get("baseScore")
                if base_score:
                    scores["CVSS v2"] = str(base_score)
        
        if "cvssMetricV30" in metrics:
            v30_metrics = metrics["cvssMetricV30"]
            if isinstance(v30_metrics, list):
                for metric in v30_metrics:
                    base_score = metric.get("cvssData", {}).get("baseScore")
                    if base_score:
                        scores["CVSS v3.0"] = str(base_score)
            elif isinstance(v30_metrics, dict):
                base_score = v30_metrics.get("cvssData", {}).get("baseScore")
                if base_score:
                    scores["CVSS v3.0"] = str(base_score)
        
        if "cvssMetricV31" in metrics:
            v31_metrics = metrics["cvssMetricV31"]
            if isinstance(v31_metrics, list):
                for metric in v31_metrics:
                    base_score = metric.get("cvssData", {}).get("baseScore")
                    if base_score:
                        scores["CVSS v3.1"] = str(base_score)
            elif isinstance(v31_metrics, dict):
                base_score = v31_metrics.get("cvssData", {}).get("baseScore")
                if base_score:
                    scores["CVSS v3.1"] = str(base_score)
        
        return scores
    
    def search(self, request: SearchRequest) -> SearchResponse:
        """Execute an NVD/CVE search request.
        
        Supports:
        - Search by CVE ID (exact match)
        - Search by keyword
        
        Query format:
        - "CVE-2021-1234" - search for specific CVE
        - "apache struts" - keyword search
        """
        # Validate scope
        if request.scope and request.scope not in (SearchScope.NVD, SearchScope.CVE):
            raise InvalidRequestError(
                f"NVD provider only supports NVD/CVE scope, got {request.scope}",
                provider=self.name,
            )
        
        # Check availability
        self.check_availability()
        if self._status == ProviderStatus.UNAVAILABLE:
            raise ProviderUnavailableError(
                f"NVD provider is {self._status.value}",
                provider=self.name,
            )
        
        query = request.query.strip()
        results = []
        
        # Check if query is a CVE ID
        cve_id_pattern = re.compile(r'^CVE-\d{4}-\d+$', re.IGNORECASE)
        if cve_id_pattern.match(query):
            # Direct CVE ID lookup
            results = self._search_by_cve_id(query)
        else:
            # Keyword search
            results = self._search_cves(query, request.max_results)
        
        return SearchResponse(
            request=request,
            results=results[:request.max_results],
            total_results=len(results),
            provider=self.name,
            metadata={
                "query": query,
                "search_type": "cve_id" if cve_id_pattern.match(query) else "keyword",
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
