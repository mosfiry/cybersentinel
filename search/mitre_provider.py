"""
MITRE ATT&CK Search Provider

Read-only MITRE ATT&CK search provider for techniques, tactics, and procedures.
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
    ProviderTimeoutError,
    RateLimitError,
    InvalidRequestError,
    ParseError,
    NetworkError,
    ResponseTooLargeError,
)
from .ssrf import check_url_ssrf


class MITREProvider(SearchProvider):
    """MITRE ATT&CK search provider with read-only capabilities.
    
    This provider searches MITRE ATT&CK data for:
    - Techniques
    - Tactics
    - Mitigations
    - Groups
    - Software
    - Malware
    
    All results are UNTRUSTED_DATA.
    All operations are READ-ONLY in Phase 4.
    """
    
    name = "mitre"
    scope = SearchScope.MITRE
    capabilities = frozenset({
        ProviderCapability.SEARCH,
        ProviderCapability.GET_BY_ID,
        ProviderCapability.READ_ONLY,
    })
    
    # Configuration
    MITRE_API_URL = "https://attack.mitre.org"
    MITRE_STIX_API_URL = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack"
    
    # Limits
    max_results = 50
    max_response_bytes = 1000000  # 1MB
    max_result_chars = 30000
    timeout = 30.0
    
    # Local cache for STIX data
    _stix_data = None
    _last_stix_load = None
    _stix_load_timeout = 3600  # 1 hour
    
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
        # MITRE ATT&CK is always available (public data)
        # But we should check if we can reach it
        try:
            session = self._get_session()
            if hasattr(session, 'get'):
                import httpx
                import requests
                
                # Try a simple HEAD request to check API availability
                if isinstance(session, httpx.Client):
                    response = session.head(
                        self.MITRE_API_URL,
                        timeout=5.0,
                    )
                elif isinstance(session, requests.Session):
                    response = session.head(
                        self.MITRE_API_URL,
                        timeout=5.0,
                    )
                else:
                    return ProviderStatus.UNAVAILABLE
                
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
    
    def _load_stix_data(self) -> dict[str, Any] | None:
        """Load MITRE ATT&CK STIX data from GitHub."""
        import httpx
        import requests
        
        # Check if we have cached data
        if self._stix_data is not None:
            import time
            if time.time() - self._last_stix_load < self._stix_load_timeout:
                return self._stix_data
        
        # Load from GitHub
        urls = [
            f"{self.MITRE_STIX_API_URL}/enterprise-attack.json",
            f"{self.MITRE_STIX_API_URL}/enterprise-attack.json",
        ]
        
        session = self._get_session()
        
        for url in urls:
            check_url_ssrf(url, raise_on_block=True)
            
            try:
                if isinstance(session, httpx.Client):
                    response = session.get(url, timeout=self.timeout)
                elif isinstance(session, requests.Session):
                    response = session.get(url, timeout=self.timeout)
                else:
                    continue
                
                if response.status_code == 200:
                    self._stix_data = response.json()
                    self._last_stix_load = datetime.now(timezone.utc).timestamp()
                    return self._stix_data
            except Exception:
                continue
        
        return None
    
    def _get_techniques(self) -> list[dict[str, Any]]:
        """Get all techniques from STIX data."""
        stix_data = self._load_stix_data()
        if not stix_data:
            return []
        
        techniques = []
        objects = stix_data.get("objects", [])
        
        for obj in objects:
            if obj.get("type") == "attack-pattern":
                techniques.append(obj)
        
        return techniques
    
    def _get_tactics(self) -> list[dict[str, Any]]:
        """Get all tactics from STIX data."""
        stix_data = self._load_stix_data()
        if not stix_data:
            return []
        
        tactics = []
        objects = stix_data.get("objects", [])
        
        for obj in objects:
            if obj.get("type") == "x-mitre-tactic":
                tactics.append(obj)
        
        return tactics
    
    def _get_mitigations(self) -> list[dict[str, Any]]:
        """Get all mitigations from STIX data."""
        stix_data = self._load_stix_data()
        if not stix_data:
            return []
        
        mitigations = []
        objects = stix_data.get("objects", [])
        
        for obj in objects:
            if obj.get("type") == "course-of-action":
                mitigations.append(obj)
        
        return mitigations
    
    def _get_groups(self) -> list[dict[str, Any]]:
        """Get all groups from STIX data."""
        stix_data = self._load_stix_data()
        if not stix_data:
            return []
        
        groups = []
        objects = stix_data.get("objects", [])
        
        for obj in objects:
            if obj.get("type") == "intrusion-set":
                groups.append(obj)
        
        return groups
    
    def _search_techniques(
        self,
        query: str,
        max_results: int,
    ) -> list[SearchResult]:
        """Search MITRE ATT&CK techniques."""
        results = []
        techniques = self._get_techniques()
        
        query_lower = query.lower()
        
        for technique in techniques:
            name = technique.get("name", "").lower()
            description = technique.get("description", "").lower()
            external_references = technique.get("external_references", [])
            
            # Extract technique ID
            technique_id = ""
            for ref in external_references:
                if ref.get("source_name") == "mitre-attack":
                    technique_id = ref.get("external_id", "")
                    break
            
            # Check if matches query
            if (query_lower in name or 
                query_lower in description or 
                query_lower in technique_id.lower()):
                
                result = self._normalize_technique(technique)
                if result:
                    results.append(result)
            
            if len(results) >= max_results:
                break
        
        return results
    
    def _search_tactics(
        self,
        query: str,
        max_results: int,
    ) -> list[SearchResult]:
        """Search MITRE ATT&CK tactics."""
        results = []
        tactics = self._get_tactics()
        
        query_lower = query.lower()
        
        for tactic in tactics:
            name = tactic.get("name", "").lower()
            description = tactic.get("description", "").lower()
            
            if query_lower in name or query_lower in description:
                result = self._normalize_tactic(tactic)
                if result:
                    results.append(result)
            
            if len(results) >= max_results:
                break
        
        return results
    
    def _search_by_id(
        self,
        technique_id: str,
    ) -> list[SearchResult]:
        """Search for a specific technique by ID."""
        results = []
        techniques = self._get_techniques()
        
        for technique in techniques:
            external_references = technique.get("external_references", [])
            
            for ref in external_references:
                if ref.get("source_name") == "mitre-attack":
                    if ref.get("external_id", "").upper() == technique_id.upper():
                        result = self._normalize_technique(technique)
                        if result:
                            results.append(result)
                        break
        
        return results
    
    def _normalize_technique(self, technique: dict[str, Any]) -> SearchResult | None:
        """Normalize a MITRE ATT&CK technique into SearchResult."""
        try:
            name = technique.get("name", "")
            description = technique.get("description", "")
            
            # Extract technique ID
            external_references = technique.get("external_references", [])
            technique_id = ""
            url = ""
            for ref in external_references:
                if ref.get("source_name") == "mitre-attack":
                    technique_id = ref.get("external_id", "")
                    url = ref.get("url", "")
                    break
            
            # Build content
            content = f"Technique ID: {technique_id}\n"
            content += f"Name: {name}\n\n"
            content += f"Description:\n{description}\n\n"
            
            # Add x_mitre fields
            x_mitre_attack = technique.get("x_mitre_attack", {})
            if x_mitre_attack:
                tactics = x_mitre_attack.get("tactics", [])
                if tactics:
                    content += "Tactics:\n"
                    for tactic in tactics:
                        content += f"  - {tactic}\n"
                    content += "\n"
            
            # Add mitigations
            mitigations = technique.get("x_mitre_mitigations", [])
            if mitigations:
                content += "Mitigations:\n"
                for mitigation in mitigations:
                    content += f"  - {mitigation}\n"
                content += "\n"
            
            # Add data sources
            data_sources = technique.get("x_mitre_data_sources", [])
            if data_sources:
                content += "Data Sources:\n"
                for ds in data_sources:
                    content += f"  - {ds}\n"
                content += "\n"
            
            content = self.truncate_result(content)
            content = self.sanitize_content(content)
            
            # Calculate hash
            content_bytes = content.encode('utf-8')
            content_hash = hashlib.sha256(content_bytes).hexdigest()
            
            return SearchResult(
                result_id=f"mitre:technique:{technique_id}",
                title=f"{technique_id}: {name}" if technique_id else name,
                content=content,
                source="mitre",
                source_type="technique",
                url=url or f"https://attack.mitre.org/techniques/{technique_id.lower()}",
                provenance={
                    "source": "mitre",
                    "type": "technique",
                    "provider": self.name,
                },
                metadata={
                    "technique_id": technique_id,
                    "name": name,
                    "type": "attack-pattern",
                    "content_hash": content_hash,
                },
            )
        except Exception:
            return None
    
    def _normalize_tactic(self, tactic: dict[str, Any]) -> SearchResult | None:
        """Normalize a MITRE ATT&CK tactic into SearchResult."""
        try:
            name = tactic.get("name", "")
            description = tactic.get("description", "")
            
            # Extract tactic ID
            external_references = tactic.get("external_references", [])
            tactic_id = ""
            url = ""
            for ref in external_references:
                if ref.get("source_name") == "mitre-attack":
                    tactic_id = ref.get("external_id", "")
                    url = ref.get("url", "")
                    break
            
            # Build content
            content = f"Tactic ID: {tactic_id}\n"
            content += f"Name: {name}\n\n"
            content += f"Description:\n{description}\n"
            
            content = self.truncate_result(content)
            content = self.sanitize_content(content)
            
            # Calculate hash
            content_bytes = content.encode('utf-8')
            content_hash = hashlib.sha256(content_bytes).hexdigest()
            
            return SearchResult(
                result_id=f"mitre:tactic:{tactic_id}",
                title=f"{tactic_id}: {name}" if tactic_id else name,
                content=content,
                source="mitre",
                source_type="tactic",
                url=url or f"https://attack.mitre.org/tactics/{tactic_id.lower()}",
                provenance={
                    "source": "mitre",
                    "type": "tactic",
                    "provider": self.name,
                },
                metadata={
                    "tactic_id": tactic_id,
                    "name": name,
                    "type": "x-mitre-tactic",
                    "content_hash": content_hash,
                },
            )
        except Exception:
            return None
    
    def _normalize_mitigation(self, mitigation: dict[str, Any]) -> SearchResult | None:
        """Normalize a MITRE ATT&CK mitigation into SearchResult."""
        try:
            name = mitigation.get("name", "")
            description = mitigation.get("description", "")
            
            # Extract mitigation ID
            external_references = mitigation.get("external_references", [])
            mitigation_id = ""
            url = ""
            for ref in external_references:
                if ref.get("source_name") == "mitre-attack":
                    mitigation_id = ref.get("external_id", "")
                    url = ref.get("url", "")
                    break
            
            # Build content
            content = f"Mitigation ID: {mitigation_id}\n"
            content += f"Name: {name}\n\n"
            content += f"Description:\n{description}\n"
            
            content = self.truncate_result(content)
            content = self.sanitize_content(content)
            
            # Calculate hash
            content_bytes = content.encode('utf-8')
            content_hash = hashlib.sha256(content_bytes).hexdigest()
            
            return SearchResult(
                result_id=f"mitre:mitigation:{mitigation_id}",
                title=f"{mitigation_id}: {name}" if mitigation_id else name,
                content=content,
                source="mitre",
                source_type="mitigation",
                url=url or f"https://attack.mitre.org/mitigations/{mitigation_id.lower()}",
                provenance={
                    "source": "mitre",
                    "type": "mitigation",
                    "provider": self.name,
                },
                metadata={
                    "mitigation_id": mitigation_id,
                    "name": name,
                    "type": "course-of-action",
                    "content_hash": content_hash,
                },
            )
        except Exception:
            return None
    
    def search(self, request: SearchRequest) -> SearchResponse:
        """Execute a MITRE ATT&CK search request.
        
        Supports searching:
        - Techniques (default)
        - Tactics
        - Mitigations
        
        Query format:
        - "T1055" or "T1055.001" - search for specific technique by ID
        - "type:technique persistence" - search techniques with keyword
        - "type:tactic persistence" - search tactics with keyword
        - "type:mitigation network" - search mitigations with keyword
        - "persistence" - default: search techniques
        """
        # Validate scope
        if request.scope and request.scope != SearchScope.MITRE:
            raise InvalidRequestError(
                f"MITRE provider only supports MITRE scope, got {request.scope}",
                provider=self.name,
            )
        
        # Check availability
        self.check_availability()
        if self._status == ProviderStatus.UNAVAILABLE:
            raise ProviderUnavailableError(
                f"MITRE provider is {self._status.value}",
                provider=self.name,
            )
        
        query = request.query.strip()
        
        # Parse query type
        search_type = "technique"  # default
        
        # Check for type prefix
        type_match = re.match(r'^type:(\w+)\s+(.*)', query, re.IGNORECASE)
        if type_match:
            search_type = type_match.group(1).lower()
            query = type_match.group(2)
        
        # Check for technique ID pattern
        technique_id_pattern = re.compile(r'^T\d{4}(\.\d{3})?$', re.IGNORECASE)
        if technique_id_pattern.match(query):
            # Direct technique ID lookup
            results = self._search_by_id(query)
        elif search_type == "tactic":
            results = self._search_tactics(query, request.max_results)
        elif search_type == "mitigation":
            results = self._search_mitigations(query, request.max_results)
        else:
            # Default to techniques
            results = self._search_techniques(query, request.max_results)
        
        return SearchResponse(
            request=request,
            results=results[:request.max_results],
            total_results=len(results),
            provider=self.name,
            metadata={
                "query": query,
                "search_type": search_type,
                "status": self._status.value,
            },
        )
    
    def _search_mitigations(
        self,
        query: str,
        max_results: int,
    ) -> list[SearchResult]:
        """Search MITRE ATT&CK mitigations."""
        results = []
        mitigations = self._get_mitigations()
        
        query_lower = query.lower()
        
        for mitigation in mitigations:
            name = mitigation.get("name", "").lower()
            description = mitigation.get("description", "").lower()
            
            if query_lower in name or query_lower in description:
                result = self._normalize_mitigation(mitigation)
                if result:
                    results.append(result)
            
            if len(results) >= max_results:
                break
        
        return results


# Provider error for compatibility
class ProviderError(Exception):
    """Generic provider error."""
    def __init__(self, message: str, provider: str | None = None):
        super().__init__(message)
        self.message = message
        self.provider = provider
