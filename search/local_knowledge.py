"""
Local Knowledge Provider

Search provider for local knowledge database (intel).
"""

from __future__ import annotations

import hashlib
import json
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
from .exceptions import ProviderUnavailableError, InvalidRequestError


class LocalKnowledgeProvider(SearchProvider):
    """Search provider for local knowledge/intel database.
    
    This provider searches the local SQLite database for:
    - Events
    - Threat intelligence
    - Watched keywords
    
    All results are UNTRUSTED_DATA.
    """
    
    name = "local_knowledge"
    scope = SearchScope.LOCAL
    capabilities = frozenset({
        ProviderCapability.SEARCH,
        ProviderCapability.READ_ONLY,
    })
    status = ProviderStatus.IMPLEMENTED
    
    max_results = 50
    max_response_bytes = 1000000  # 1MB
    max_result_chars = 50000
    timeout = 30.0
    
    def __init__(self):
        """Initialize provider and check database availability."""
        self._check_db()
    
    def _check_db(self) -> None:
        """Check if database is available."""
        try:
            from core.db import connect
            with connect() as con:
                con.execute("SELECT 1")
            self.status = ProviderStatus.AVAILABLE
        except Exception:
            self.status = ProviderStatus.UNAVAILABLE
    
    def check_availability(self) -> ProviderStatus:
        """Check if provider is available."""
        self._check_db()
        return self.status
    
    def search(self, request: SearchRequest) -> SearchResponse:
        """Search local knowledge database.
        
        Searches:
        - intel table (threat intelligence)
        - events table (audit events)
        
        Returns normalized SearchResponse with provenance.
        """
        from core.db import search_all
        
        # Validate request
        if request.scope and request.scope != SearchScope.LOCAL:
            raise InvalidRequestError(
                f"Local knowledge provider only supports LOCAL scope, got {request.scope}",
                provider=self.name,
            )
        
        # Check availability
        if self.status != ProviderStatus.AVAILABLE:
            raise ProviderUnavailableError(
                f"Local knowledge database is {self.status.value}",
                provider=self.name,
            )
        
        # Execute search
        try:
            results = search_all(request.query, limit=request.max_results)
        except Exception as e:
            return SearchResponse(
                request=request,
                results=[],
                total_results=0,
                provider=self.name,
                error=str(e),
                error_type="provider_error",
                metadata={"status": self.status.value},
            )
        
        # Normalize results
        search_results = []
        for event in results.get("events", []):
            result = self._normalize_event(event, "event")
            if result:
                search_results.append(result)
        
        for intel_item in results.get("intel", []):
            result = self._normalize_intel(intel_item, "intel")
            if result:
                search_results.append(result)
        
        return SearchResponse(
            request=request,
            results=search_results[:request.max_results],
            total_results=len(search_results),
            provider=self.name,
            metadata={
                "sources": ["events", "intel"],
                "query": request.query,
            },
        )
    
    def _normalize_event(self, event: dict[str, Any], source_type: str) -> SearchResult | None:
        """Normalize an event into SearchResult."""
        try:
            content = f"{event.get('title', '')}: {event.get('body', '')}"
            if not content.strip():
                return None
            
            return SearchResult(
                result_id=f"event:{event.get('id', '')}",
                title=event.get('title', 'Untitled Event'),
                content=self.truncate_result(content),
                source="local_db",
                source_type=source_type,
                url=None,
                provenance={
                    "source": "local_db",
                    "table": "events",
                    "severity": event.get('severity', 'info'),
                    "kind": event.get('kind', 'unknown'),
                },
                metadata={
                    "event_id": event.get('id'),
                    "created_at": event.get('created_at'),
                    "trusted": event.get('trusted', False),
                },
            )
        except Exception:
            return None
    
    def _normalize_intel(self, intel: dict[str, Any], source_type: str) -> SearchResult | None:
        """Normalize an intel item into SearchResult."""
        try:
            content = f"{intel.get('title', '')}: {intel.get('body', '')}"
            if not content.strip():
                return None
            
            # Calculate content hash
            content_bytes = content.encode('utf-8')
            content_hash = hashlib.sha256(content_bytes).hexdigest()
            
            return SearchResult(
                result_id=f"intel:{intel.get('id', '')}",
                title=intel.get('title', 'Untitled Intel'),
                content=self.truncate_result(content),
                source=intel.get('source', 'unknown'),
                source_type=source_type,
                url=intel.get('external_id'),  # Could be CVE ID or URL
                provenance={
                    "source": intel.get('source', 'unknown'),
                    "table": "intel",
                    "severity": intel.get('severity', 'info'),
                },
                metadata={
                    "intel_id": intel.get('id'),
                    "external_id": intel.get('external_id'),
                    "collected_at": intel.get('collected_at'),
                    "content_hash": content_hash,
                },
            )
        except Exception:
            return None
