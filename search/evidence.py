"""
Evidence Generation from Search Results

Generates evidence records from search operations for audit and provenance tracking.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from .providers import (
    SearchRequest,
    SearchResponse,
    SearchResult,
    SearchScope,
    ProviderStatus,
)
from .exceptions import SearchError


@dataclass(frozen=True)
class Evidence:
    """Evidence record for search operations.
    
    This record tracks:
    - The search request
    - The results obtained
    - Provenance information
    - Security classification
    
    All evidence is stored with content hashes, not raw content,
    to avoid storing sensitive data.
    """
    evidence_id: str
    request_id: str | None
    search_query: str
    search_scope: SearchScope | None
    provider: str
    timestamp: str
    result_count: int
    content_hash: str
    provenance: dict[str, Any]
    metadata: dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "evidence_id": self.evidence_id,
            "request_id": self.request_id,
            "search_query": self.search_query,
            "search_scope": self.search_scope.value if self.search_scope else None,
            "provider": self.provider,
            "timestamp": self.timestamp,
            "result_count": self.result_count,
            "content_hash": self.content_hash,
            "provenance": self.provenance,
            "metadata": self.metadata,
        }
    
    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Evidence:
        """Create from dictionary."""
        scope = None
        if data.get("search_scope"):
            scope = SearchScope(data["search_scope"])
        
        return cls(
            evidence_id=data["evidence_id"],
            request_id=data.get("request_id"),
            search_query=data["search_query"],
            search_scope=scope,
            provider=data["provider"],
            timestamp=data["timestamp"],
            result_count=data["result_count"],
            content_hash=data["content_hash"],
            provenance=data["provenance"],
            metadata=data.get("metadata", {}),
        )


@dataclass
class EvidenceBuilder:
    """Builder for creating evidence from search results."""
    
    def build_from_response(
        self,
        response: SearchResponse,
        request_id: str | None = None,
    ) -> Evidence:
        """Build evidence from a search response.
        
        Args:
            response: The search response
            request_id: Optional request ID for correlation
            
        Returns:
            Evidence record
        """
        # Calculate content hash from all results
        content_parts = []
        for result in response.results:
            content_parts.append(result.content)
        
        content = "\n\n".join(content_parts)
        content_hash = hashlib.sha256(content.encode('utf-8')).hexdigest()
        
        # Build provenance
        provenance = {
            "source": "search",
            "provider": response.provider,
            "query": response.request.query,
            "scope": response.request.scope.value if response.request.scope else None,
            "total_results": response.total_results,
            "success": response.success,
            "error": response.error,
            "error_type": response.error_type,
        }
        
        # Add result provenance
        result_sources = set()
        result_types = set()
        for result in response.results:
            result_sources.add(result.source)
            result_types.add(result.source_type)
        
        provenance["result_sources"] = list(result_sources)
        provenance["result_types"] = list(result_types)
        
        return Evidence(
            evidence_id=str(uuid.uuid4()),
            request_id=request_id,
            search_query=response.request.query,
            search_scope=response.request.scope,
            provider=response.provider,
            timestamp=datetime.now(timezone.utc).isoformat(),
            result_count=len(response.results),
            content_hash=content_hash,
            provenance=provenance,
            metadata={
                "max_results": response.request.max_results,
                "timeout": response.request.timeout,
                "metadata": response.metadata,
            },
        )
    
    def build_from_result(
        self,
        result: SearchResult,
        request: SearchRequest,
        request_id: str | None = None,
    ) -> Evidence:
        """Build evidence from a single search result.
        
        Args:
            result: The search result
            request: The original search request
            request_id: Optional request ID for correlation
            
        Returns:
            Evidence record
        """
        content_hash = result.content_hash or hashlib.sha256(
            result.content.encode('utf-8')
        ).hexdigest()
        
        provenance = {
            "source": result.source,
            "source_type": result.source_type,
            "result_id": result.result_id,
            "url": result.url,
            "retrieved_at": result.retrieved_at,
        }
        
        # Add metadata provenance
        if result.metadata:
            provenance["metadata"] = {
                k: v for k, v in result.metadata.items()
                if not self._is_sensitive_key(k)
            }
        
        return Evidence(
            evidence_id=str(uuid.uuid4()),
            request_id=request_id,
            search_query=request.query,
            search_scope=request.scope,
            provider=result.source,
            timestamp=datetime.now(timezone.utc).isoformat(),
            result_count=1,
            content_hash=content_hash,
            provenance=provenance,
            metadata={
                "title": result.title,
                "content_length": len(result.content),
            },
        )
    
    def _is_sensitive_key(self, key: str) -> bool:
        """Check if a metadata key contains sensitive data."""
        sensitive_keys = {
            "token",
            "api_key",
            "apikey",
            "secret",
            "password",
            "credential",
            "auth",
            "authorization",
            "private_key",
            "access_token",
        }
        key_lower = key.lower()
        return any(s in key_lower for s in sensitive_keys)


class EvidenceStore:
    """Simple in-memory store for evidence records.
    
    In a production environment, this would persist to a database.
    """
    
    def __init__(self):
        self._evidence: dict[str, Evidence] = {}
        self._request_evidence: dict[str, list[str]] = {}  # request_id -> evidence_ids
    
    def add(self, evidence: Evidence) -> str:
        """Add evidence to store.
        
        Args:
            evidence: Evidence to store
            
        Returns:
            evidence_id
        """
        self._evidence[evidence.evidence_id] = evidence
        
        if evidence.request_id:
            if evidence.request_id not in self._request_evidence:
                self._request_evidence[evidence.request_id] = []
            self._request_evidence[evidence.request_id].append(evidence.evidence_id)
        
        return evidence.evidence_id
    
    def get(self, evidence_id: str) -> Evidence | None:
        """Get evidence by ID."""
        return self._evidence.get(evidence_id)
    
    def get_by_request(self, request_id: str) -> list[Evidence]:
        """Get all evidence for a request."""
        evidence_ids = self._request_evidence.get(request_id, [])
        return [self._evidence[eid] for eid in evidence_ids if eid in self._evidence]
    
    def query(
        self,
        search_query: str | None = None,
        provider: str | None = None,
        scope: SearchScope | None = None,
        limit: int = 100,
    ) -> list[Evidence]:
        """Query evidence by criteria."""
        results = []
        
        for evidence in self._evidence.values():
            if search_query and search_query.lower() not in evidence.search_query.lower():
                continue
            if provider and provider.lower() != evidence.provider.lower():
                continue
            if scope and scope != evidence.search_scope:
                continue
            
            results.append(evidence)
            if len(results) >= limit:
                break
        
        return results
    
    def clear(self) -> None:
        """Clear all evidence."""
        self._evidence.clear()
        self._request_evidence.clear()


class EvidenceGenerator:
    """Generates evidence from search operations.
    
    This class integrates with the search service to automatically
    generate evidence records for all search operations.
    """
    
    def __init__(self):
        self.builder = EvidenceBuilder()
        self.store = EvidenceStore()
    
    def generate_from_response(
        self,
        response: SearchResponse,
        request_id: str | None = None,
        store: bool = True,
    ) -> Evidence:
        """Generate and optionally store evidence from a search response.
        
        Args:
            response: The search response
            request_id: Optional request ID for correlation
            store: Whether to store the evidence
            
        Returns:
            Evidence record
        """
        evidence = self.builder.build_from_response(response, request_id)
        
        if store:
            self.store.add(evidence)
        
        return evidence
    
    def generate_from_result(
        self,
        result: SearchResult,
        request: SearchRequest,
        request_id: str | None = None,
        store: bool = True,
    ) -> Evidence:
        """Generate and optionally store evidence from a search result.
        
        Args:
            result: The search result
            request: The original search request
            request_id: Optional request ID for correlation
            store: Whether to store the evidence
            
        Returns:
            Evidence record
        """
        evidence = self.builder.build_from_result(result, request, request_id)
        
        if store:
            self.store.add(evidence)
        
        return evidence


# Global evidence generator instance
evidence_generator = EvidenceGenerator()


def generate_evidence(
    response: SearchResponse,
    request_id: str | None = None,
) -> Evidence:
    """Generate evidence from a search response.
    
    Convenience function that uses the global evidence generator.
    
    Args:
        response: The search response
        request_id: Optional request ID for correlation
        
    Returns:
        Evidence record
    """
    return evidence_generator.generate_from_response(response, request_id)
