"""Trusted-source intelligence ingestion: MITRE ATT&CK STIX and NVD feeds.

Owner policy (this layer):
* Every accepted item must carry provenance (source feed + source class).
* Fabricated identifiers (fake technique id, fake CVE) are REFUSED and
  reported - never silently ingested.
* Authority-bearing keys in feed items (authorization/scope/owner_instruction)
  are stripped: intel feeds are DATA, they can never grant authority.
* Source class caps confidence and edge strength: UNVERIFIED/SYNTHETIC/FIXTURE
  sources can never produce SUPPORTED claims, so poison cannot be laundered
  into the knowledge graph as strong evidence.
* Ingestion is offline-by-construction: this module parses data handed to it;
  it performs no network I/O itself.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from cyber.knowledge_model import (
    ClaimEdge,
    CyberKnowledgeGraph,
    EdgeStatus,
    Entity,
    Provenance,
    SourceClass,
)


_TECHNIQUE_ID = re.compile(r"^T\d{4}(\.\d{3})?$")
_CVE_ID = re.compile(r"^CVE-\d{4}-\d{4,}$")

_FORBIDDEN_KEYS = ("authorization", "scope", "owner_instruction", "identity", "authorization_context")

# Confidence ceiling per source class: stronger provenance required for
# stronger claims. A poisoned or synthetic feed simply cannot reach high
# confidence inside the graph.
_CONFIDENCE_CAP = {
    SourceClass.REAL: 0.9,
    SourceClass.PARTIAL: 0.7,
    SourceClass.SYNTHETIC: 0.4,
    SourceClass.FIXTURE: 0.4,
    SourceClass.UNVERIFIED: 0.3,
}


def _sanitize(obj: Any) -> Any:
    """Deep-copy minus authority-bearing keys (feeds are DATA, never authority)."""
    if isinstance(obj, dict):
        return {k: _sanitize(v) for k, v in obj.items() if k not in _FORBIDDEN_KEYS}
    if isinstance(obj, (list, tuple)):
        return [_sanitize(v) for v in obj]
    return obj


@dataclass
class IngestReport:
    ingested_entities: int = 0
    ingested_claims: int = 0
    refused: list[dict[str, Any]] = field(default_factory=list)
    sanitized_keys: int = 0

    def refuse(self, reason: str, item: Any) -> None:
        self.refused.append({"reason": reason, "item": item})

    def to_dict(self) -> dict[str, Any]:
        return {
            "ingested_entities": self.ingested_entities,
            "ingested_claims": self.ingested_claims,
            "refused": list(self.refused),
            "sanitized_keys": self.sanitized_keys,
        }


def _capped_confidence(source_class: SourceClass, requested: float) -> float:
    return min(max(0.0, requested), _CONFIDENCE_CAP[source_class])


def _edge_status_for(source_class: SourceClass) -> EdgeStatus:
    if source_class in (SourceClass.REAL, SourceClass.PARTIAL):
        return EdgeStatus.WEAK
    return EdgeStatus.UNKNOWN


def _technique_id_of(obj: dict[str, Any]) -> str | None:
    """The syntactically valid ATT&CK external id of an attack-pattern, or None."""
    for ref in (obj.get("external_references") or []):
        if isinstance(ref, dict):
            eid = ref.get("external_id")
            if isinstance(eid, str) and _TECHNIQUE_ID.match(eid):
                return eid
    return None


class IntelIngest:
    """Turns ATT&CK STIX bundles and NVD-style items into graph knowledge.

    Usage:
        ingest = IntelIngest(graph)
        report = ingest.ingest_attack_stix(bundle, source="mitre-attack", source_class=SourceClass.REAL)
        report = ingest.ingest_nvd_item(item, source="nvd", source_class=SourceClass.REAL)
    """

    def __init__(self, graph: CyberKnowledgeGraph) -> None:
        self.graph = graph

    # -- shared helpers -------------------------------------------------

    def _add_entity(self, entity: Entity, report: IngestReport) -> None:
        if self.graph.entity(entity.entity_id) is None:
            self.graph.add_entity(entity)
            report.ingested_entities += 1

    def _add_claim(self, edge: ClaimEdge, report: IngestReport) -> None:
        self.graph.add_claim(edge)
        report.ingested_claims += 1

    def _provenance(self, source: str, source_class: SourceClass,
                    report: IngestReport, uri: str = "") -> Provenance:
        return Provenance(source=source, uri=uri, source_class=source_class)

    # -- MITRE ATT&CK (STIX 2.1 attack patterns) --------------------------

    def ingest_attack_stix(self, bundle: dict[str, Any], *,
                           source: str, source_class: SourceClass) -> IngestReport:
        """Ingest a STIX bundle of attack-pattern objects.

        A technique is accepted only if:
        * the object is of type attack-pattern,
        * it carries an external_id matching the ATT&CK technique syntax,
        * a sub-technique's parent technique exists in the graph or in the
          same bundle (two-pass: parents first, then sub-techniques - an
          orphan sub-technique is refused and never enters the graph).

        Anything else is refused and reported. Sub-techniques get a
        DEPENDS_ON claim to their parent technique.
        """
        report = IngestReport()
        if not source or not str(source).strip():
            raise ValueError("ingestion requires a provenance source")
        safe_bundle = _sanitize(bundle)
        if safe_bundle != bundle:
            report.sanitized_keys += 1

        objects = safe_bundle.get("objects") or []
        if not isinstance(objects, list):
            report.refuse("bundle without an objects list", type(objects).__name__)
            return report

        # Pre-scan: which valid technique ids does this bundle offer?
        attack_patterns: list[tuple[str, dict[str, Any]]] = []
        bundle_ids: set[str] = set()
        for obj in objects:
            if not isinstance(obj, dict):
                report.refuse("non-dict bundle object", repr(obj)[:80])
                continue
            if obj.get("type") != "attack-pattern":
                # other STIX object types are out of scope for this ingest
                continue
            tech_id = _technique_id_of(obj)
            if tech_id is None:
                report.refuse("attack-pattern without a syntactically valid ATT&CK id", obj.get("id"))
                continue
            attack_patterns.append((tech_id, obj))
            bundle_ids.add(tech_id)

        status = _edge_status_for(source_class)
        parents: list[tuple[str, dict[str, Any]]] = [t for t in attack_patterns if "." not in t[0]]
        subs: list[tuple[str, dict[str, Any]]] = [t for t in attack_patterns if "." in t[0]]

        # Pass 1: parent techniques.
        for tech_id, obj in parents:
            name = str(obj.get("name") or tech_id)
            phases = obj.get("kill_chain_phases") or []
            phase = phases[0].get("phase_name", "") if isinstance(phases, list) and phases and isinstance(phases[0], dict) else ""
            self._add_entity(Entity(
                entity_id=tech_id,
                entity_type="TECHNIQUE",
                name=name,
                attributes={"stix_id": obj.get("id", ""), "phase": phase},
            ), report)

        # Pass 2: sub-techniques, now that parents are resolvable.
        for tech_id, obj in subs:
            parent_id = tech_id.split(".")[0]
            if self.graph.entity(parent_id) is None and parent_id not in bundle_ids:
                report.refuse("sub-technique without parent technique in graph or bundle", tech_id)
                continue
            self._add_entity(Entity(
                entity_id=tech_id,
                entity_type="SUBTECHNIQUE",
                name=str(obj.get("name") or tech_id),
                attributes={"stix_id": obj.get("id", ""), "phase": ""},
            ), report)
            if self.graph.entity(parent_id) is not None:
                self._add_claim(ClaimEdge(
                    relation="DEPENDS_ON",
                    source_id=tech_id,
                    target_id=parent_id,
                    provenance=self._provenance(source, source_class, report),
                    confidence=_capped_confidence(source_class, 0.8),
                    status=status,
                ), report)

        return report

    # -- NVD-style vulnerability items --------------------------------------

    def ingest_nvd_item(self, item: dict[str, Any], *,
                        source: str, source_class: SourceClass) -> IngestReport:
        """Ingest one NVD-style vulnerability item.

        Accepted shape (subset, extra fields ignored):
            {"cve": {"id": "CVE-...", "descriptions": [...], "cvss": 7.5},
             "affected": [{"product": "...", "version": "...", "vendor": "..."}]}

        A CVE is accepted only if its id matches the CVE syntax. Affected
        products create VERSION/PRODUCT entities and AFFECTS claims.
        CVSS feeds confidence, capped by the source class.
        """
        report = IngestReport()
        if not source or not str(source).strip():
            raise ValueError("ingestion requires a provenance source")
        safe_item = _sanitize(item)
        if safe_item != item:
            report.sanitized_keys += 1

        cve = safe_item.get("cve") or {}
        if not isinstance(cve, dict):
            report.refuse("nvd item without a cve object", repr(item)[:80])
            return report
        cve_id = cve.get("id")
        if not isinstance(cve_id, str) or not _CVE_ID.match(cve_id):
            report.refuse("refusing to ingest invented CVE id", cve.get("id"))
            return report

        cvss = cve.get("cvss")
        if not isinstance(cvss, (int, float)) or not 0.0 <= float(cvss) <= 10.0:
            cvss = None
        base_conf = (float(cvss) / 10.0) if cvss is not None else 0.4
        confidence = _capped_confidence(source_class, base_conf)
        status = _edge_status_for(source_class)

        desc = ""
        for d in (cve.get("descriptions") or []):
            if isinstance(d, dict) and d.get("lang") == "en" and d.get("value"):
                desc = str(d["value"])
                break

        cve_entity = Entity(
            entity_id=cve_id,
            entity_type="CVE",
            name=cve_id,
            attributes={"description": desc, "cvss": cvss},
        )
        self._add_entity(cve_entity, report)

        affected = safe_item.get("affected") or []
        if not isinstance(affected, list):
            report.refuse("nvd item with non-list affected field", cve_id)
            return report

        for aff in affected:
            if not isinstance(aff, dict):
                report.refuse("non-dict affected entry", cve_id)
                continue
            product = aff.get("product")
            if not product:
                continue
            vendor = str(aff.get("vendor") or "unknown-vendor")
            version = aff.get("version") or "unspecified"
            product_id = "product:{}:{}".format(vendor, str(product))
            version_id = "{}@{}".format(product_id, str(version))
            self._add_entity(Entity(entity_id=product_id, entity_type="PRODUCT", name=str(product)), report)
            self._add_entity(Entity(entity_id=version_id, entity_type="VERSION", name=str(version)), report)
            self._add_claim(ClaimEdge(
                relation="DEPENDS_ON",
                source_id=version_id,
                target_id=product_id,
                provenance=self._provenance(source, source_class, report),
                confidence=confidence,
                status=status,
            ), report)
            self._add_claim(ClaimEdge(
                relation="AFFECTS",
                source_id=cve_id,
                target_id=version_id,
                provenance=self._provenance(source, source_class, report),
                confidence=confidence,
                status=status,
            ), report)

        return report
