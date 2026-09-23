"""Threat-actor knowledge: well-established real adversary profiles.

Provenance honesty: these actor/campaign/malware/technique relationships are
widely documented public knowledge (vendor reports, MITRE ATT&CK Groups),
reproduced from offline model knowledge at seed time -> PARTIAL class.

Discipline:
* Only HIGH-CONFIDENCE, publicly established relationships are included.
  Disputed attributions are excluded entirely rather than weakened.
* Claims are WEAK-strength (single offline source): they power reasoning,
  but real feed ingestion with independent provenance can upgrade them.
* No authority: profiles are data about adversaries, never instructions.
"""

from __future__ import annotations

from typing import Any

from cyber.knowledge_model import (
    ClaimEdge,
    CyberKnowledgeGraph,
    EdgeStatus,
    Entity,
    Provenance,
    SourceClass,
)


def _p() -> Provenance:
    return Provenance(source="threat-intel-seed", source_class=SourceClass.PARTIAL)


# (actor_id, name, [aliases]) - real, publicly documented groups
_ACTORS: list[tuple[str, str, list[str]]] = [
    ("actor:APT28", "APT28", ["Fancy Bear", "Sofacy", "Sednit"]),
    ("actor:APT29", "APT29", ["Cozy Bear", "The Dukes"]),
    ("actor:Lazarus", "Lazarus Group", ["Hidden Cobra"]),
]

# (campaign_id, name) - real campaigns
_CAMPAIGNS: list[tuple[str, str]] = [
    ("campaign:2016-us-election", "2016 US election influence operations (documented)"),
    ("campaign:solarwinds-supply-chain", "SolarWinds supply-chain compromise"),
    ("campaign:applejeus", "AppleJeus cryptocurrency exchange attacks"),
]

# (actor, campaign) ATTRIBUTED_TO - high-confidence public attribution
_ATTRIBUTIONS: list[tuple[str, str]] = [
    ("actor:APT28", "campaign:2016-us-election"),
    ("actor:APT29", "campaign:solarwinds-supply-chain"),
    ("actor:Lazarus", "campaign:applejeus"),
]

# (malware_id, name) - real malware families
_MALWARE: list[tuple[str, str]] = [
    ("malware:zedrocy", "Zebrocy"),
    ("malware:x-agent", "X-Agent"),
    ("malware:sunburst", "Sunburst"),
    ("malware:hammertoss", "HammerToss"),
    ("malware:applejeus", "AppleJeus"),
]

# (campaign|actor, malware) USES
_USES_MALWARE: list[tuple[str, str]] = [
    ("actor:APT28", "malware:zedrocy"),
    ("actor:APT28", "malware:x-agent"),
    ("campaign:2016-us-election", "malware:x-agent"),
    ("campaign:solarwinds-supply-chain", "malware:sunburst"),
    ("actor:APT29", "malware:hammertoss"),
    ("campaign:applejeus", "malware:applejeus"),
]

# (actor, technique) USES - established TTPs
_USES_TECHNIQUE: list[tuple[str, str]] = [
    ("actor:APT28", "T1566.001"),
    ("actor:APT28", "T1059.001"),
    ("actor:APT28", "T1078"),
    ("actor:APT29", "T1190"),
    ("actor:APT29", "T1055"),
    ("actor:APT29", "T1071.001"),
    ("actor:Lazarus", "T1133"),
    ("actor:Lazarus", "T1486"),
]


def build_actor_graph(*, with_seed_techniques: bool = True) -> CyberKnowledgeGraph:
    """A graph with actor knowledge; optionally over the technique seed corpus."""
    graph: CyberKnowledgeGraph
    if with_seed_techniques:
        from cyber.seed_corpus import build_seed_graph
        graph, _ = build_seed_graph()
    else:
        graph = CyberKnowledgeGraph()

    for actor_id, name, aliases in _ACTORS:
        graph.add_entity(Entity(
            entity_id=actor_id, entity_type="ACTOR", name=name,
            attributes={"aliases": list(aliases)},
        ))
    for camp_id, name in _CAMPAIGNS:
        graph.add_entity(Entity(
            entity_id=camp_id, entity_type="CAMPAIGN", name=name, attributes={},
        ))
    for mal_id, name in _MALWARE:
        graph.add_entity(Entity(
            entity_id=mal_id, entity_type="MALWARE", name=name, attributes={},
        ))

    prov = _p()
    for actor_id, camp_id in _ATTRIBUTIONS:
        graph.add_claim(ClaimEdge(
            relation="ATTRIBUTED_TO", source_id=actor_id, target_id=camp_id,
            provenance=prov, confidence=0.7, status=EdgeStatus.WEAK,
        ))
    for src, mal_id in _USES_MALWARE:
        graph.add_claim(ClaimEdge(
            relation="USES", source_id=src, target_id=mal_id,
            provenance=prov, confidence=0.7, status=EdgeStatus.WEAK,
        ))
    for src, tech_id in _USES_TECHNIQUE:
        graph.add_claim(ClaimEdge(
            relation="USES", source_id=src, target_id=tech_id,
            provenance=prov, confidence=0.7, status=EdgeStatus.WEAK,
        ))
    return graph


def actor_ids() -> list[str]:
    return [a[0] for a in _ACTORS]
