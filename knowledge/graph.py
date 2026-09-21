from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Iterable

from .foundation import KnowledgeError


class GraphRelation(str, Enum):
    SUPPORTS = "SUPPORTS"
    DESCRIBES = "DESCRIBES"
    ATTRIBUTED_TO = "ATTRIBUTED_TO"
    USES = "USES"
    REFERENCES = "REFERENCES"
    CONTRADICTS = "CONTRADICTS"
    DETECTED_BY = "DETECTED_BY"


ALLOWED_NODE_TYPES = {"SOURCE", "DOCUMENT", "CLAIM", "ACTOR", "CAMPAIGN", "TECHNIQUE", "MALWARE", "VULNERABILITY", "EVIDENCE", "FINDING", "DETECTION"}


@dataclass(frozen=True)
class GraphNode:
    node_id: str
    node_type: str
    label: str

    def __post_init__(self) -> None:
        if self.node_type not in ALLOWED_NODE_TYPES:
            raise KnowledgeError("unsupported provenance graph node type")
        if not self.node_id or not self.label:
            raise KnowledgeError("graph node identity and label are required")


@dataclass(frozen=True)
class ProvenanceEdge:
    edge_id: str
    source_node: str
    relation: GraphRelation
    target_node: str
    source_claim_id: str

    def __post_init__(self) -> None:
        if not self.edge_id or not self.source_node or not self.target_node or not self.source_claim_id:
            raise KnowledgeError("provenance edges require source claim IDs")
        if self.relation not in set(GraphRelation):
            raise KnowledgeError("unsupported provenance graph relation")


@dataclass(frozen=True)
class ProvenanceGraph:
    nodes: tuple[GraphNode, ...] = ()
    edges: tuple[ProvenanceEdge, ...] = ()

    def validate(self) -> None:
        node_ids = {node.node_id for node in self.nodes}
        if len(node_ids) != len(self.nodes):
            raise KnowledgeError("provenance graph node IDs must be unique")
        edge_ids = {edge.edge_id for edge in self.edges}
        if len(edge_ids) != len(self.edges):
            raise KnowledgeError("provenance graph edge IDs must be unique")
        for edge in self.edges:
            if edge.source_node not in node_ids or edge.target_node not in node_ids:
                raise KnowledgeError("provenance edge references unknown node")
        return None

    def neighbors(self, node_id: str, relation: GraphRelation | None = None) -> tuple[GraphNode, ...]:
        self.validate()
        ids = {edge.target_node for edge in self.edges if edge.source_node == node_id and (relation is None or edge.relation is relation)}
        return tuple(node for node in self.nodes if node.node_id in ids)


@dataclass(frozen=True)
class RedBluePurpleCase:
    case_id: str
    red_mechanism: str
    blue_detection: str
    purple_correlation: str
    evidence_claim_ids: tuple[str, ...] = ()
    content_role: str = "UNTRUSTED_ATTACK_DATA"

    def __post_init__(self) -> None:
        if self.content_role != "UNTRUSTED_ATTACK_DATA":
            raise KnowledgeError("red-team content cannot become executable authority")
        if not self.red_mechanism or not self.blue_detection or not self.purple_correlation:
            raise KnowledgeError("red, blue, and purple fields are required")


class LearningStage(str, Enum):
    CURRENT_SKILL = "CURRENT_SKILL"
    PREREQUISITES = "PREREQUISITES"
    LESSON = "LESSON"
    EXAMPLE = "EXAMPLE"
    QUESTION = "QUESTION"
    ASSESSMENT = "ASSESSMENT"
    WEAKNESS = "WEAKNESS"
    NEXT_LESSON = "NEXT_LESSON"


@dataclass(frozen=True)
class LearningPlan:
    topic: str
    current_skill: str
    prerequisites: tuple[str, ...]
    lesson: str
    example: str
    question: str
    assessment: str
    weakness: str
    next_lesson: str
    content_role: str = "ANALYTIC_CASE"

    def __post_init__(self) -> None:
        if not self.topic or not self.current_skill or not self.lesson:
            raise KnowledgeError("learning plan requires topic, current skill, and lesson")
        if self.content_role not in {"ANALYTIC_CASE", "TRAINING_EXAMPLE"}:
            raise KnowledgeError("learning content must remain non-authoritative")
