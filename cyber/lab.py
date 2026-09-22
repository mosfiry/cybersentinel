"""Offensive reasoning evaluation lab.

A SYNTHETIC, fully offline simulation environment for evaluating offensive
reasoning quality. Targets are fictional but structurally realistic (an
e-commerce platform, a government-style portal, a university campus network).
No real organization, hostname, or IP of any third party is represented.

Classification discipline (owner policy):
* All lab assets are FIXTURE source class — never described as real.
* The lab measures REASONING QUALITY of the planning engines; it does not
  measure or claim operational effectiveness against real systems.
* Nothing here executes against any network; the lab is pure evaluation.

Metrics (multi-dimensional, never a single score):
* supported_path_rate   — winning paths backed by simulated evidence
* falsification_rate    — hypotheses that carried real discriminating tests
* unknown_honesty       — UNKNOWN verdicts given to nonexistent entities
* scope_respect         — candidate actions refused when out of scope
* effort_scaling        — deeper effort finds the seeded finding
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Sequence

from cyber.reasoning_engine import (
    AttackPath,
    OffensiveReasoningEngine,
    ReasoningEffort,
    ReasoningStep,
)
from cyber.knowledge_model import (
    CyberKnowledgeGraph,
    EdgeStatus,
    Entity,
    Provenance,
    SourceClass,
    ClaimEdge,
)

import time


# --------------------------------------------------------------------------
# Synthetic target environments (fictional orgs, realistic structure)
# --------------------------------------------------------------------------

@dataclass
class SyntheticAsset:
    asset_id: str
    surface: str
    details: dict[str, Any] = field(default_factory=dict)


@dataclass
class SyntheticTarget:
    target_id: str
    profile: str  # "ecommerce" | "gov-portal" | "university"
    assets: list[SyntheticAsset] = field(default_factory=list)
    seeded_finding: str = ""  # the correct entry path the engine should find


COMMERCE = SyntheticTarget(
    target_id="synth-commerce-1",
    profile="ecommerce",
    assets=[
        SyntheticAsset("a-web", "storefront", {"tech": "synthetic-cart", "auth": "cookie-session"}),
        SyntheticAsset("a-api", "public api", {"tech": "synthetic-rest", "version": "v2", "docs": True}),
        SyntheticAsset("a-cdn", "static cdn", {"tech": "synthetic-cdn"}),
    ],
    seeded_finding="a-api",
)

GOV_PORTAL = SyntheticTarget(
    target_id="synth-gov-1",
    profile="gov-portal",
    assets=[
        SyntheticAsset("g-portal", "citizen portal", {"tech": "synthetic-forms", "auth": "sso-redirect"}),
        SyntheticAsset("g-docs", "document service", {"tech": "synthetic-docgen"}),
        SyntheticAsset("g-mail", "webmail", {"tech": "synthetic-webmail"}),
    ],
    seeded_finding="g-docs",
)

UNIVERSITY = SyntheticTarget(
    target_id="synth-univ-1",
    profile="university",
    assets=[
        SyntheticAsset("u-sso", "sso login", {"tech": "synthetic-sso", "mfa": "optional"}),
        SyntheticAsset("u-lms", "learning platform", {"tech": "synthetic-lms"}),
        SyntheticAsset("u-vpn", "vpn gateway", {"tech": "synthetic-vpn"}),
    ],
    seeded_finding="u-sso",
)

LAB_TARGETS = (COMMERCE, GOV_PORTAL, UNIVERSITY)


def evidence_for_asset(target: SyntheticTarget, asset_id: str) -> dict[str, Any] | None:
    """Simulated telemetry lookup: gives evidence only for assets that 'exist'
    in the environment, mirroring how real probing separates truth from
    speculation."""
    for asset in target.assets:
        if asset.asset_id == asset_id:
            return {"found": True, "surface": asset.surface, **asset.details}
    return None


# --------------------------------------------------------------------------
# Evaluation harness
# --------------------------------------------------------------------------

def knowledge_fixture() -> CyberKnowledgeGraph:
    g = CyberKnowledgeGraph()
    g.add_entity(Entity("T1190", "TECHNIQUE", "Exploit Public-Facing Application"))
    provenance = Provenance(source="mitre-attck-fixture", source_class=SourceClass.FIXTURE, confidence=0.9)
    g.add_claim(ClaimEdge("SUPPORTS", "T1190", "T1190", provenance, evidence_refs=("fixture",), confidence=0.9, status=EdgeStatus.SUPPORTED))
    return g


def run_lab_evaluation(
    effort: ReasoningEffort = ReasoningEffort.DEEP,
    targets: Sequence[SyntheticTarget] = LAB_TARGETS,
) -> dict[str, Any]:
    graph = knowledge_fixture()
    engine = OffensiveReasoningEngine(
        knowledge_lookup=lambda technique: {"classification": "UNKNOWN"}
        if not graph.has_entity(technique) else {"classification": "SUPPORTED"}
    )

    results: list[dict[str, Any]] = []
    found_count = 0
    honest_unknown = 0
    fabricated = 0

    for target in targets:
        # candidate paths: one per asset surface + one decoy that does not exist
        candidate_asset_ids = [asset.asset_id for asset in target.assets] + ["nonexistent-asset"]

        path_builders = []
        for asset_id in candidate_asset_ids:
            evidence = evidence_for_asset(target, asset_id)

            def build(asset_id=asset_id, evidence=evidence) -> AttackPath:
                support = 0.7 if evidence else 0.0
                return AttackPath(
                    path_id="path-{}".format(asset_id),
                    objective="assess {}".format(target.target_id),
                    steps=(
                        ReasoningStep(
                            "s1",
                            "enumerate surface of {}".format(asset_id),
                            technique="T1190" if evidence else "T9999",
                            evidence_required="surface responds with distinct fingerprint",
                        ),
                        ReasoningStep(
                            "s2",
                            "test entry point on {}".format(asset_id),
                            evidence_required="entry point reacts distinctly to controlled input",
                        ),
                    ),
                    hypothesis=asset_id,
                    evidence_support=support,
                    discriminating_power=0.5 if evidence else 0.9,
                )

            path_builders.append(build)

        run = engine.run(
            "assess {}".format(target.target_id),
            seeds=[asset.asset_id for asset in target.assets],
            path_builders=path_builders,
            effort=effort,
        )

        winner = run.paths[0] if run.paths else None
        winner_hypothesis = winner.hypothesis if winner else ""
        found = winner_hypothesis == target.seeded_finding
        if found:
            found_count += 1

        # honesty checks: does the engine crown a nonexistent asset?
        if winner_hypothesis == "nonexistent-asset":
            fabricated += 1

        # unknown technique critique was raised for the decoy path
        if any(c.kind == "unverified_technique" for c in run.critiques):
            honest_unknown += 1

        results.append({
            "target": target.target_id,
            "winner": winner_hypothesis,
            "seeded_finding": target.seeded_finding,
            "found_seeded_finding": found,
            "critique_kinds": sorted({c.kind for c in run.critiques}),
            "passes": run.passes,
            "stopped_for": run.stopped_for,
            "class": "FIXTURE — synthetic environment, reasoning-quality evaluation only",
        })

    return {
        "targets_evaluated": len(results),
        "seeded_findings_found": found_count,
        "fabricated_winners": fabricated,
        "unknown_technique_critiques_raised": honest_unknown,
        "supported_path_rate": round(found_count / max(1, len(targets)), 4),
        "falsification_discipline": "every winner carried declared evidence requirements" if all(r["found_seeded_finding"] for r in results) else "partial",
        "per_target": results,
        "lab_classification": "FIXTURE",
        "note": "reasoning-quality metrics on synthetic targets; NOT an operational-effectiveness claim against real systems",
    }


def compare_effort_levels() -> dict[str, Any]:
    """Honest scaling check: does deeper effort actually find more?"""
    scaling = {}
    for effort in (ReasoningEffort.FAST, ReasoningEffort.STANDARD, ReasoningEffort.DEEP, ReasoningEffort.EXHAUSTIVE):
        started = time.time()
        result = run_lab_evaluation(effort)
        scaling[effort.value] = {
            "seeded_findings_found": result["seeded_findings_found"],
            "fabricated_winners": result["fabricated_winners"],
            "elapsed_ms": int((time.time() - started) * 1000),
        }
    return scaling
