"""Propose the concrete Playbook change that closes a detected gap.

For a domain-coverage gap the proposal is deterministic from the probe: add the
present-but-uncited domains to ``data_domains`` and append a staging-check phase
so a worker is told to go corroborate there. The *which domains* came from the
probe (a real read of the estate); the model's job was to detect and name the
failure, not to invent the edit — so this stays grounded rather than freeform.

A richer, LLM-authored proposal (via ``core.workflows.workflow_ai_generator``) is
a later extension for failure classes whose fix is not a vocabulary gap.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from core.evolution.models import ProbeResult


@dataclass
class ProposedChange:
    """A candidate Playbook edit, in the shape ``activation.apply_playbook_edit``
    consumes, plus a human-readable rationale for the diff view."""

    add_data_domains: List[str] = field(default_factory=list)
    add_phases: List[Dict[str, Any]] = field(default_factory=list)
    rationale: str = ""

    @property
    def is_empty(self) -> bool:
        return not self.add_data_domains and not self.add_phases

    def to_dict(self) -> Dict[str, Any]:
        return {
            "add_data_domains": self.add_data_domains,
            "add_phases": self.add_phases,
            "rationale": self.rationale,
        }


def _staging_phase(hypothesis_id: str, domains: List[str]) -> Dict[str, Any]:
    return {
        "phase_id": "staging-check",
        "agent_id": "threat_hunter",
        "name": "Staging check",
        "purpose": (
            "corroborate exfil staging on the subject host using the newly "
            f"in-vocabulary domains ({', '.join(domains)})"
        ),
        "tools": ["findings_search", "telemetry_search"],
    }


def propose_domain_augment(
    hypothesis_id: str,
    probe: ProbeResult,
    *,
    with_phase: bool = True,
) -> ProposedChange:
    """Turn the probe's present-but-uncited domains into a data_domains augment."""
    domains = sorted(probe.present_but_uncited_domains)
    if not domains:
        return ProposedChange(rationale="no uncited domains found; nothing to add")
    phases = [_staging_phase(hypothesis_id, domains)] if with_phase else []
    return ProposedChange(
        add_data_domains=domains,
        add_phases=phases,
        rationale=(
            f"{hypothesis_id} never crossed a second telemetry domain; the estate has "
            f"present-but-uncited evidence in {', '.join(domains)}, so add those to "
            "data_domains and a phase that goes and corroborates there"
        ),
    )
