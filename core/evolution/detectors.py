"""Tier-1 detector rules.

The cold-start set is **empty**: no failure-mode rule is hand-authored. Rules
enter Tier-1 only by crystallising a Tier-2 discovery that has survived the A/B
gate across several cycles (``core.evolution.controller`` codify-back). This
module holds the *shape* of that crystallisation and the canonical predicate the
demo's first discovery produces, so the codify-back path and the tests reference
one definition rather than restating it.

Rules are data (``DetectorRule``), stored via ``core.evolution.store`` and
hot-reloaded; nothing here is a Python branch a workflow is gated on.
"""

from __future__ import annotations

from typing import Any, Dict, List

from core.evolution.models import DetectorRule

# The predicate a Tier-2 "uncorroborated_domain_gap" finding proposes: a
# hypothesis that looked (gathered evidence) yet is chronically NOT proven, while
# the estate holds present-but-uncited evidence that could corroborate it.
#
# Re-anchored (2026-09) on signals a real hunt actually produces. The earlier
# version counted the run's distinct telemetry domains, but a run's evidence
# source_system is the model's own attribution from the playbook data_domains
# vocabulary — not the finding's data_source — so it does not separate cleanly by
# domain and could not carry the signal. "Rarely proven" (a real verdict outcome)
# plus the deterministic uncited-evidence probe do. ``proven_rate`` counts only the
# ``proven`` outcome, so a hypothesis that ends inconclusive, parked or
# cost-exhausted all read the same here: it did not prove.
UNCORROBORATED_DOMAIN_GAP_PREDICATE: Dict[str, Any] = {
    "all": [
        {"metric": "proven_rate", "op": "<=", "value": 0.2},
        {"metric": "probe.present_but_uncited_domains", "op": "nonempty"},
    ]
}
# NB: no ``looked_rate`` condition. The probe IS the discriminator between an
# augmentable domain gap and a true data-starve: probe-nonempty means evidence
# exists in the estate that the workflow could not cite, whether or not the hunt's
# own searches happened to gather anything. A probe-empty unproven hypothesis is
# routed to "data-starved" by the controller instead.


def crystallize(
    failure_class: str,
    predicate: Dict[str, Any],
    *,
    cycle_id: str,
    validated_cycles: int,
    then: Dict[str, Any] | None = None,
) -> DetectorRule:
    """Turn a validated Tier-2 discovery into a Tier-1 rule, carrying the
    provenance back to the discovery so the Detectors tab can show where it came
    from. The controller calls this once a discovery has survived the gate."""
    return DetectorRule(
        id=failure_class.replace("_", "-"),
        when=predicate,
        then=then or {"locate": "probe_uncited_evidence",
                      "propose": "add_uncited_domains_to_data_domains"},
        origin={
            "discovered_by": "blindspot_critic",
            "first_cycle": cycle_id,
            "validated_cycles": validated_cycles,
        },
        enabled=True,
    )


def cold_start_detectors() -> List[DetectorRule]:
    """The Tier-1 set before any discovery has crystallised: empty on purpose."""
    return []
