"""Data types for workflow self-evolution.

Plain dataclasses, not ORM rows: these are the *computed* shapes the miner,
detectors and critic pass around. Persistence lives in ``core.evolution.store``
and the ORM models; what is here is folded from run outcomes on read and never
stored beside them, the same discipline the agent-layer projection keeps.

A telemetry **domain** here is a Finding's ``data_source`` (there is no
``source_system`` on a Finding) and, symmetrically, a distil conclusion's
``sources[].source_system``. The two are the same vocabulary read from the two
sides, which is what lets the probe compare "what the estate has" against "what
the run cited".
"""

from __future__ import annotations

import statistics
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

# The corroboration bar the hunt verdict gate enforces: a hypothesis reaches
# proven only on supporting evidence from MORE THAN ONE telemetry domain. The
# miner does not re-implement the gate; it counts against the same threshold so
# "domain short" means the same thing here as it does to the run.
CORROBORATION_MIN_DOMAINS = 2

# A distil conclusion status counts as "looked" only through evidence_count; the
# status alone cannot separate an inconclusive that gathered evidence from one
# that never did (that is the whole point of the distil carrying the count).
INCONCLUSIVE = "inconclusive"


@dataclass
class HypothesisStats:
    """Everything the miner learned about one declared hypothesis across a
    workflow's run population. All rates are derived from the raw counts so a
    detector predicate reads the same number the analyst is shown."""

    hypothesis_id: str
    statement: str
    techniques: List[str]
    run_count: int
    # status -> number of runs that closed the hypothesis that way.
    outcomes: Dict[str, int] = field(default_factory=dict)
    # runs where evidence_count > 0 ("looked"), vs. the population.
    looked_count: int = 0
    evidence_count_median: float = 0.0
    # supporting telemetry domain -> number of runs it supported in.
    domains_cited: Dict[str, int] = field(default_factory=dict)
    # every domain the runs cited with any stance — what the probe subtracts.
    cited_domains_any: List[str] = field(default_factory=list)
    # the best any single run achieved: max distinct supporting domains.
    max_distinct_domains_in_a_run: int = 0
    # runs that cleared CORROBORATION_MIN_DOMAINS.
    corroboration_met_count: int = 0
    # union of subject entities the runs named, as {"type":..,"value":..} dicts;
    # the probe reads these to know what to look for uncited evidence about.
    subject_entities: List[Dict[str, str]] = field(default_factory=list)
    # windows the runs observed, used to bound the probe's Findings read.
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None

    # -- derived rates (kept as properties so the raw counts stay the source) --
    @property
    def inconclusive_rate(self) -> float:
        return self._rate(self.outcomes.get(INCONCLUSIVE, 0))

    @property
    def proven_rate(self) -> float:
        return self._rate(self.outcomes.get("proven", 0))

    @property
    def looked_rate(self) -> float:
        return self._rate(self.looked_count)

    @property
    def corroboration_met_rate(self) -> float:
        return self._rate(self.corroboration_met_count)

    def _rate(self, numerator: int) -> float:
        return (numerator / self.run_count) if self.run_count else 0.0

    def metric(self, name: str) -> Any:
        """Resolve a detector-predicate metric name to its value. Names match the
        stored DetectorRule predicates so a rule is data, not code."""
        simple = {
            "inconclusive_rate": self.inconclusive_rate,
            "proven_rate": self.proven_rate,
            "looked_rate": self.looked_rate,
            "corroboration_met_rate": self.corroboration_met_rate,
            "max_distinct_domains_in_a_run": self.max_distinct_domains_in_a_run,
            "run_count": self.run_count,
        }
        if name in simple:
            return simple[name]
        raise KeyError(f"unknown metric: {name}")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "hypothesis_id": self.hypothesis_id,
            "statement": self.statement,
            "technique": self.techniques[0] if self.techniques else None,
            "techniques": list(self.techniques),
            "run_count": self.run_count,
            "outcomes": dict(self.outcomes),
            "looked_rate": round(self.looked_rate, 3),
            "evidence_count_median": self.evidence_count_median,
            "domains_cited_union": sorted(self.domains_cited),
            "max_distinct_domains_in_a_run": self.max_distinct_domains_in_a_run,
            "corroboration_met_rate": round(self.corroboration_met_rate, 3),
            "subject_entities": list(self.subject_entities),
        }


@dataclass
class WorkflowStats:
    """The descriptive fold over one workflow's run population — generic, no
    theory of failure baked in. Tier-1 detectors and the Tier-2 critic both read
    this; it is the substrate, not a diagnosis."""

    workflow_id: str
    run_count: int
    window: Optional[Tuple[str, str]] = None
    # the workflow's declared telemetry vocabulary if known (hunt playbooks carry
    # one); None when the source does not expose it.
    data_domains: Optional[List[str]] = None
    hypotheses: List[HypothesisStats] = field(default_factory=list)

    def hypothesis(self, hypothesis_id: str) -> Optional[HypothesisStats]:
        return next(
            (h for h in self.hypotheses if h.hypothesis_id == hypothesis_id), None
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "workflow_id": self.workflow_id,
            "run_count": self.run_count,
            "window": list(self.window) if self.window else None,
            "data_domains": self.data_domains,
            "hypotheses": [h.to_dict() for h in self.hypotheses],
        }


@dataclass
class ProbeResult:
    """What ``probe_uncited_evidence`` found: telemetry domains present in the
    estate for a hypothesis's subjects/window that no run could cite (because they
    were outside the workflow's vocabulary). The concrete input to an augment."""

    hypothesis_id: str
    subject_entities: List[str]
    present_but_uncited_domains: Dict[str, int] = field(default_factory=dict)

    @property
    def has_uncited(self) -> bool:
        return bool(self.present_but_uncited_domains)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "hypothesis_id": self.hypothesis_id,
            "subject_entities": list(self.subject_entities),
            "present_but_uncited_domains": dict(self.present_but_uncited_domains),
        }


@dataclass
class DetectorRule:
    """A Tier-1 detector — data, not code, so it hot-reloads and carries the
    provenance of the Tier-2 discovery it crystallised from. ``when`` is a
    predicate over HypothesisStats metrics (+ the probe); ``then`` names the
    locate/propose handlers the controller runs when it fires."""

    id: str
    when: Dict[str, Any]
    then: Dict[str, Any] = field(default_factory=dict)
    origin: Dict[str, Any] = field(default_factory=dict)
    enabled: bool = True

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "when": self.when,
            "then": self.then,
            "origin": self.origin,
            "enabled": self.enabled,
        }

    @classmethod
    def from_dict(cls, raw: Dict[str, Any]) -> "DetectorRule":
        return cls(
            id=str(raw["id"]),
            when=dict(raw.get("when") or {}),
            then=dict(raw.get("then") or {}),
            origin=dict(raw.get("origin") or {}),
            enabled=bool(raw.get("enabled", True)),
        )


@dataclass
class DetectorFinding:
    """One detector firing on one hypothesis — the deterministic diagnosis the
    controller carries into locate → propose → prove."""

    rule_id: str
    workflow_id: str
    hypothesis_id: str
    reason: str
    statement: str = ""
    stat_refs: Dict[str, Any] = field(default_factory=dict)
    origin: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "workflow_id": self.workflow_id,
            "hypothesis_id": self.hypothesis_id,
            "statement": self.statement,
            "reason": self.reason,
            "stat_refs": self.stat_refs,
            "origin": self.origin,
        }


def median(values: List[float]) -> float:
    """Median with an empty-safe 0.0, so a hypothesis nobody looked at does not
    raise on the way to being reported as looked_rate 0."""
    return float(statistics.median(values)) if values else 0.0
