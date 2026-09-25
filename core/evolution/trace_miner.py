"""The trace miner: fold a workflow's finished-run population into descriptive
statistics, probe for evidence the runs could not cite, and evaluate the Tier-1
detector rules against the result.

Three concerns, each with a pure core that takes plain data so it is testable
without a live agent stack or database:

  * ``aggregate_stats``          — distil payloads → WorkflowStats  (pure)
  * ``probe_uncited_evidence``   — HypothesisStats + Findings → ProbeResult
  * ``evaluate_detectors``       — WorkflowStats + rules → DetectorFindings (pure)

and thin async/DB wrappers (``mine_workflow``, the ``get_findings`` call) that
feed the pure cores from the real interfaces. Read-only throughout: the miner
never writes to a run's ledger, and it reads run outcomes over the agent-layer
HTTP surface (``core.agents.projections.read_distil``) rather than folding a
second time here.
"""

from __future__ import annotations

import asyncio
import logging
import re
from datetime import datetime
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

from core.evolution.models import (
    CORROBORATION_MIN_DOMAINS,
    DetectorFinding,
    DetectorRule,
    HypothesisStats,
    ProbeResult,
    WorkflowStats,
    median,
)

logger = logging.getLogger(__name__)


# --------------------------------------------------------------------------- #
# Tier-1 aggregation (pure)
# --------------------------------------------------------------------------- #


class _HypothesisAccumulator:
    """Per-hypothesis running totals across the run population. Kept internal:
    the miner hands out the frozen ``HypothesisStats``, not this."""

    def __init__(self, hypothesis_id: str) -> None:
        self.hypothesis_id = hypothesis_id
        self.statement = ""
        self.techniques: List[str] = []
        self.run_count = 0
        self.outcomes: Dict[str, int] = {}
        self.looked_count = 0
        self.evidence_counts: List[float] = []
        # supporting-domain -> runs it supported in (for corroboration/display)
        self.supporting_domain_runs: Dict[str, int] = {}
        # every domain any run cited, any stance (for the probe to subtract)
        self.cited_domains_any: set[str] = set()
        self.max_distinct_domains_in_a_run = 0
        self.corroboration_met_count = 0
        self._subjects: "dict[Tuple[str, str], Dict[str, str]]" = {}
        self.first_seen: Optional[str] = None
        self.last_seen: Optional[str] = None

    def add(self, conclusion: Dict[str, Any]) -> None:
        self.run_count += 1
        if conclusion.get("statement") and not self.statement:
            self.statement = str(conclusion["statement"])
        for tech in conclusion.get("techniques") or []:
            if tech and tech not in self.techniques:
                self.techniques.append(str(tech))

        status = str(conclusion.get("status") or "unknown")
        self.outcomes[status] = self.outcomes.get(status, 0) + 1

        evidence_count = _as_int(conclusion.get("evidence_count"))
        self.evidence_counts.append(float(evidence_count))
        if evidence_count > 0:
            self.looked_count += 1

        sources = conclusion.get("sources") or []
        supporting: set[str] = set()
        for source in sources:
            if not isinstance(source, dict):
                continue
            system = source.get("source_system")
            if not system:
                continue
            system = str(system)
            self.cited_domains_any.add(system)
            # A missing stance defaults to "supports": an unlabelled citation
            # still names a domain the run reached, and undercounting here would
            # invent a corroboration gap that is not real.
            if str(source.get("stance", "supports")) == "supports":
                supporting.add(system)

        for system in supporting:
            self.supporting_domain_runs[system] = (
                self.supporting_domain_runs.get(system, 0) + 1
            )
        self.max_distinct_domains_in_a_run = max(
            self.max_distinct_domains_in_a_run, len(supporting)
        )
        if len(supporting) >= CORROBORATION_MIN_DOMAINS:
            self.corroboration_met_count += 1

        for subject in conclusion.get("subject_entities") or []:
            if not isinstance(subject, dict):
                continue
            key = (str(subject.get("type", "")), str(subject.get("value", "")))
            if key[1]:
                self._subjects.setdefault(key, {"type": key[0], "value": key[1]})

        self.first_seen = _min_iso(self.first_seen, conclusion.get("first_seen"))
        self.last_seen = _max_iso(self.last_seen, conclusion.get("last_seen"))

    def freeze(self) -> HypothesisStats:
        stats = HypothesisStats(
            hypothesis_id=self.hypothesis_id,
            statement=self.statement,
            techniques=self.techniques,
            run_count=self.run_count,
            outcomes=self.outcomes,
            looked_count=self.looked_count,
            evidence_count_median=median(self.evidence_counts),
            domains_cited=self.supporting_domain_runs,
            cited_domains_any=sorted(self.cited_domains_any),
            max_distinct_domains_in_a_run=self.max_distinct_domains_in_a_run,
            corroboration_met_count=self.corroboration_met_count,
            subject_entities=list(self._subjects.values()),
            first_seen=self.first_seen,
            last_seen=self.last_seen,
        )
        return stats


def aggregate_stats(
    workflow_id: str,
    distils: Sequence[Tuple[str, Dict[str, Any]]],
    *,
    data_domains: Optional[List[str]] = None,
) -> WorkflowStats:
    """Fold ``(run_id, distil_payload)`` pairs into a WorkflowStats. Pure — the
    caller supplies the payloads, so this is exercised directly in tests."""

    # Key on the STATEMENT, not the hypothesis_id: a hunt mints a fresh random
    # hypothesis_id every run, so the same declared claim carries a different id
    # each time. The statement is what the playbook declares and is stable across
    # the population — the only thing the miner can aggregate a hypothesis on.
    accumulators: "dict[str, _HypothesisAccumulator]" = {}
    for _run_id, payload in distils:
        if not isinstance(payload, dict):
            continue
        for conclusion in payload.get("conclusions") or []:
            if not isinstance(conclusion, dict):
                continue
            statement = (conclusion.get("statement") or "").strip()
            key = statement or str(conclusion.get("hypothesis_id") or "")
            if not key:
                continue
            acc = accumulators.get(key)
            if acc is None:
                # Representative id for display: the first run's id for this claim.
                rep_id = str(conclusion.get("hypothesis_id") or key)
                acc = accumulators[key] = _HypothesisAccumulator(rep_id)
            acc.add(conclusion)

    hypotheses = [acc.freeze() for acc in accumulators.values()]
    window = _population_window(hypotheses)
    return WorkflowStats(
        workflow_id=workflow_id,
        run_count=len(distils),
        window=window,
        data_domains=data_domains,
        hypotheses=hypotheses,
    )


async def mine_workflow(
    workflow_id: str,
    *,
    status: Optional[str] = None,
    limit: int = 200,
    data_domains: Optional[List[str]] = None,
    runs_service: Any = None,
) -> WorkflowStats:
    """Enumerate a workflow's finished runs, read each run's distil over the
    agent-layer HTTP surface, and aggregate. The async/IO wrapper around the
    pure ``aggregate_stats``."""

    from core.agents.projections import read_distil
    from core.workflows.workflow_run_service import WorkflowRunService

    svc = runs_service or WorkflowRunService()
    # Fold any run that produced a distil, not only status="completed": a hunt that
    # parks (e.g. cost-exhausted) never flips to "completed" but has a readable
    # distil with usable conclusions, and its hypotheses' outcomes are exactly the
    # signal the miner is after. ``status=None`` takes them all; runs with no distil
    # yet (still early) simply drop out below.
    runs = svc.list_runs(workflow_id=workflow_id, status=status, limit=limit)
    if not runs:
        return WorkflowStats(workflow_id=workflow_id, run_count=0, data_domains=data_domains)

    payloads = await asyncio.gather(
        *(read_distil(run["run_id"]) for run in runs), return_exceptions=True
    )
    distils: List[Tuple[str, Dict[str, Any]]] = []
    for run, payload in zip(runs, payloads):
        if isinstance(payload, dict):
            distils.append((run["run_id"], payload))
        elif isinstance(payload, Exception):
            logger.warning("distil read failed for %s: %r", run["run_id"], payload)
    return aggregate_stats(workflow_id, distils, data_domains=data_domains)


# --------------------------------------------------------------------------- #
# Locate: the uncited-evidence probe
# --------------------------------------------------------------------------- #


def _finding_entity_values(entity_context: Any) -> set[str]:
    """Casefolded host/ip/user values on a Finding, spanning the singular and
    plural spellings the estate uses (mirrors reconstruction's join)."""
    values: set[str] = set()
    if not isinstance(entity_context, dict):
        return values
    plural = ("hostnames", "src_ips", "ips", "users", "usernames")
    singular = ("hostname", "host", "computer_name", "src_ip", "ip", "user", "username")
    for key in plural:
        for item in entity_context.get(key) or []:
            if item:
                values.add(str(item).strip().casefold())
    for key in singular:
        item = entity_context.get(key)
        if item:
            values.add(str(item).strip().casefold())
    return values


def uncited_domains(
    findings: Iterable[Dict[str, Any]],
    subject_values: Iterable[str],
    allowed_domains: Iterable[str],
) -> Dict[str, int]:
    """Pure core: of ``findings`` that mention one of ``subject_values``, count by
    ``data_source`` those whose domain is NOT in ``allowed_domains`` — i.e. present
    in the estate but outside what the workflow could cite. Testable directly."""
    wanted = {str(v).strip().casefold() for v in subject_values if v}
    cited = {str(d) for d in allowed_domains}
    counts: Dict[str, int] = {}
    for finding in findings:
        if not isinstance(finding, dict):
            continue
        if wanted and not (_finding_entity_values(finding.get("entity_context")) & wanted):
            continue
        domain = finding.get("data_source")
        if not domain or str(domain) in cited:
            continue
        counts[str(domain)] = counts.get(str(domain), 0) + 1
    return counts


def probe_uncited_evidence(
    hypothesis: HypothesisStats,
    *,
    data_service: Any = None,
    data_domains: Optional[List[str]] = None,
    finding_limit: int = 10000,
) -> ProbeResult:
    """Locate the missing capability: query raw Findings for the hypothesis's
    subject entities + window (the miner is a backend job, so it is NOT scoped by
    the workflow's data_domains), and return the domains present in the estate
    that no run cited. Mirrors ``core.memory.hunt_coverage``, inverted."""

    from core.storage.database_data_service import DatabaseDataService

    svc = data_service or DatabaseDataService()
    # No time window: the probe asks "does uncited evidence for this entity exist
    # in the estate at all?", so bounding it to the run's own window would miss
    # evidence outside it (and a run that gathered nothing falls back to its own
    # dates, which would exclude everything). Entity match is the filter.
    findings = svc.get_findings(limit=finding_limit)
    subject_values = [s.get("value") for s in hypothesis.subject_entities if s.get("value")]
    subject_display = [
        f"{s.get('type')}:{s.get('value')}" for s in hypothesis.subject_entities if s.get("value")
    ]
    # A real hunt often records no subject_entities on a declared hypothesis, so
    # fall back to entity-shaped tokens named in the statement itself
    # ("...exfiltrated from fin-db-02..."). Without a subject the probe has nothing
    # to scope to and comes back empty on an otherwise real gap.
    if not subject_values:
        subject_values = _subjects_from_statement(hypothesis.statement)
        subject_display = [f"host:{v}" for v in subject_values]
    # "Uncitable" means the domain is OUTSIDE the workflow's data_domains — evidence
    # a worker's source_system citation is refused for at spec build — not merely a
    # domain this run did not happen to cite. So subtract the workflow vocabulary.
    # Falls back to what the runs cited only when data_domains is unknown.
    allowed = data_domains if data_domains is not None else (
        hypothesis.cited_domains_any or list(hypothesis.domains_cited)
    )
    counts = uncited_domains(findings, subject_values, allowed)
    return ProbeResult(
        hypothesis_id=hypothesis.hypothesis_id,
        subject_entities=subject_display,
        present_but_uncited_domains=counts,
    )


# Host/user-shaped tokens a hypothesis statement names, used only when the run
# recorded no subject_entities. Matches conventions like fin-db-02, fin-app-02,
# svc-payroll, dc01 — deliberately narrow so prose words are not mistaken for
# entities. A token only matters if it also names a Finding, which uncited_domains
# enforces by intersecting with the estate.
_ENTITY_TOKEN = re.compile(r"\b(?:[a-z]{2,}-[a-z]{2,}-?\d+|[a-z]{2,}-[a-z0-9]{3,}|[a-z]{2,}\d{2,})\b", re.I)


def _subjects_from_statement(statement: str) -> List[str]:
    if not statement:
        return []
    seen: List[str] = []
    for tok in _ENTITY_TOKEN.findall(statement):
        t = tok.strip().casefold()
        if t and t not in seen:
            seen.append(t)
    return seen


# --------------------------------------------------------------------------- #
# Tier-1 detector evaluation (pure)
# --------------------------------------------------------------------------- #


def _resolve_metric(
    name: str, hypothesis: HypothesisStats, probe: Optional[ProbeResult]
) -> Any:
    if name.startswith("probe."):
        if probe is None:
            return None
        field_name = name.split(".", 1)[1]
        return getattr(probe, field_name, None)
    return hypothesis.metric(name)


def _test_condition(
    cond: Dict[str, Any], hypothesis: HypothesisStats, probe: Optional[ProbeResult]
) -> bool:
    metric = _resolve_metric(str(cond.get("metric")), hypothesis, probe)
    op = str(cond.get("op"))
    if op == "nonempty":
        return bool(metric)
    if op == "empty":
        return not metric
    if metric is None:
        return False
    value = cond.get("value")
    ops = {
        ">=": lambda a, b: a >= b,
        "<=": lambda a, b: a <= b,
        ">": lambda a, b: a > b,
        "<": lambda a, b: a < b,
        "==": lambda a, b: a == b,
        "!=": lambda a, b: a != b,
    }
    fn = ops.get(op)
    if fn is None:
        raise ValueError(f"unknown predicate op: {op}")
    return bool(fn(metric, value))


def _test_predicate(
    when: Dict[str, Any], hypothesis: HypothesisStats, probe: Optional[ProbeResult]
) -> bool:
    if "all" in when:
        return all(_test_condition(c, hypothesis, probe) for c in when["all"])
    if "any" in when:
        return any(_test_condition(c, hypothesis, probe) for c in when["any"])
    # a bare single condition
    return _test_condition(when, hypothesis, probe)


def evaluate_detectors(
    stats: WorkflowStats,
    rules: Sequence[DetectorRule],
    probes: Optional[Dict[str, ProbeResult]] = None,
) -> List[DetectorFinding]:
    """Run every enabled Tier-1 rule against every hypothesis; return the ones
    that fire. Pure — the caller supplies stats, rules and any probe results."""
    probes = probes or {}
    findings: List[DetectorFinding] = []
    for rule in rules:
        if not rule.enabled:
            continue
        when = rule.when or {}
        for hyp in stats.hypotheses:
            # Keyed on statement, the stable hypothesis identity across runs.
            probe = probes.get(hyp.statement) or probes.get(hyp.hypothesis_id)
            if not _test_predicate(when, hyp, probe):
                continue
            findings.append(
                DetectorFinding(
                    rule_id=rule.id,
                    workflow_id=stats.workflow_id,
                    hypothesis_id=hyp.hypothesis_id,
                    statement=hyp.statement,
                    reason=_finding_reason(rule, hyp, probe),
                    stat_refs={
                        "inconclusive_rate": round(hyp.inconclusive_rate, 3),
                        "looked_rate": round(hyp.looked_rate, 3),
                        "corroboration_met_rate": round(hyp.corroboration_met_rate, 3),
                        "max_distinct_domains_in_a_run": hyp.max_distinct_domains_in_a_run,
                        "present_but_uncited_domains": (
                            probe.present_but_uncited_domains if probe else {}
                        ),
                    },
                    origin=dict(rule.origin),
                )
            )
    return findings


def _finding_reason(
    rule: DetectorRule, hyp: HypothesisStats, probe: Optional[ProbeResult]
) -> str:
    bits = [
        f"{hyp.hypothesis_id} matched detector '{rule.id}'",
        f"inconclusive {hyp.inconclusive_rate:.0%}",
        f"looked {hyp.looked_rate:.0%}",
        f"max domains cited {hyp.max_distinct_domains_in_a_run}",
    ]
    if probe and probe.present_but_uncited_domains:
        present = ", ".join(sorted(probe.present_but_uncited_domains))
        bits.append(f"present-but-uncited: {present}")
    return "; ".join(bits)


# --------------------------------------------------------------------------- #
# small helpers
# --------------------------------------------------------------------------- #


def _as_int(value: Any) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def _parse_iso(value: Any) -> Optional[datetime]:
    if not value or not isinstance(value, str):
        return None
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is not None:
        parsed = parsed.astimezone().replace(tzinfo=None)
    return parsed


def _min_iso(current: Optional[str], candidate: Any) -> Optional[str]:
    if not candidate or not isinstance(candidate, str):
        return current
    if current is None or candidate < current:
        return candidate
    return current


def _max_iso(current: Optional[str], candidate: Any) -> Optional[str]:
    if not candidate or not isinstance(candidate, str):
        return current
    if current is None or candidate > current:
        return candidate
    return current


def _population_window(
    hypotheses: Sequence[HypothesisStats],
) -> Optional[Tuple[str, str]]:
    firsts = [h.first_seen for h in hypotheses if h.first_seen]
    lasts = [h.last_seen for h in hypotheses if h.last_seen]
    if not firsts or not lasts:
        return None
    return (min(firsts), max(lasts))
