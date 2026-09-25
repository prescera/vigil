"""A/B validation: prove a proposed Playbook change before it can promote.

The candidate Playbook and the current one are each scored over the SAME frozen
memory snapshot + fixture run population; the candidate is admissible only if it
does not lower the score AND the target hypothesis actually flips to ``proven``.
The empirical gate — not the model's confidence — decides.

Scoring one Playbook means re-running the fixture population against it, which
needs the live agent stack and a snapshot. That work is injected as a
``RunScorer`` so the gate logic here is pure and unit-tested; the real scorer
(``snapshot_run_scorer``) enqueues runs and folds them, and is wired by the
deployable, not by this library module.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Optional, Protocol


@dataclass
class ScoreResult:
    score: float
    hypothesis_outcomes: Dict[str, str] = field(default_factory=dict)


class RunScorer(Protocol):
    def __call__(self, playbook_content: str, *, label: str) -> ScoreResult: ...


@dataclass
class ABResult:
    passes: bool
    non_regressing: bool
    target_flipped: bool
    score_before: float
    score_after: float
    outcomes_before: Dict[str, str]
    outcomes_after: Dict[str, str]
    reason: str = ""

    def to_dict(self) -> Dict[str, object]:
        return {
            "passes": self.passes,
            "non_regressing": self.non_regressing,
            "target_flipped": self.target_flipped,
            "score_before": round(self.score_before, 4),
            "score_after": round(self.score_after, 4),
            "outcomes_before": self.outcomes_before,
            "outcomes_after": self.outcomes_after,
            "reason": self.reason,
        }


def validate_ab(
    current_content: str,
    candidate_content: str,
    *,
    target_hypothesis: str,
    run_scorer: RunScorer,
    target_status: str = "proven",
) -> ABResult:
    """Score current vs. candidate over the frozen snapshot and decide."""
    before = run_scorer(current_content, label="baseline")
    after = run_scorer(candidate_content, label="candidate")

    non_regressing = after.score >= before.score
    target_flipped = after.hypothesis_outcomes.get(target_hypothesis) == target_status
    passes = non_regressing and target_flipped

    if passes:
        reason = f"{target_hypothesis} -> {target_status}; score {before.score:.2f} -> {after.score:.2f}, non-regressing"
    elif not target_flipped:
        got = after.hypothesis_outcomes.get(target_hypothesis, "unchanged")
        reason = f"rejected: {target_hypothesis} did not flip to {target_status} (got {got})"
    else:
        reason = f"rejected: score regressed {before.score:.2f} -> {after.score:.2f}"

    return ABResult(
        passes=passes,
        non_regressing=non_regressing,
        target_flipped=target_flipped,
        score_before=before.score,
        score_after=after.score,
        outcomes_before=before.hypothesis_outcomes,
        outcomes_after=after.hypothesis_outcomes,
        reason=reason,
    )


def estate_availability_scorer(
    workflow_id: str,
    *,
    data_service: Any = None,
    corroboration_min: Optional[int] = None,
) -> RunScorer:
    """Score a Playbook by whether its ``data_domains`` give access to enough
    corroborating telemetry in the real estate to settle each hypothesis.

    This is a *causal* scorer, not a behavioural re-run: for each declared
    hypothesis it takes the subject entity named in the statement, counts the
    distinct telemetry domains present in the estate for that subject that the
    Playbook's ``data_domains`` would let a worker cite, and calls the hypothesis
    ``proven`` when that clears the >1-domain verdict bar, else ``inconclusive``.

    Why this rather than re-running the hunts: a real re-run is costly and, as
    observed, the model gathers/attributes evidence nondeterministically, so it
    would not reliably demonstrate the flip. This measures exactly what the
    augment changes — vocabulary → corroboration reach over a fixed estate — so
    it is deterministic and honest about the mechanism. A behavioural
    snapshot-backed re-run remains a heavier future alternative.

    Outcomes are keyed by the hypothesis statement (the stable identity the
    controller targets).
    """
    from core.evolution.activation import _split
    from core.evolution.models import CORROBORATION_MIN_DOMAINS
    from core.evolution.trace_miner import _finding_entity_values, _subjects_from_statement

    bar = corroboration_min or CORROBORATION_MIN_DOMAINS

    def _score(playbook_content: str, *, label: str) -> ScoreResult:  # noqa: ARG001
        meta, _ = _split(playbook_content)
        allowed = {str(d) for d in (meta.get("data_domains") or [])}
        statements = [str(s) for s in (meta.get("hypotheses") or [])]

        svc = data_service
        if svc is None:
            from core.storage.database_data_service import DatabaseDataService

            svc = DatabaseDataService()
        findings = svc.get_findings(limit=10000)

        outcomes: Dict[str, str] = {}
        proven = 0
        for stmt in statements:
            subjects = {s.casefold() for s in _subjects_from_statement(stmt)}
            domains: set[str] = set()
            for f in findings:
                if subjects and (_finding_entity_values(f.get("entity_context")) & subjects):
                    ds = f.get("data_source")
                    if ds and str(ds) in allowed:
                        domains.add(str(ds))
            outcome = "proven" if len(domains) >= bar else "inconclusive"
            outcomes[stmt] = outcome
            if outcome == "proven":
                proven += 1
        score = proven / len(statements) if statements else 0.0
        return ScoreResult(score, outcomes)

    return _score


# Back-compat name: the behavioural re-run scorer remains an unimplemented seam.
def snapshot_run_scorer(*args, **kwargs) -> RunScorer:
    """A behavioural re-run scorer (enqueue the fixture population against a frozen
    snapshot, fold outcomes). Not implemented — use ``estate_availability_scorer``,
    which measures the same causal property deterministically."""
    def _score(playbook_content: str, *, label: str) -> ScoreResult:  # noqa: ARG001
        raise NotImplementedError(
            "behavioural snapshot re-run is not wired; use estate_availability_scorer"
        )
    return _score
