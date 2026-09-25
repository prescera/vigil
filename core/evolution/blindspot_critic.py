"""Tier-2 detection: a model completeness-critic over a workflow's statistics.

Runs only over the statistical outliers Tier-1 did not already claim, and asks
"what recurring failure did the rules miss?" It catches what no metric threshold
can (proven-for-wrong-reason, early-abandon, an unproductive phase). Because
detection is the confabulation-prone step, three guardrails are enforced *here*,
not left to the prompt: every finding must cite run ids, must recur across
``min_recurrence`` runs, and is deduped against the Tier-1 rules by the caller.

The model call is one-shot ``ClaudeService.chat`` with a strict-JSON instruction
(there is no JSON mode); the parse is defensive. Injectable ``claude`` for tests.
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from core.evolution.models import ProbeResult, WorkflowStats

logger = logging.getLogger(__name__)

_SYSTEM_PROMPT = """\
You are a completeness critic over one workflow's population of past runs. You are
given descriptive statistics (no failure labels) and, for statistically unusual
hypotheses, an uncited-evidence probe.

Identify RECURRING failure modes — patterns that hold across many runs, not
one-offs. For every claim you MUST:
  - cite the run_ids (and evidence, if any) that establish it;
  - give the recurrence count (how many runs it holds across);
  - propose a GENERALIZABLE detector: a predicate over the statistics fields that
    would flag this failure in ANY workflow;
  - propose the concrete workflow edit that would fix it.
If you cannot cite evidence, do not report the claim.

Return STRICT JSON only, no prose, of the form:
{"findings":[{"failure_class":"...","hypothesis_id":"...","rationale":"...",
  "recurrence_n":<int>,"evidence":{"run_ids":[...],"stat_refs":[...]},
  "proposed_detector":{"predicate":{...}},
  "proposed_workflow_edit":{"add_data_domains":[...],"add_phase":true}}]}"""


@dataclass
class CriticFinding:
    failure_class: str
    hypothesis_id: str
    rationale: str
    recurrence_n: int
    statement: str = ""
    evidence: Dict[str, Any] = field(default_factory=dict)
    proposed_detector: Dict[str, Any] = field(default_factory=dict)
    proposed_workflow_edit: Dict[str, Any] = field(default_factory=dict)
    source: str = "blindspot_critic"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "failure_class": self.failure_class,
            "hypothesis_id": self.hypothesis_id,
            "statement": self.statement,
            "rationale": self.rationale,
            "recurrence_n": self.recurrence_n,
            "evidence": self.evidence,
            "proposed_detector": self.proposed_detector,
            "proposed_workflow_edit": self.proposed_workflow_edit,
            "source": self.source,
        }


def _outlier_hypotheses(stats: WorkflowStats) -> List[str]:
    """Cheap statistical triage: hypotheses worth the model's attention. No
    theory of failure — just 'unusual'. Keeps Tier-2 off every trace."""
    return [
        h.hypothesis_id
        for h in stats.hypotheses
        if h.inconclusive_rate >= 0.5 or h.corroboration_met_rate <= 0.5
    ]


def _build_input(stats: WorkflowStats, probes: Dict[str, ProbeResult], outliers: List[str]) -> str:
    return json.dumps(
        {
            "stats": stats.to_dict(),
            "outliers": outliers,
            "probes": {hid: probes[hid].to_dict() for hid in outliers if hid in probes},
        },
        default=str,
    )


def _extract_json(text: str) -> Optional[Dict[str, Any]]:
    if not text:
        return None
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass
    match = re.search(r"\{.*\}", text, re.DOTALL)
    if not match:
        return None
    try:
        return json.loads(match.group(0))
    except json.JSONDecodeError:
        return None


def detect(
    stats: WorkflowStats,
    probes: Optional[Dict[str, ProbeResult]] = None,
    *,
    claude: Any = None,
    min_recurrence: int = 3,
) -> List[CriticFinding]:
    """Run the Tier-2 critic. Returns [] when there is nothing unusual, no API
    key, or the model returns nothing that clears the guardrails."""
    probes = probes or {}
    outliers = _outlier_hypotheses(stats)
    if not outliers:
        return []

    if claude is None:
        from core.llm.harness.claude import ClaudeService

        claude = ClaudeService()
    if not claude.has_api_key():
        logger.info("blindspot_critic: no LLM key; skipping Tier-2 detection")
        return []

    raw = claude.chat(
        message=_build_input(stats, probes, outliers),
        system_prompt=_SYSTEM_PROMPT,
        max_tokens=2048,
    )
    parsed = _extract_json(raw or "")
    if not parsed:
        return []

    # Resolve the model's hypothesis reference against either the (per-run) id it
    # was shown or the statement — the stable identity — so a finding keyed on the
    # claim text is accepted and normalised back to both.
    by_id = {h.hypothesis_id: h for h in stats.hypotheses}
    by_statement = {h.statement: h for h in stats.hypotheses}
    findings: List[CriticFinding] = []
    for item in parsed.get("findings", []):
        if not isinstance(item, dict):
            continue
        ref = str(item.get("hypothesis_id") or "")
        hyp = by_id.get(ref) or by_statement.get(ref) or by_statement.get(
            str(item.get("statement") or "")
        )
        recurrence = int(item.get("recurrence_n") or 0)
        run_ids = (item.get("evidence") or {}).get("run_ids") or []
        # Guardrails: known hypothesis, cited runs, recurs enough to be worth spend.
        if hyp is None:
            continue
        if not run_ids:
            continue
        if recurrence < min_recurrence:
            continue
        findings.append(
            CriticFinding(
                failure_class=str(item.get("failure_class") or "unspecified"),
                hypothesis_id=hyp.hypothesis_id,
                statement=hyp.statement,
                rationale=str(item.get("rationale") or ""),
                recurrence_n=recurrence,
                evidence=dict(item.get("evidence") or {}),
                proposed_detector=dict(item.get("proposed_detector") or {}),
                proposed_workflow_edit=dict(item.get("proposed_workflow_edit") or {}),
            )
        )
    return findings
