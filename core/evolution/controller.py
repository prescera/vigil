"""The evolution controller: one cycle of detect → locate → propose → prove →
gate → activate, plus codify-back.

It orchestrates the other modules and holds no detection or generation logic of
its own. Every collaborator is injectable so the whole loop is unit-tested with
fakes; the defaults wire the real miner, store, critic, validator and activator.

Stages a cycle can end in:
  no-runs       — the workflow has no finished runs to fold
  no-gap        — nothing detected
  data-starved  — a hypothesis is failing but the missing evidence is not in the
                  estate (a visibility gap): routed out, no Playbook change
  proposed      — a change was proposed but could not be A/B-validated (no scorer
                  wired): parked for validation
  rejected      — validated and it regressed / did not flip: refused
  parked        — validated and non-regressing but below the confidence gate:
                  awaiting human promotion
  activated     — validated and auto-activated (confidence >= gate)
"""

from __future__ import annotations

import hashlib
import logging
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from core.evolution import blindspot_critic, generator
from core.evolution.activation import apply_playbook_edit, plan_edit
from core.evolution.detectors import crystallize
from core.evolution.models import ProbeResult, WorkflowStats
from core.evolution.trace_miner import (
    evaluate_detectors,
    mine_workflow,
    probe_uncited_evidence,
)
from core.evolution.validate import validate_ab
from core.time import utcnow

logger = logging.getLogger(__name__)

DEFAULT_CONFIDENCE_GATE = 0.90
SUSPICION_UNPROVEN_RATE = 0.5


@dataclass
class CycleResult:
    cycle_id: str
    workflow_id: str
    stage: str
    hypothesis_id: Optional[str] = None
    statement: Optional[str] = None
    tier: Optional[str] = None
    detected: Dict[str, Any] = field(default_factory=dict)
    proposal: Dict[str, Any] = field(default_factory=dict)
    ab: Dict[str, Any] = field(default_factory=dict)
    confidence: float = 0.0
    reason: str = ""
    created_at: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "cycle_id": self.cycle_id,
            "workflow_id": self.workflow_id,
            "stage": self.stage,
            "hypothesis_id": self.hypothesis_id,
            "statement": self.statement,
            "tier": self.tier,
            "detected": self.detected,
            "proposal": self.proposal,
            "ab": self.ab,
            "confidence": self.confidence,
            "reason": self.reason,
            "created_at": self.created_at,
        }


class EvolutionController:
    def __init__(
        self,
        *,
        store: Any = None,
        run_scorer: Any = None,
        claude: Any = None,
        activator: Any = apply_playbook_edit,
        gate_threshold: float = DEFAULT_CONFIDENCE_GATE,
        data_service: Any = None,
    ) -> None:
        if store is None:
            from core.evolution.store import EvolutionStore

            store = EvolutionStore()
        self.store = store
        self.run_scorer = run_scorer
        self.claude = claude
        self.activator = activator
        self.gate_threshold = gate_threshold
        self.data_service = data_service

    async def run_cycle(
        self,
        workflow_id: str,
        playbook_path: str,
        *,
        data_domains: Optional[List[str]] = None,
    ) -> CycleResult:
        # Resolve the workflow's declared telemetry vocabulary if the caller did
        # not pass it — the probe needs it to tell an uncitable domain (outside
        # data_domains) from one the run merely did not cite.
        if data_domains is None:
            data_domains = self._resolve_data_domains(workflow_id)
        stats = await mine_workflow(workflow_id, data_domains=data_domains)
        if not stats.hypotheses:
            return self._record(CycleResult(
                cycle_id=self._cycle_id(workflow_id, "no-runs"),
                workflow_id=workflow_id, stage="no-runs",
                reason="no finished runs to fold", created_at=self._now(),
            ))

        probes = self._probe_suspicious(stats)
        tier, finding = self._detect(stats, probes)
        if finding is None:
            return self._record(CycleResult(
                cycle_id=self._cycle_id(workflow_id, "no-gap"),
                workflow_id=workflow_id, stage="no-gap",
                reason="no detector fired and the critic found nothing", created_at=self._now(),
            ))

        # Statement is the stable identity: a hunt mints a fresh hypothesis_id every
        # run, so probes, the A/B target and recall all key on the claim itself.
        hyp_id = finding.get("hypothesis_id")
        statement = finding.get("statement") or hyp_id
        probe = probes.get(statement) or probes.get(hyp_id)
        cycle_id = self._cycle_id(workflow_id, statement or hyp_id)

        # data-starved: failing, but the missing evidence is not in the estate.
        if probe is None or not probe.has_uncited:
            return self._record(CycleResult(
                cycle_id=cycle_id, workflow_id=workflow_id, stage="data-starved",
                hypothesis_id=hyp_id, statement=statement, tier=tier, detected=finding,
                reason="unproven but no present-but-uncited evidence; routed to integrations",
                created_at=self._now(),
            ))

        proposal = generator.propose_domain_augment(statement or hyp_id, probe)
        current = self._read(playbook_path)
        candidate = plan_edit(
            current,
            add_data_domains=proposal.add_data_domains,
            add_phases=proposal.add_phases,
        ).after_content

        confidence = self._confidence(tier, finding)
        base = CycleResult(
            cycle_id=cycle_id, workflow_id=workflow_id, stage="proposed",
            hypothesis_id=hyp_id, statement=statement, tier=tier, detected=finding,
            proposal=proposal.to_dict(), confidence=confidence, created_at=self._now(),
        )

        if self.run_scorer is None:
            base.reason = "proposed; no A/B scorer wired (needs live agent stack + snapshot)"
            return self._record(base)

        ab = validate_ab(
            current, candidate, target_hypothesis=statement or hyp_id,
            run_scorer=self.run_scorer,
        )
        base.ab = ab.to_dict()

        if not ab.passes:
            base.stage = "rejected"
            base.reason = ab.reason
            return self._record(base)

        if confidence < self.gate_threshold:
            base.stage = "parked"
            base.reason = f"{ab.reason}; confidence {confidence:.2f} < gate {self.gate_threshold:.2f} — awaiting human promotion"
            return self._record(base)

        # auto-activate
        result = self.activator(
            playbook_path,
            add_data_domains=proposal.add_data_domains,
            add_phases=proposal.add_phases,
        )
        base.stage = "activated"
        base.reason = f"{ab.reason}; auto-activated (confidence {confidence:.2f} >= gate)"
        base.proposal = {**proposal.to_dict(), "edit": result.to_dict()}

        if tier == "tier2":
            self._codify_back(finding, cycle_id)

        return self._record(base)

    # ------------------------------------------------------------------ steps
    def _probe_suspicious(self, stats: WorkflowStats) -> Dict[str, ProbeResult]:
        probes: Dict[str, ProbeResult] = {}
        for h in stats.hypotheses:
            # Rarely-proven claims are the ones worth probing for uncited evidence.
            # proven_rate is robust to how a run ended (inconclusive, parked,
            # cost-exhausted all read as "did not prove"). No looked_count gate:
            # the probe itself decides gap vs. data-starve, and a hunt whose own
            # searches missed still deserves the probe.
            if h.proven_rate < SUSPICION_UNPROVEN_RATE:
                try:
                    probes[h.statement] = probe_uncited_evidence(
                        h, data_service=self.data_service,
                        data_domains=stats.data_domains,
                    )
                except Exception as exc:  # noqa: BLE001
                    logger.warning("probe failed for %s: %r", h.statement, exc)
        return probes

    def _detect(self, stats, probes):
        tier1 = evaluate_detectors(stats, self.store.list_detectors(), probes)
        if tier1:
            return "tier1", tier1[0].to_dict()
        tier2 = blindspot_critic.detect(stats, probes, claude=self.claude)
        # dedup vs Tier-1 rule ids is a no-op here (tier1 empty), kept for clarity
        known = {r.id for r in self.store.list_detectors()}
        tier2 = [f for f in tier2 if f.failure_class.replace("_", "-") not in known]
        if tier2:
            return "tier2", tier2[0].to_dict()
        return None, None

    def _confidence(self, tier: str, finding: Dict[str, Any]) -> float:
        if tier == "tier1":
            return 0.95  # a crystallised rule fired: high, deterministic
        # tier2: scale with recurrence, capped below the gate unless strongly recurring
        recurrence = int(finding.get("recurrence_n") or 0)
        return min(0.95, 0.6 + 0.05 * recurrence)

    def _codify_back(self, finding: Dict[str, Any], cycle_id: str) -> None:
        predicate = (finding.get("proposed_detector") or {}).get("predicate")
        if not predicate:
            from core.evolution.detectors import UNCORROBORATED_DOMAIN_GAP_PREDICATE

            predicate = UNCORROBORATED_DOMAIN_GAP_PREDICATE
        rule = crystallize(
            finding.get("failure_class", "unspecified"),
            predicate,
            cycle_id=cycle_id,
            validated_cycles=1,
        )
        self.store.save_detector(rule)

    # ------------------------------------------------------------------ utils
    def _read(self, playbook_path: str) -> str:
        from pathlib import Path

        return Path(playbook_path).read_text(encoding="utf-8")

    def _resolve_data_domains(self, workflow_id: str) -> Optional[List[str]]:
        try:
            from core.workflows.workflows_service import WorkflowsService

            wf = WorkflowsService().get_workflow(workflow_id)
            dd = (wf.metadata.get("data_domains") if wf else None) or None
            return [str(d) for d in dd] if dd else None
        except Exception as exc:  # noqa: BLE001
            logger.warning("could not resolve data_domains for %s: %r", workflow_id, exc)
            return None

    def _record(self, result: CycleResult) -> CycleResult:
        try:
            self.store.save_cycle(result.to_dict())
        except Exception as exc:  # noqa: BLE001
            logger.warning("could not persist cycle %s: %r", result.cycle_id, exc)
        return result

    def _now(self) -> str:
        return utcnow().isoformat()

    def _cycle_id(self, workflow_id: str, salt: str) -> str:
        digest = hashlib.sha1(f"{workflow_id}:{salt}".encode()).hexdigest()[:8]
        return f"cyc-{workflow_id}-{digest}"
