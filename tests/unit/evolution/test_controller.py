"""The controller end-to-end with fakes: the real miner-aggregation, probe,
detector evaluator, generator and activator run; only the run population
(mine_workflow), the A/B scorer, the LLM and the store are faked. Proves the
loop wiring: detect → locate → propose → prove → gate → activate, and
codify-back on the Tier-2 path."""

from __future__ import annotations

import textwrap
from pathlib import Path
from typing import Any, Dict, List

import pytest
import yaml

from core.evolution.controller import EvolutionController
from core.evolution.detectors import (
    UNCORROBORATED_DOMAIN_GAP_PREDICATE,
    crystallize,
)
from core.evolution.models import DetectorRule
from core.evolution.trace_miner import aggregate_stats
from core.evolution.validate import ScoreResult

FIN_DB = {"type": "host", "value": "fin-db-01"}

PLAYBOOK = textwrap.dedent(
    """\
    ---
    name: finance-hunt
    run_kind: hunt
    data_domains:
      - net_flow
      - dns
      - http
      - proxy
      - win_events
      - auth
    phases:
      - phase_id: characterize
        agent_id: threat_hunter
        name: Characterize
    ---
    # Finance Hunt
    """
)


FIN_APP = {"type": "host", "value": "fin-app-02"}

# Test vocabulary: endpoint/process_lineage are deliberately OUT (the gap the probe finds).
DD = ["net_flow", "dns", "http", "proxy", "win_events", "auth"]


def _population(n=15):
    def conc(hyp, status, ev, domains, tech, subject=FIN_DB):
        # hypothesis_id is randomised per run, as a real hunt mints it; the
        # statement is the stable key the miner aggregates on.
        return {
            "hypothesis_id": f"{hyp}-{status}-{ev}", "status": status,
            "statement": f"{hyp} statement", "evidence_count": ev,
            "subject_entities": [subject], "techniques": [tech],
            "sources": [{"source_system": d, "stance": "supports"} for d in domains],
            "first_seen": "2026-09-01T00:00:00Z", "last_seen": "2026-09-01T06:00:00Z",
        }
    distils = []
    for i in range(n):
        distils.append((f"r-{i:03d}", {"conclusions": [
            conc("H1", "inconclusive" if i < 2 else "proven", 6,
                 ["http"] if i < 2 else ["dns", "auth"], "T1071.004"),
            conc("H2", "disproven", 4, ["win_events", "auth"], "T1021.001", subject=FIN_APP),
            conc("H3", "inconclusive", 3, ["http"], "T1567"),
        ]}))
    return distils


class FakeStore:
    def __init__(self, detectors: List[DetectorRule] | None = None):
        self._detectors = list(detectors or [])
        self.cycles: List[Dict[str, Any]] = []

    def list_detectors(self): return list(self._detectors)
    def save_detector(self, rule): self._detectors.append(rule)
    def save_cycle(self, cycle): self.cycles.append(cycle)
    def list_cycles(self): return list(self.cycles)


class FakeFindings:
    """Estate has endpoint + process_lineage evidence on fin-db-01 (uncited)."""
    def get_findings(self, **kwargs):
        return [
            {"finding_id": "f1", "data_source": "endpoint",
             "entity_context": {"hostnames": ["fin-db-01"]}},
            {"finding_id": "f2", "data_source": "process_lineage",
             "entity_context": {"hostnames": ["fin-db-01"]}},
        ]


def _fake_scorer():
    # Outcomes keyed by STATEMENT (the stable identity the controller targets).
    def score(content: str, *, label: str) -> ScoreResult:
        if "endpoint" in content:            # candidate playbook
            return ScoreResult(0.8, {"H1 statement": "proven", "H2 statement": "disproven",
                                     "H3 statement": "proven"})
        return ScoreResult(0.6, {"H1 statement": "proven", "H2 statement": "disproven",
                                 "H3 statement": "inconclusive"})
    return score


@pytest.fixture
def playbook(tmp_path) -> Path:
    p = tmp_path / "WORKFLOW.md"
    p.write_text(PLAYBOOK, encoding="utf-8")
    return p


def _patch_mine(monkeypatch, distils):
    async def fake_mine(workflow_id, **kwargs):
        return aggregate_stats(workflow_id, distils, data_domains=kwargs.get("data_domains"))
    monkeypatch.setattr("core.evolution.controller.mine_workflow", fake_mine)


@pytest.mark.asyncio
async def test_tier1_detector_activates_and_edits_playbook(monkeypatch, playbook):
    _patch_mine(monkeypatch, _population())
    store = FakeStore([crystallize(
        "uncorroborated_domain_gap", UNCORROBORATED_DOMAIN_GAP_PREDICATE,
        cycle_id="seed", validated_cycles=3)])
    ctl = EvolutionController(
        store=store, run_scorer=_fake_scorer(), data_service=FakeFindings())

    result = await ctl.run_cycle("finance-hunt", str(playbook), data_domains=DD)

    assert result.stage == "activated"
    assert result.statement == "H3 statement"
    assert result.tier == "tier1"
    assert result.ab["target_flipped"] is True
    meta = yaml.safe_load(playbook.read_text().split("---")[1])
    assert "endpoint" in meta["data_domains"]
    assert "process_lineage" in meta["data_domains"]
    assert store.cycles and store.cycles[-1]["stage"] == "activated"


@pytest.mark.asyncio
async def test_tier2_discovery_activates_and_codifies_back(monkeypatch, playbook):
    _patch_mine(monkeypatch, _population())

    import json as _json

    critic_payload = _json.dumps({"findings": [{
        "failure_class": "uncorroborated_domain_gap",
        "hypothesis_id": "H3 statement",   # references the stable statement
        "rationale": "unproven every run; endpoint evidence uncited",
        "recurrence_n": 15,
        "evidence": {"run_ids": ["r-000", "r-001"]},
        "proposed_detector": {"predicate": UNCORROBORATED_DOMAIN_GAP_PREDICATE},
        "proposed_workflow_edit": {"add_data_domains": ["endpoint"]},
    }]})

    class FakeClaude:
        def has_api_key(self): return True
        def chat(self, **kwargs): return critic_payload

    store = FakeStore([])  # cold start: no Tier-1 rules
    ctl = EvolutionController(
        store=store, run_scorer=_fake_scorer(),
        claude=FakeClaude(), data_service=FakeFindings())

    result = await ctl.run_cycle("finance-hunt", str(playbook), data_domains=DD)

    assert result.stage == "activated"
    assert result.tier == "tier2"
    # codify-back: the discovery crystallised into a Tier-1 detector
    assert any(r.id == "uncorroborated-domain-gap" for r in store.list_detectors())


@pytest.mark.asyncio
async def test_data_starved_when_no_uncited_evidence(monkeypatch, playbook):
    _patch_mine(monkeypatch, _population())

    class EmptyFindings:
        def get_findings(self, **kwargs): return []

    class NoKeyClaude:
        def has_api_key(self): return False
        def chat(self, **kwargs): return None

    store = FakeStore([crystallize(
        "uncorroborated_domain_gap", UNCORROBORATED_DOMAIN_GAP_PREDICATE,
        cycle_id="seed", validated_cycles=3)])
    ctl = EvolutionController(
        store=store, run_scorer=_fake_scorer(), claude=NoKeyClaude(),
        data_service=EmptyFindings())

    result = await ctl.run_cycle("finance-hunt", str(playbook), data_domains=DD)
    # Tier-1 predicate needs the probe nonempty, so with no estate evidence it
    # does not even fire -> no gap detected.
    assert result.stage in {"data-starved", "no-gap"}
    meta = yaml.safe_load(playbook.read_text().split("---")[1])
    assert "endpoint" not in meta["data_domains"]  # nothing activated


@pytest.mark.asyncio
async def test_no_scorer_parks_as_proposed(monkeypatch, playbook):
    _patch_mine(monkeypatch, _population())
    store = FakeStore([crystallize(
        "uncorroborated_domain_gap", UNCORROBORATED_DOMAIN_GAP_PREDICATE,
        cycle_id="seed", validated_cycles=3)])
    ctl = EvolutionController(store=store, run_scorer=None, data_service=FakeFindings())

    result = await ctl.run_cycle("finance-hunt", str(playbook), data_domains=DD)
    assert result.stage == "proposed"
    assert result.proposal["add_data_domains"] == ["endpoint", "process_lineage"]
