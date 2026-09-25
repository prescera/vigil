"""Phase-1 miner: aggregation, the uncited-evidence probe, and the detector
evaluator — all exercised against synthetic distil payloads and findings, so no
agent stack or database is touched.

The population is the plan's `finance-hunt` fixture: H1 proves (2 domains),
H2 resolves benign, H3 is chronically inconclusive-that-looked on one domain
while endpoint/process_lineage evidence sits present-but-uncited in the estate.
"""

from __future__ import annotations

from typing import Any, Dict, List

import pytest

from core.evolution.detectors import (
    UNCORROBORATED_DOMAIN_GAP_PREDICATE,
    cold_start_detectors,
    crystallize,
)
from core.evolution.models import DetectorRule
from core.evolution.trace_miner import (
    aggregate_stats,
    evaluate_detectors,
    probe_uncited_evidence,
    uncited_domains,
)

FIN_DB = {"type": "host", "value": "fin-db-01"}


def _conclusion(
    hyp_id: str,
    status: str,
    *,
    evidence_count: int,
    supporting_domains: List[str],
    technique: str,
    subject=FIN_DB,
) -> Dict[str, Any]:
    return {
        "hypothesis_id": hyp_id,
        "status": status,
        "statement": f"{hyp_id} statement",
        "rationale": "",
        "evidence_count": evidence_count,
        "subject_entities": [subject],
        "techniques": [technique],
        "sources": [
            {"source_system": d, "stance": "supports"} for d in supporting_domains
        ],
        "first_seen": "2026-09-01T00:00:00Z",
        "last_seen": "2026-09-01T06:00:00Z",
    }


def _finance_hunt_population(n: int = 15):
    """n runs. H1 proven in all but 2 (inconclusive), H2 benign every run,
    H3 inconclusive-that-looked on `http` alone every run."""
    distils = []
    for i in range(n):
        h1_status = "inconclusive" if i < 2 else "proven"
        h1_domains = ["http"] if i < 2 else ["dns", "auth"]
        conclusions = [
            _conclusion("H1", h1_status, evidence_count=6,
                        supporting_domains=h1_domains, technique="T1071.004"),
            _conclusion("H2", "disproven", evidence_count=4,
                        supporting_domains=["win_events", "auth"], technique="T1021.001"),
            _conclusion("H3", "inconclusive", evidence_count=3,
                        supporting_domains=["http"], technique="T1567"),
        ]
        distils.append((f"r-{i:03d}", {"outcome": "completed", "conclusions": conclusions}))
    return distils


# --------------------------------------------------------------------------- #
# aggregation
# --------------------------------------------------------------------------- #


def test_aggregate_marks_h3_chronically_inconclusive_single_domain():
    stats = aggregate_stats("finance-hunt", _finance_hunt_population())
    assert stats.run_count == 15

    h3 = stats.hypothesis("H3")
    assert h3 is not None
    assert h3.run_count == 15
    assert h3.inconclusive_rate == 1.0
    assert h3.looked_rate == 1.0                      # evidence_count 3 every run
    assert h3.max_distinct_domains_in_a_run == 1      # http only
    assert h3.corroboration_met_rate == 0.0           # never reached 2 domains
    assert h3.cited_domains_any == ["http"]
    assert h3.evidence_count_median == 3.0
    assert h3.techniques == ["T1567"]


def test_aggregate_h1_corroborates_h2_resolves():
    stats = aggregate_stats("finance-hunt", _finance_hunt_population())

    h1 = stats.hypothesis("H1")
    assert h1.outcomes.get("proven") == 13
    assert h1.max_distinct_domains_in_a_run == 2      # dns + auth
    assert h1.corroboration_met_rate == pytest.approx(13 / 15)
    assert set(h1.cited_domains_any) == {"http", "dns", "auth"}

    h2 = stats.hypothesis("H2")
    assert h2.outcomes.get("disproven") == 15
    assert h2.inconclusive_rate == 0.0


def test_aggregate_keys_on_statement_not_random_ids():
    # A hunt mints a fresh hypothesis_id per run; the same claim must still
    # aggregate as ONE hypothesis across the population, keyed on its statement.
    distils = []
    for i in range(4):
        distils.append((f"r{i}", {"conclusions": [{
            "hypothesis_id": f"h-random-{i}",              # different every run
            "statement": "data was exfiltrated over web",   # stable
            "status": "inconclusive", "evidence_count": 3,
            "subject_entities": [FIN_DB], "techniques": ["T1567"],
            "sources": [{"source_system": "http", "stance": "supports"}],
            "first_seen": "2026-09-01T00:00:00Z", "last_seen": "2026-09-01T06:00:00Z",
        }]}))
    stats = aggregate_stats("wf", distils)
    assert len(stats.hypotheses) == 1
    h = stats.hypotheses[0]
    assert h.run_count == 4
    assert h.inconclusive_rate == 1.0
    assert h.proven_rate == 0.0


def test_aggregate_empty_population_is_safe():
    stats = aggregate_stats("finance-hunt", [])
    assert stats.run_count == 0
    assert stats.hypotheses == []
    assert stats.window is None


def test_population_window_spans_conclusions():
    stats = aggregate_stats("finance-hunt", _finance_hunt_population())
    assert stats.window == ("2026-09-01T00:00:00Z", "2026-09-01T06:00:00Z")


# --------------------------------------------------------------------------- #
# probe (pure core)
# --------------------------------------------------------------------------- #


def _finding(fid: str, data_source: str, host: str) -> Dict[str, Any]:
    return {
        "finding_id": fid,
        "data_source": data_source,
        "timestamp": "2026-09-01T03:00:00Z",
        "entity_context": {"hostnames": [host]},
    }


def test_uncited_domains_surfaces_present_but_uncited():
    findings = [
        _finding("f1", "http", "fin-db-01"),            # already cited → excluded
        _finding("f2", "endpoint", "fin-db-01"),
        _finding("f3", "endpoint", "fin-db-01"),
        _finding("f4", "process_lineage", "fin-db-01"),
        _finding("f5", "endpoint", "other-host"),       # wrong entity → excluded
    ]
    out = uncited_domains(findings, subject_values=["fin-db-01"], allowed_domains=["http"])
    assert out == {"endpoint": 2, "process_lineage": 1}


def test_uncited_domains_entity_match_is_casefolded():
    findings = [_finding("f1", "endpoint", "FIN-DB-01")]
    out = uncited_domains(findings, subject_values=["fin-db-01"], allowed_domains=[])
    assert out == {"endpoint": 1}


def test_probe_falls_back_to_statement_subject_when_none_recorded():
    # Real hunts often record no subject_entities; the probe must still scope to
    # the host named in the statement ("...exfiltrated from fin-db-02...").
    from core.evolution.models import HypothesisStats

    h = HypothesisStats(
        hypothesis_id="h-x", statement="data was exfiltrated from fin-db-02 over web",
        techniques=["T1567"], run_count=4, outcomes={"inconclusive": 4},
        looked_count=4, subject_entities=[], cited_domains_any=["http"],
    )

    class FakeDataService:
        def get_findings(self, **kwargs):
            return [
                _finding("f1", "http", "fin-db-02"),
                _finding("f2", "endpoint", "fin-db-02"),
                _finding("f3", "endpoint", "other-host"),  # wrong host → excluded
            ]

    probe = probe_uncited_evidence(h, data_service=FakeDataService())
    assert probe.present_but_uncited_domains == {"endpoint": 1}
    assert probe.subject_entities == ["host:fin-db-02"]


def test_probe_uncited_evidence_uses_service_and_subtracts_cited():
    stats = aggregate_stats("finance-hunt", _finance_hunt_population())
    h3 = stats.hypothesis("H3")

    class FakeDataService:
        def get_findings(self, **kwargs):
            return [
                _finding("f1", "http", "fin-db-01"),
                _finding("f2", "endpoint", "fin-db-01"),
                _finding("f3", "process_lineage", "fin-db-01"),
            ]

    probe = probe_uncited_evidence(h3, data_service=FakeDataService())
    assert probe.hypothesis_id == "H3"
    assert probe.has_uncited
    assert probe.present_but_uncited_domains == {"endpoint": 1, "process_lineage": 1}
    assert probe.subject_entities == ["host:fin-db-01"]


# --------------------------------------------------------------------------- #
# detector evaluation
# --------------------------------------------------------------------------- #


def _gap_rule() -> DetectorRule:
    return crystallize(
        "uncorroborated_domain_gap",
        UNCORROBORATED_DOMAIN_GAP_PREDICATE,
        cycle_id="cyc-test",
        validated_cycles=3,
    )


def test_detector_fires_on_h3_only():
    stats = aggregate_stats("finance-hunt", _finance_hunt_population())
    probes = {
        "H3": probe_uncited_evidence(
            stats.hypothesis("H3"),
            data_service=type(
                "S", (), {"get_findings": lambda self, **k: [
                    _finding("f2", "endpoint", "fin-db-01"),
                ]}
            )(),
        )
    }
    findings = evaluate_detectors(stats, [_gap_rule()], probes)
    assert len(findings) == 1
    assert findings[0].hypothesis_id == "H3"
    assert findings[0].rule_id == "uncorroborated-domain-gap"
    assert findings[0].stat_refs["present_but_uncited_domains"] == {"endpoint": 1}
    assert findings[0].origin["discovered_by"] == "blindspot_critic"


def test_detector_needs_the_probe_to_fire():
    # Without a probe result (no present-but-uncited evidence), the predicate's
    # nonempty condition fails and H3 does NOT fire — a domain gap is only a gap
    # if the missing evidence actually exists in the estate.
    stats = aggregate_stats("finance-hunt", _finance_hunt_population())
    findings = evaluate_detectors(stats, [_gap_rule()], probes={})
    assert findings == []


def test_cold_start_has_no_detectors():
    stats = aggregate_stats("finance-hunt", _finance_hunt_population())
    assert evaluate_detectors(stats, cold_start_detectors(), probes={}) == []


def test_predicate_ops_and_serialization_roundtrip():
    rule = _gap_rule()
    restored = DetectorRule.from_dict(rule.to_dict())
    assert restored.id == rule.id
    assert restored.when == rule.when
    assert restored.origin == rule.origin
