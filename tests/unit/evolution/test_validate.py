"""A/B validation with the estate-availability scorer: a candidate that brings a
hypothesis's corroborating domain into the workflow vocabulary flips it to proven
and passes the gate; a candidate that does not is rejected."""

from __future__ import annotations

import textwrap
from typing import Any, Dict, List

from core.evolution.validate import estate_availability_scorer, validate_ab

H3 = "data was exfiltrated from fin-db-02 over an encrypted web channel"

BASE = textwrap.dedent(
    f"""\
    ---
    name: finance-hunt
    hypotheses:
      - "fin-db-01 is beaconing to external C2 over DNS"
      - "{H3}"
    data_domains:
      - dns
      - http
      - auth
    ---
    # body
    """
)


def _fs():
    class FakeDS:
        def get_findings(self, **k) -> List[Dict[str, Any]]:
            return [
                {"finding_id": "a", "data_source": "dns", "entity_context": {"hostnames": ["fin-db-01"]}},
                {"finding_id": "b", "data_source": "auth", "entity_context": {"hostnames": ["fin-db-01"]}},
                {"finding_id": "c", "data_source": "http", "entity_context": {"hostnames": ["fin-db-02"]}},
                {"finding_id": "d", "data_source": "endpoint", "entity_context": {"hostnames": ["fin-db-02"]}},
                {"finding_id": "e", "data_source": "process_lineage", "entity_context": {"hostnames": ["fin-db-02"]}},
            ]
    return FakeDS()


def test_scorer_marks_h3_inconclusive_under_current_vocabulary():
    score = estate_availability_scorer("finance-hunt", data_service=_fs())
    result = score(BASE, label="baseline")
    # H1 has dns+auth (both in vocab) -> proven; H3 has only http in vocab -> inconclusive
    assert result.hypothesis_outcomes["fin-db-01 is beaconing to external C2 over DNS"] == "proven"
    assert result.hypothesis_outcomes[H3] == "inconclusive"


def test_candidate_flips_h3_and_passes_gate():
    from core.evolution.activation import plan_edit
    candidate = plan_edit(BASE, add_data_domains=["endpoint", "process_lineage"]).after_content
    score = estate_availability_scorer("finance-hunt", data_service=_fs())
    ab = validate_ab(BASE, candidate, target_hypothesis=H3, run_scorer=score)
    assert ab.target_flipped is True
    assert ab.non_regressing is True
    assert ab.passes is True
    assert ab.outcomes_before[H3] == "inconclusive"
    assert ab.outcomes_after[H3] == "proven"


def test_useless_candidate_is_rejected():
    # Adding an irrelevant domain (no fin-db-02 evidence in it) does not flip H3.
    from core.evolution.activation import plan_edit
    candidate = plan_edit(BASE, add_data_domains=["email"]).after_content
    score = estate_availability_scorer("finance-hunt", data_service=_fs())
    ab = validate_ab(BASE, candidate, target_hypothesis=H3, run_scorer=score)
    assert ab.target_flipped is False
    assert ab.passes is False
