#!/usr/bin/env python3
"""Reset the finance-hunt self-evolution demo to a clean, repeatable slate.

Activation rewrites the finance-hunt WORKFLOW.md (adds endpoint/process_lineage +
a staging-check phase, and safe_dump reflows the front matter), so a second demo
would start from an already-evolved playbook with a closed gap. This restores the
pristine pre-activation state and clears the demo's run + evolution state:

  1. rewrite core/workflows/definitions/finance-hunt/WORKFLOW.md to the canonical
     pre-activation content (data_domains WITHOUT endpoint/process_lineage, no
     staging-check phase, comments + narrative intact)
  2. wipe the finance-hunt run population (workflow_runs + agent_events)
  3. clear the evolution cycle timeline (evolution.cycles)
  4. re-seed the uncorroborated-domain-gap Tier-1 detector (deterministic detection)

It does NOT touch the seeded estate findings (that is scripts/seed_hunt_traces.py)
or your LLM/stack config. After reset, the demo is:

    python scripts/seed_hunt_traces.py          # (if the estate isn't seeded)
    python scripts/run_finance_hunt.py -n 5      # run hunts (needs agent worker + key)
    python scripts/run_evolution_cycle.py finance-hunt   # detect -> validate -> activate
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

_WORKFLOW = Path(__file__).resolve().parents[1] / "core" / "workflows" / "definitions" / "finance-hunt" / "WORKFLOW.md"

# The canonical pre-activation playbook. Kept here (not read from disk) precisely
# because activation overwrites the on-disk copy — this is the source of truth the
# reset restores to.
_CANONICAL = """\
---
name: finance-hunt
description: "Finance-subnet hunt used to demonstrate self-evolving workflows: three declared hypotheses, one of which is structurally under-observed."
use_case: "Recurring hunt over the finance business unit. Two hypotheses resolve; the exfil hypothesis stays chronically inconclusive because the workflow's data_domains omit the endpoint evidence that would corroborate it."
trigger_examples:
  - "Run the finance-subnet hunt over fin-db-01 and svc-payroll"
run_kind: hunt

# Declared on purpose (unlike the shipped threat-hunt, which leaves this empty so
# the caller states them per run). The evolution miner aggregates PER hypothesis
# across the run population, so the population needs a stable hypothesis identity
# to prune/augment -- that is what these give it.
hypotheses:
  - "fin-db-01 is beaconing to external C2 over DNS"
  - "svc-payroll credentials were reused for RDP lateral movement"
  - "data was exfiltrated from fin-db-02 over an encrypted web channel"

attack_techniques:
  - T1071.004   # DNS C2            (H1)
  - T1071.001   # Web protocols
  - T1021.001   # RDP              (H2)
  - T1078       # Valid accounts
  - T1567       # Exfil over web    (H3)
  - T1041       # Exfil over C2

# The load-bearing part of the demo. H1 corroborates across dns + auth (both here);
# H2 resolves on win_events + auth. H3's second corroborating domain -- endpoint /
# process_lineage staging evidence on fin-db-02 -- EXISTS in the estate but is
# deliberately absent from this list, so a worker's source_system citation of it is
# refused at spec build and H3 can never reach the >1-domain verdict bar. The
# evolution augment adds those two domains (+ a staging-check phase). Do not add
# endpoint/process_lineage here by hand -- the point is that the harness discovers
# and adds them.
data_domains:
  - net_flow
  - dns
  - http
  - proxy
  - win_events
  - auth

objectives:
  - "State each hypothesis and the scope that would test it"
  - "Characterise the evidence bearing on it across the available domains"
  - "Report each hypothesis as proven, disproven or inconclusive, with reasons"

phases:
  - id: threat_hunter
    agent: threat_hunter
    name: "Behavioural hunting"
    # search_findings queries Vigil's own Findings table (where the seeded estate
    # lives). telemetry_search is intentionally NOT granted: it reads a self-hosted
    # SIEM this deployment does not have.
    tools: [search_findings]
    instructions: |
      Broad behavioural hunting across the scored findings for each hypothesis, using
      search_findings across the finding entities and their data_source domains.
      "Nothing matched" is a finding about visibility, not a failure: say which domains
      you could read and which you could not.

  - id: network_analyst
    agent: network_analyst
    name: "Traffic shape"
    tools: [search_findings]
    instructions: |
      Beaconing shape for H1; outbound volume asymmetry and destination reputation for
      H3, from the findings on the subject host. Quantify -- a regular low-variance
      interval is the signal, a busy host is not.

  - id: threat_intel
    agent: threat_intel
    name: "Observable enrichment"
    tools: [lookup_indicators]
    instructions: |
      Reputation and attribution for the domains, IPs and accounts each hypothesis
      names. A miss is not exoneration: say "not in the feed", never report an unknown
      observable as benign.
---

# Finance-Subnet Hunt (evolution demo)

This hunt exists to demonstrate a self-evolving workflow. It puts three hypotheses on
the board over the finance business unit and, each iteration, the Hunt Lead reads a
digest and chooses what to do next -- dispatch a worker, expand evidence, pivot,
deepen, abandon, validate, or conclude.

Every hypothesis ends proven, disproven or **inconclusive**. The exfil hypothesis
(H3, on fin-db-02) stays unproven every run -- it can gather a single-domain network
signal but can never corroborate it, because the endpoint staging evidence it needs
is outside this playbook's `data_domains`. That recurring, structural shortfall is
exactly what the evolution loop is built to find and close.
"""


def main() -> int:
    from core.storage.connection import init_database, get_db_manager
    from sqlalchemy import text

    init_database(echo=False, create_tables=True)

    # 1. restore the pristine playbook
    _WORKFLOW.write_text(_CANONICAL, encoding="utf-8")
    print(f"restored {_WORKFLOW.relative_to(Path.cwd()) if _WORKFLOW.is_relative_to(Path.cwd()) else _WORKFLOW}")

    # 2. wipe the finance-hunt run population
    with get_db_manager().session_scope() as s:
        ids = [str(r[0]) for r in s.execute(
            text("SELECT run_id FROM workflow_runs WHERE workflow_id='finance-hunt'")
        ).all()]
        if ids:
            s.execute(text("DELETE FROM agent_events WHERE run_id::text = ANY(:ids)"), {"ids": ids})
            s.execute(text("DELETE FROM workflow_runs WHERE workflow_id='finance-hunt'"))
    print(f"wiped {len(ids)} finance-hunt runs")

    # 3. clear the evolution cycle timeline
    from core.storage.config_service import get_config_service
    get_config_service().set_system_config("evolution.cycles", {"cycles": []}, config_type="evolution")
    print("cleared evolution.cycles")

    # 4. re-seed the Tier-1 detector (deterministic detection)
    from core.storage.config_service import get_config_service as _gcs
    _gcs().set_system_config("evolution.detectors", {"rules": []}, config_type="evolution")
    from core.evolution.store import EvolutionStore
    from core.evolution.detectors import crystallize, UNCORROBORATED_DOMAIN_GAP_PREDICATE
    EvolutionStore().save_detector(crystallize(
        "uncorroborated_domain_gap", UNCORROBORATED_DOMAIN_GAP_PREDICATE,
        cycle_id="seed", validated_cycles=3))
    print("re-seeded Tier-1 detector: uncorroborated-domain-gap")

    print()
    print("clean slate. next:")
    print("  python scripts/seed_hunt_traces.py          # if the estate isn't seeded")
    print("  python scripts/run_finance_hunt.py -n 5     # run hunts")
    print("  python scripts/run_evolution_cycle.py finance-hunt")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
