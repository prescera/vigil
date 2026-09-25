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
