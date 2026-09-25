"""Self-evolving workflows (#evolution).

The harness improves its own Playbooks from the evidence it already produces.
A finished hunt population is folded into per-workflow statistics; a chronically
underperforming hypothesis is detected (deterministic Tier-1 rules, then a model
Tier-2 critic for what the rules did not anticipate), the missing capability is
located from Findings the runs could not cite, a candidate Playbook is generated,
validated by A/B over a frozen memory snapshot, and — if it does not regress —
promoted. Validated Tier-2 discoveries crystallise into new Tier-1 rules, so the
detector set grows.

This package is a capability domain: it may read ``core.storage``, ``core.memory``,
``core.workflows``, ``core.agents`` (projection/distil reads), ``core.detections``
and ``core.llm``; it must not import the ``services`` deployables (``.importlinter``).
Run outcomes are read over the agent-layer HTTP surface via
``core.agents.projections``, never by a second fold here.
"""
