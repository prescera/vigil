"""Activation: the WORKFLOW.md augmenter. Exercised against a temp playbook so
the round-trip, idempotency and revert are real file operations."""

from __future__ import annotations

import textwrap
from pathlib import Path

import yaml

from core.evolution.activation import (
    apply_playbook_edit,
    plan_edit,
    revert_playbook,
)

PLAYBOOK = textwrap.dedent(
    """\
    ---
    name: finance-hunt
    description: "Finance-subnet hunt."
    run_kind: hunt
    attack_techniques:
      - T1071.004
      - T1567
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

    Body text stays intact.
    """
)

STAGING_PHASE = {
    "phase_id": "staging-check",
    "agent_id": "threat_hunter",
    "name": "Staging check",
    "purpose": "corroborate exfil staging on the subject host",
}


def test_plan_edit_adds_domains_and_phase():
    result = plan_edit(
        PLAYBOOK,
        add_data_domains=["endpoint", "process_lineage"],
        add_phases=[STAGING_PHASE],
    )
    assert result.added_domains == ["endpoint", "process_lineage"]
    assert result.added_phases == ["staging-check"]

    meta = yaml.safe_load(result.after_content.split("---")[1])
    assert meta["data_domains"] == [
        "net_flow", "dns", "http", "proxy", "win_events", "auth",
        "endpoint", "process_lineage",
    ]
    assert any(p["phase_id"] == "staging-check" for p in meta["phases"])
    # existing content preserved
    assert meta["run_kind"] == "hunt"
    assert "Body text stays intact." in result.after_content


def test_plan_edit_is_idempotent():
    once = plan_edit(PLAYBOOK, add_data_domains=["endpoint"], add_phases=[STAGING_PHASE])
    twice = plan_edit(
        once.after_content, add_data_domains=["endpoint"], add_phases=[STAGING_PHASE]
    )
    assert twice.added_domains == []
    assert twice.added_phases == []


def test_apply_and_revert_round_trip(tmp_path: Path):
    path = tmp_path / "WORKFLOW.md"
    path.write_text(PLAYBOOK, encoding="utf-8")

    result = apply_playbook_edit(
        path, add_data_domains=["endpoint", "process_lineage"], add_phases=[STAGING_PHASE]
    )
    on_disk = yaml.safe_load(path.read_text().split("---")[1])
    assert "endpoint" in on_disk["data_domains"]
    assert "process_lineage" in on_disk["data_domains"]

    revert_playbook(path, result.before_content)
    assert path.read_text(encoding="utf-8") == PLAYBOOK
    reverted = yaml.safe_load(path.read_text().split("---")[1])
    assert "endpoint" not in reverted["data_domains"]
