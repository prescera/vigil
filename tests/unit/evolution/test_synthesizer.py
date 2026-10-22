"""Synthesis from an APT description: the draft is grounded in the estate, the
written WORKFLOW.md is one the evolution activator can edit, and a run of it
declares typed subjects. Only the LLM and the Findings table are faked."""

from __future__ import annotations

import json
from typing import Any, Dict, List

import pytest

from core.evolution import synthesizer
from core.evolution.activation import _split, plan_edit
from core.evolution.synthesizer import (
    SynthesisError,
    normalize,
    read_estate,
    render,
    run_parameters,
    synthesize,
)
from core.workflows.workflows_service import WorkflowsService

FINDINGS = [
    {"finding_id": "f-1", "timestamp": "2026-10-01T00:00:00", "data_source": "dns",
     "entity_context": {"hostnames": ["fin-db-01"]}},
    {"finding_id": "f-2", "timestamp": "2026-10-02T00:00:00", "data_source": "auth",
     "entity_context": {"users": ["svc-payroll"], "hostnames": ["fin-app-02"]}},
    {"finding_id": "f-3", "timestamp": "2026-10-03T00:00:00", "data_source": "endpoint",
     "entity_context": {"hostname": "fin-db-01"}},
]

AGENTS = {"threat_hunter": "hunting", "network_analyst": "network", "threat_intel": "intel"}

DRAFT: Dict[str, Any] = {
    "name": "APT29 Finance Hunt",
    "title": "APT29 Finance Hunt",
    "description": "Hunts APT29 tradecraft in the finance unit.",
    "use_case": "After an APT29 advisory.",
    "trigger_examples": ["Hunt APT29 in finance"],
    "hypotheses": [
        "fin-db-01 is beaconing to external C2 over DNS",
        "svc-payroll credentials were reused for lateral movement",
        "the adversary is present somewhere",
    ],
    "attack_techniques": ["T1071.004", "T1078"],
    "data_domains": ["dns", "auth", "endpoint", "process_lineage", "made_up"],
    "objectives": ["Settle each hypothesis"],
    "phases": [
        {"id": "threat_hunter", "agent": "threat_hunter", "name": "Hunt",
         "tools": ["search_findings", "telemetry_search"], "instructions": "Hunt.\nCarefully."},
        {"id": "ghost", "agent": "no_such_agent", "tools": [], "instructions": "x"},
    ],
    "narrative": "APT29 favours DNS C2.",
}


class FakeData:
    def get_findings(self, limit: int = 10000) -> List[Dict[str, Any]]:
        return FINDINGS


class FakeClaude:
    def __init__(self, reply: str, has_key: bool = True):
        self.reply, self.has_key, self.prompts = reply, has_key, []

    def has_api_key(self) -> bool:
        return self.has_key

    def chat(self, message: str, **_: Any) -> str:
        self.prompts.append(message)
        return self.reply


def test_estate_types_entities_and_anchors_newest_finding():
    estate = read_estate(FakeData())
    assert estate.kinds == {"fin-db-01": "host", "svc-payroll": "user", "fin-app-02": "host"}
    assert estate.entity_domains["fin-db-01"] == {"dns", "endpoint"}
    assert estate.anchor["fin-db-01"] == "f-3"
    assert "net_flow" in estate.vocabulary()
    assert not {"endpoint", "process_lineage"} & set(estate.vocabulary())


def test_normalize_grounds_the_draft():
    estate = read_estate(FakeData())
    pb = normalize(DRAFT, estate, AGENTS, workflow_id="apt29-finance-hunt")

    assert pb.metadata["run_kind"] == "hunt"
    assert pb.metadata["data_domains"] == ["dns", "auth"]
    assert [p["agent"] for p in pb.metadata["phases"]] == ["threat_hunter"]
    assert pb.metadata["phases"][0]["tools"] == ["search_findings"]
    assert any("made_up" in w for w in pb.warnings)
    assert any(w.startswith("held back") and "process_lineage" in w for w in pb.warnings)
    assert any("no_such_agent" in w for w in pb.warnings)
    assert any("present somewhere" in w for w in pb.warnings)


def test_normalize_refuses_a_draft_without_hypotheses():
    with pytest.raises(SynthesisError):
        normalize({**DRAFT, "hypotheses": []}, read_estate(FakeData()), AGENTS, workflow_id="x")


def test_rendered_playbook_is_editable_by_the_activator():
    pb = normalize(DRAFT, read_estate(FakeData()), AGENTS, workflow_id="apt29-finance-hunt")
    content = render(pb)

    meta, body = _split(content)
    assert meta["hypotheses"] == pb.metadata["hypotheses"]
    assert body.startswith("# APT29 Finance Hunt")

    edited = plan_edit(content, add_data_domains=["endpoint"])
    assert edited.added_domains == ["endpoint"]
    assert _split(edited.after_content)[0]["data_domains"] == ["dns", "auth", "endpoint"]


def test_run_parameters_type_subjects_and_anchor():
    estate = read_estate(FakeData())
    pb = normalize(DRAFT, estate, AGENTS, workflow_id="apt29-finance-hunt")
    params = run_parameters(pb.metadata, estate)

    assert params["finding_id"] == "f-3"
    assert params["hypothesis_subjects"] == {
        "fin-db-01 is beaconing to external C2 over DNS": ["host:fin-db-01"],
        "svc-payroll credentials were reused for lateral movement": ["user:svc-payroll"],
    }
    assert "approve_hypotheses" not in params


@pytest.mark.asyncio
async def test_synthesize_writes_a_loadable_hunt(tmp_path, monkeypatch):
    monkeypatch.setattr(synthesizer, "_agents", lambda: AGENTS)
    claude = FakeClaude(f"```json\n{json.dumps(DRAFT)}\n```")

    result = await synthesize(
        "APT29 runs DNS C2 and reuses service account credentials.",
        taken_ids={"apt29-finance-hunt"},
        claude=claude, data_service=FakeData(), definitions_dir=tmp_path,
    )

    assert result["workflow_id"] == "apt29-finance-hunt-2"
    assert "fin-db-01" in claude.prompts[0]
    assert "endpoint" not in claude.prompts[0]
    loaded = WorkflowsService(workflows_dir=tmp_path).get_workflow("apt29-finance-hunt-2")
    assert loaded is not None
    assert loaded.metadata["data_domains"] == ["dns", "auth"]


@pytest.mark.asyncio
async def test_synthesize_without_a_provider_writes_nothing(tmp_path):
    with pytest.raises(SynthesisError):
        await synthesize(
            "APT29 runs DNS C2 and reuses credentials.", taken_ids=set(),
            claude=FakeClaude("", has_key=False), data_service=FakeData(),
            definitions_dir=tmp_path,
        )
    assert list(tmp_path.iterdir()) == []
