"""The Evolution console screen's surface (auto-discovered router).

Reads: the cycle timeline, one cycle's detail, the crystallised Tier-1 detector
set, and a read-only stats preview for a workflow (a mine with no side effects).

Writes, each an explicit operator action: synthesize a hunt Playbook from an APT
description, enqueue a run of a file-based hunt to build its trace population,
and run one evolution cycle over it -- the same ``EvolutionController.run_cycle``
that ``scripts/run_evolution_cycle.py`` drives.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from core.deps import provide_workflows
from core.routing import Auth, RouterMeta
from core.workflows.workflows_service import WorkflowsService

logger = logging.getLogger(__name__)

router = APIRouter()
ROUTER_META = RouterMeta(
    prefix="/api/evolution",
    tags=["evolution"],
    auth=Auth.REQUIRED,
)


def _store():
    from core.evolution.store import EvolutionStore

    return EvolutionStore()


@router.get("/cycles")
def list_cycles() -> Dict[str, List[Dict[str, Any]]]:
    """The Evolution timeline, newest last (as persisted)."""
    return {"cycles": _store().list_cycles()}


@router.get("/cycles/{cycle_id}")
def get_cycle(cycle_id: str) -> Dict[str, Any]:
    cycle = _store().get_cycle(cycle_id)
    if cycle is None:
        raise HTTPException(status_code=404, detail=f"no evolution cycle {cycle_id}")
    return cycle


@router.get("/detectors")
def list_detectors() -> Dict[str, List[Dict[str, Any]]]:
    """The Tier-1 detector set — empty at cold start, grows via codify-back."""
    return {"detectors": [r.to_dict() for r in _store().list_detectors()]}


@router.get("/stats/{workflow_id}")
async def stats_preview(workflow_id: str) -> Dict[str, Any]:
    """A read-only mine of one workflow's finished runs — the descriptive fold the
    detectors read, surfaced for the cycle-detail 'Detected' block. No side effects."""
    from core.evolution.trace_miner import mine_workflow

    stats = await mine_workflow(workflow_id)
    return stats.to_dict()


class SynthesizeRequest(BaseModel):
    description: str = Field(..., min_length=20, max_length=20000)


def _hunt_playbook(service: WorkflowsService, workflow_id: str):
    """A file-based hunt with declared hypotheses: the only shape the miner can
    fold and the activator can rewrite."""
    workflow = service.get_workflow(workflow_id)
    if workflow is None:
        raise HTTPException(status_code=404, detail=f"Workflow not found: {workflow_id}")
    if workflow.metadata.get("run_kind") != "hunt" or not workflow.metadata.get("hypotheses"):
        raise HTTPException(
            status_code=400,
            detail=f"{workflow_id} is not a hunt with declared hypotheses",
        )
    path = getattr(workflow, "file_path", None)
    if not path or not path.exists():
        raise HTTPException(
            status_code=400,
            detail=f"{workflow_id} has no WORKFLOW.md for evolution to edit",
        )
    return workflow


@router.get("/playbooks")
def list_evolvable(service: WorkflowsService = Depends(provide_workflows)) -> Dict[str, Any]:
    """File-based hunts with declared hypotheses -- what Evolve can act on."""
    out = []
    for wf in service.list_workflows():
        try:
            definition = _hunt_playbook(service, wf["id"])
        except HTTPException:
            continue
        out.append({
            "id": wf["id"],
            "name": wf.get("name"),
            "description": wf.get("description"),
            "hypotheses": definition.metadata.get("hypotheses") or [],
            "data_domains": definition.metadata.get("data_domains") or [],
        })
    return {"playbooks": out}


@router.post("/synthesize", status_code=201)
async def synthesize_playbook(
    payload: SynthesizeRequest,
    service: WorkflowsService = Depends(provide_workflows),
) -> Dict[str, Any]:
    """Write a new hunt Playbook from a textual description of an APT."""
    from core.evolution.synthesizer import SynthesisError, synthesize

    taken = {wf["id"] for wf in service.list_workflows()}
    try:
        result = await synthesize(payload.description, taken_ids=taken)
    except SynthesisError as exc:
        raise HTTPException(status_code=502, detail=str(exc))
    service.reload()
    return result


@router.post("/playbooks/{workflow_id}/run")
async def run_playbook(
    workflow_id: str,
    service: WorkflowsService = Depends(provide_workflows),
) -> Dict[str, Any]:
    """Enqueue one headless run of a hunt, adding to the population Evolve folds."""
    from core.evolution.synthesizer import read_estate, run_parameters

    workflow = _hunt_playbook(service, workflow_id)
    params = run_parameters(workflow.metadata, read_estate())
    result = await service.execute_workflow(workflow_id, params, triggered_by="evolution")
    if not result.get("success"):
        raise HTTPException(
            status_code=500,
            detail=result.get("error") or "Could not start the hunt run",
        )
    return {"run_id": result.get("run_id"), "parameters": params}


@router.post("/playbooks/{workflow_id}/evolve")
async def evolve_playbook(
    workflow_id: str,
    service: WorkflowsService = Depends(provide_workflows),
) -> Dict[str, Any]:
    """Run one evolution cycle over the hunt's finished runs.

    Scored by ``estate_availability_scorer``, as the CLI does; a validated change
    at or above the confidence gate rewrites the WORKFLOW.md, so the workflow
    cache is reloaded afterwards.
    """
    from core.evolution.controller import EvolutionController
    from core.evolution.validate import estate_availability_scorer

    workflow = _hunt_playbook(service, workflow_id)
    controller = EvolutionController(run_scorer=estate_availability_scorer(workflow_id))
    result = await controller.run_cycle(workflow_id, str(workflow.file_path))
    service.reload()
    return result.to_dict()
