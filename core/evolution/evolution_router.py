"""Read surface for the Evolution console screen (auto-discovered router).

Exposes the cycle timeline, one cycle's detail, the crystallised Tier-1 detector
set, and a read-only stats preview for a workflow (a mine with no side effects).
Activation/promotion is driven by the controller from the daemon, not by a GET
here, so this router stays read-only.
"""

from __future__ import annotations

from typing import Any, Dict, List

from fastapi import APIRouter, HTTPException

from core.routing import Auth, RouterMeta

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
