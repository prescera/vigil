#!/usr/bin/env python3
"""Drive one self-evolution cycle for a workflow.

Mines the workflow's finished runs, detects a gap (Tier-1 rules, then the Tier-2
critic), locates the missing evidence, proposes a Playbook augment, and — if an
A/B scorer is wired and the change is non-regressing above the confidence gate —
activates it by rewriting the WORKFLOW.md.

Without a scorer (the default here), the cycle stops at ``proposed`` and is
recorded for the Evolution console: the A/B re-run needs the live agent stack +
a frozen memory snapshot, wired via ``core.evolution.validate.snapshot_run_scorer``
from the daemon/worker. This CLI is the manual trigger; a scheduled tick would
call the same ``EvolutionController.run_cycle``.

    python scripts/run_evolution_cycle.py finance-hunt
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

_DEFINITIONS = Path(__file__).resolve().parents[1] / "core" / "workflows" / "definitions"


async def _run(workflow_id: str) -> int:
    # Standalone script: initialise the DB engine the API/daemon would set up.
    from core.storage.connection import init_database

    init_database(echo=False, create_tables=True)

    from core.evolution.controller import EvolutionController
    from core.evolution.validate import estate_availability_scorer

    playbook_path = _DEFINITIONS / workflow_id / "WORKFLOW.md"
    if not playbook_path.exists():
        print(f"no playbook at {playbook_path}", file=sys.stderr)
        return 2

    # The A/B scorer measures whether a Playbook's data_domains give access to
    # enough corroborating telemetry in the estate to settle each hypothesis. A
    # candidate that flips the target hypothesis to proven without regression, at
    # confidence >= the gate, auto-activates (rewrites the WORKFLOW.md).
    controller = EvolutionController(run_scorer=estate_availability_scorer(workflow_id))
    result = await controller.run_cycle(workflow_id, str(playbook_path))
    print(json.dumps(result.to_dict(), indent=2, default=str))
    print()
    print(f"stage: {result.stage} — {result.reason}")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Run one workflow self-evolution cycle")
    parser.add_argument("workflow_id", help="e.g. finance-hunt")
    args = parser.parse_args()
    return asyncio.run(_run(args.workflow_id))


if __name__ == "__main__":
    raise SystemExit(main())
