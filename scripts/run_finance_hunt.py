#!/usr/bin/env python3
"""Kick off N finance-hunt runs headless, to build the trace population the
evolution miner folds.

Each run is given a seeded finding as its target (the run-start needs at least
one of finding_id / case_id / context / hypothesis), auto-approves its hypotheses
so it advances with nobody at a terminal, and declares each hypothesis's subject
so recall keys cleanly. The three hypotheses themselves come from the finance-hunt
Playbook, so every run tests the same set — which is what lets the miner aggregate
per hypothesis across the population.

Calls the service layer directly rather than the HTTP endpoint: the API guards
POSTs with CSRF, and the execute route's own comment says daemon/headless callers
should invoke the service directly (that is what this is). Runs then execute on
the agent worker (BullMQ), so the worker must be up (./start.sh launches it) and
an LLM key must be set.

    python scripts/run_finance_hunt.py            # 12 runs
    python scripts/run_finance_hunt.py -n 15
"""

from __future__ import annotations

import argparse
import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

# Must match the hypotheses declared in
# core/workflows/definitions/finance-hunt/WORKFLOW.md exactly.
H1 = "fin-db-01 is beaconing to external C2 over DNS"
H2 = "svc-payroll credentials were reused for RDP lateral movement"
H3 = "data was exfiltrated from fin-db-02 over an encrypted web channel"

# H3 lives on its own host (fin-db-02) so the uncited endpoint/process_lineage
# evidence is scoped to H3 alone: H1's probe (fin-db-01) then finds nothing uncited
# and cannot fire, whether or not a run concludes.
HYPOTHESIS_SUBJECTS = {
    H1: ["host:fin-db-01"],
    H2: ["user:svc-payroll", "host:fin-app-02"],
    H3: ["host:fin-db-02"],
}


def _body() -> dict:
    # NB: do NOT set approve_hypotheses. It means "a human will approve the
    # hypotheses" — True pins the run's hypothesis_approval checkpoint to `ask`,
    # so the run parks at pending_approval. Omitting it keeps the config default
    # (auto), which is what a headless run needs to advance and conclude.
    return {
        "finding_id": "demo-h3-http",   # the trigger anchor; hypotheses come from the playbook
        "iterations": 8,
        "max_cost_usd": 0.75,
        "hypothesis_subjects": HYPOTHESIS_SUBJECTS,
    }


async def _run(count: int) -> int:
    from core.storage.connection import init_database

    init_database(echo=False, create_tables=True)

    from core.workflows.workflows_service import WorkflowsService

    service = WorkflowsService()
    if not service.get_workflow("finance-hunt"):
        print("finance-hunt workflow not found", file=sys.stderr)
        return 2

    ok = 0
    for i in range(count):
        try:
            result = await service.execute_workflow(
                "finance-hunt", _body(), triggered_by="evolution-demo"
            )
        except Exception as exc:  # noqa: BLE001
            print(f"[{i+1}/{count}] failed: {exc!r}", file=sys.stderr)
            continue
        if result.get("success"):
            rid = result.get("run_id") or result.get("investigation_id") or "?"
            print(f"[{i+1}/{count}] enqueued run_id={rid}")
            ok += 1
        else:
            print(f"[{i+1}/{count}] error: {result.get('error')}", file=sys.stderr)

    print(f"\nenqueued {ok}/{count} finance-hunt runs")
    print("watch them in the console (Workflows / History) or Auto Ops; once completed:")
    print("  python scripts/run_evolution_cycle.py finance-hunt")
    return 0 if ok else 1


def main() -> int:
    parser = argparse.ArgumentParser(description="Enqueue N finance-hunt runs (service layer)")
    parser.add_argument("-n", "--count", type=int, default=12)
    args = parser.parse_args()
    return asyncio.run(_run(args.count))


if __name__ == "__main__":
    raise SystemExit(main())
