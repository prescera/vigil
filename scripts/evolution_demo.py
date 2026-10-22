#!/usr/bin/env python3
"""Demo: synthesize a hunt Playbook from an APT description, then evolve it.

The CLI twin of the Evolution screen's Synthesize and Evolve tabs. Calls the
service layer directly, as scripts/run_finance_hunt.py does, so it needs no
login or CSRF token -- but it does need the stack: Postgres for findings and
runs, the agent worker to execute hunt runs, and an LLM provider for synthesis.

    python scripts/evolution_demo.py synthesize "APT29 stages data on database hosts..."
    python scripts/evolution_demo.py synthesize --file apt.txt
    python scripts/evolution_demo.py run <workflow_id> -n 3
    python scripts/evolution_demo.py status <workflow_id>
    python scripts/evolution_demo.py evolve <workflow_id>
    python scripts/evolution_demo.py show <workflow_id>
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))


def _init() -> None:
    from core.storage.connection import init_database

    init_database(echo=False, create_tables=True)


def _hunt(workflow_id: str):
    from core.workflows.workflows_service import WorkflowsService

    service = WorkflowsService()
    wf = service.get_workflow(workflow_id)
    if wf is None or not wf.file_path or not wf.metadata.get("hypotheses"):
        sys.exit(f"{workflow_id} is not a file-based hunt with declared hypotheses")
    return service, wf


async def cmd_synthesize(args) -> int:
    from core.evolution.synthesizer import SynthesisError, synthesize
    from core.workflows.workflows_service import WorkflowsService

    description = Path(args.file).read_text(encoding="utf-8") if args.file else args.description
    if not description:
        sys.exit("give an APT description, or --file")
    taken = {wf["id"] for wf in WorkflowsService().list_workflows()}
    try:
        result = await synthesize(description, taken_ids=taken)
    except SynthesisError as exc:
        sys.exit(f"synthesis failed: {exc}")

    pb = result["playbook"]
    print(f"\nSynthesized {result['workflow_id']}\n  {result['path']}\n")
    print("Hypotheses:")
    for h in pb["hypotheses"]:
        print(f"  - {h}")
    print(f"ATT&CK:       {', '.join(pb['attack_techniques'])}")
    print(f"data_domains: {', '.join(pb['data_domains'])}")
    print("Phases:")
    for p in pb["phases"]:
        print(f"  - {p['name']} ({p['agent']}): {', '.join(p['tools'])}")
    for w in result["warnings"]:
        print(f"  ! {w}")
    print(f"\nNext: python scripts/evolution_demo.py run {result['workflow_id']} -n 3")
    return 0


async def cmd_run(args) -> int:
    from core.evolution.synthesizer import read_estate, run_parameters

    service, wf = _hunt(args.workflow_id)
    params = run_parameters(wf.metadata, read_estate())
    print(f"run parameters: {json.dumps(params, indent=2)}\n")
    ok = 0
    for i in range(args.count):
        result = await service.execute_workflow(args.workflow_id, params, triggered_by="evolution-demo")
        if result.get("success"):
            ok += 1
            print(f"[{i + 1}/{args.count}] enqueued run_id={result.get('run_id')}")
        else:
            print(f"[{i + 1}/{args.count}] error: {result.get('error')}", file=sys.stderr)
    print(f"\nenqueued {ok}/{args.count}. The agent worker executes them; check progress with:")
    print(f"  python scripts/evolution_demo.py status {args.workflow_id}")
    return 0 if ok else 1


async def cmd_status(args) -> int:
    from core.evolution.trace_miner import mine_workflow
    from core.workflows.workflow_run_service import WorkflowRunService

    _, wf = _hunt(args.workflow_id)
    stats = await mine_workflow(args.workflow_id, data_domains=wf.metadata.get("data_domains"))
    # The miner folds any run with a distil, in-flight ones included, so say how
    # many of those have not concluded yet.
    running = len(WorkflowRunService().list_runs(
        workflow_id=args.workflow_id, status="running", limit=200,
    ))
    print(f"\n{args.workflow_id}: {stats.run_count} run(s) to fold, {running} still running")
    print(f"data_domains: {', '.join(wf.metadata.get('data_domains') or [])}\n")
    for h in stats.hypotheses:
        print(f"- {h.statement}")
        print(f"    runs {h.run_count} · proven {h.proven_rate:.0%} · inconclusive {h.inconclusive_rate:.0%}"
              f" · domains cited {', '.join(h.cited_domains_any) or '—'}")
    if running:
        print("\nWait for the running hunts to conclude before evolving.")
    elif stats.run_count < 2:
        print("\nLet 2-3 runs finish before evolving.")
    else:
        print(f"\nNext: python scripts/evolution_demo.py evolve {args.workflow_id}")
    return 0


async def cmd_evolve(args) -> int:
    from core.evolution.controller import EvolutionController
    from core.evolution.validate import estate_availability_scorer

    _, wf = _hunt(args.workflow_id)
    before = list(wf.metadata.get("data_domains") or [])
    controller = EvolutionController(run_scorer=estate_availability_scorer(args.workflow_id))
    result = await controller.run_cycle(args.workflow_id, str(wf.file_path))

    print(f"\nstage:      {result.stage}")
    print(f"reason:     {result.reason}")
    if result.statement:
        print(f"hypothesis: {result.statement}")
    if result.proposal:
        print(f"proposed:   + data_domains {', '.join(result.proposal.get('add_data_domains') or []) or '—'}")
        for p in result.proposal.get("add_phases") or []:
            print(f"            + phase {p.get('name')} ({p.get('agent_id') or p.get('agent')})")
    if result.ab:
        print(f"A/B:        score {result.ab.get('score_before')} -> {result.ab.get('score_after')}")
    if result.stage == "activated":
        _, evolved = _hunt(args.workflow_id)
        print(f"\ndata_domains {', '.join(before)}")
        print(f"          -> {', '.join(evolved.metadata.get('data_domains') or [])}")
        print(f"\nThe playbook was rewritten: {wf.file_path}")
    return 0


async def cmd_show(args) -> int:
    _, wf = _hunt(args.workflow_id)
    print(Path(wf.file_path).read_text(encoding="utf-8"))
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Synthesize a hunt from an APT, then evolve it")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("synthesize", help="write a hunt Playbook from an APT description")
    p.add_argument("description", nargs="?")
    p.add_argument("--file", help="read the APT description from a file")

    p = sub.add_parser("run", help="enqueue hunt runs to build the trace population")
    p.add_argument("workflow_id")
    p.add_argument("-n", "--count", type=int, default=3)

    for name, help_ in (
        ("status", "finished runs and per-hypothesis outcomes"),
        ("evolve", "run one evolution cycle"),
        ("show", "print the playbook's WORKFLOW.md"),
    ):
        sub.add_parser(name, help=help_).add_argument("workflow_id")

    args = parser.parse_args()
    _init()
    handler = {
        "synthesize": cmd_synthesize, "run": cmd_run, "status": cmd_status,
        "evolve": cmd_evolve, "show": cmd_show,
    }[args.cmd]
    return asyncio.run(handler(args))


if __name__ == "__main__":
    raise SystemExit(main())
