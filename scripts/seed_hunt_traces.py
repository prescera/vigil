#!/usr/bin/env python3
"""Seed the finance-hunt demo estate (self-evolving workflows).

Inserts Findings into Postgres so that, when the finance-hunt workflow is run,
its three hypotheses resolve as the demo needs:

  H1 (DNS C2)      provable   — dns + auth findings on fin-db-01 (two domains)
  H2 (RDP reuse)   benign     — win_events + auth, svc-payroll from the jump host
  H3 (web exfil)   inconclusive — a single http finding on fin-db-01, PLUS endpoint
                   + process_lineage staging findings that EXIST in the estate but
                   sit outside finance-hunt's data_domains (so no run can cite them)

Plus benign background so the signals are not the only rows. The endpoint /
process_lineage findings are the "present-but-uncited" evidence the evolution
probe discovers and the augment adds.

Requires the database (run ./start.sh or docker-compose up postgres first).
Idempotent: findings use deterministic ids and are skipped if already present.

    python scripts/seed_hunt_traces.py
"""

from __future__ import annotations

import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

BASE = datetime(2026, 9, 1, 2, 0, 0, tzinfo=timezone.utc)


def _f(fid, domain, host, technique, *, users=None, desc="", offset_min=0, score=0.7):
    ts = (BASE + timedelta(minutes=offset_min)).isoformat()
    ctx = {"hostnames": [host]}
    if users:
        ctx["users"] = users
    return {
        "finding_id": fid,
        "data_source": domain,
        "timestamp": ts,
        "entity_context": ctx,
        "mitre_predictions": {technique: score} if technique else {},
        "anomaly_score": score,
        "severity": "medium",
        "status": "new",
        "description": desc,
    }


def estate_findings():
    findings = []

    # H1 — DNS C2 beacon on fin-db-01, corroborated across dns + auth.
    findings.append(_f("demo-h1-dns", "dns", "fin-db-01", "T1071.004",
                        desc="periodic TXT queries to rare newly-registered domain", offset_min=5))
    findings.append(_f("demo-h1-auth", "auth", "fin-db-01", "T1078",
                       desc="anomalous service-account logon on fin-db-01", offset_min=7))

    # H2 — RDP reuse by svc-payroll, benign (jump host, change window).
    findings.append(_f("demo-h2-winevt", "win_events", "fin-app-02", "T1021.001",
                       users=["svc-payroll"], desc="RDP logon from jump-admin-01 (change window)", offset_min=20))
    findings.append(_f("demo-h2-auth", "auth", "fin-app-02", "T1078",
                       users=["svc-payroll"], desc="svc-payroll auth, ticketed change window", offset_min=22))

    # H3 — web exfil on fin-db-02 (its OWN host, so the uncited evidence is scoped
    # to H3 and H1's probe stays clean): ONE http finding the hunt can cite ...
    findings.append(_f("demo-h3-http", "http", "fin-db-02", "T1567",
                       desc="elevated encrypted outbound bytes to a legitimate CDN", offset_min=40))
    # ... and the endpoint/process_lineage staging evidence it CANNOT (outside data_domains).
    findings.append(_f("demo-h3-endpoint-1", "endpoint", "fin-db-02", "T1074",
                       desc="archive creation + large sequential file reads (staging)", offset_min=38))
    findings.append(_f("demo-h3-endpoint-2", "endpoint", "fin-db-02", "T1074",
                       desc="7z spawned by db service account", offset_min=39))
    findings.append(_f("demo-h3-proclineage", "process_lineage", "fin-db-02", "T1059",
                       desc="sqlservr -> cmd -> 7z -> curl lineage", offset_min=41))

    # Benign background so the three signals are not the only rows.
    for i in range(8):
        findings.append(_f(f"demo-noise-cdn-{i}", "http", f"fin-ws-{i:03d}", "",
                           desc="routine CDN traffic", offset_min=60 + i, score=0.1))
        findings.append(_f(f"demo-noise-dns-{i}", "dns", f"fin-ws-{i:03d}", "",
                           desc="ordinary DNS", offset_min=70 + i, score=0.1))
    return findings


def main() -> int:
    # A standalone script does not go through the API/daemon startup, so the DB
    # engine is not yet initialised — do it here (create_tables covers a fresh DB).
    from core.storage.connection import init_database

    init_database(echo=False, create_tables=True)

    # Clean any prior demo-* findings first, so re-seeding relocates evidence
    # (e.g. H3 moving to fin-db-02) instead of ingest skipping the stale rows.
    from core.storage.connection import get_db_manager
    from sqlalchemy import text

    with get_db_manager().session_scope() as session:
        # child rows first to satisfy FKs; ignore if a table is absent
        for child in ("finding_mitre_predictions",):
            try:
                session.execute(
                    text(f"DELETE FROM {child} WHERE finding_id LIKE 'demo-%'")
                )
            except Exception:  # noqa: BLE001
                pass
        deleted = session.execute(
            text("DELETE FROM findings WHERE finding_id LIKE 'demo-%'")
        ).rowcount
    print(f"cleared {deleted} prior demo-* findings")

    from core.ingestion.ingestion_service import IngestionService

    svc = IngestionService()
    findings = estate_findings()
    ok = sum(1 for f in findings if svc.ingest_finding(f))
    print(f"seeded {ok}/{len(findings)} findings for the finance-hunt estate")
    print("stats:", svc.stats)
    print()
    print("next:")
    print("  1. run the finance-hunt workflow a dozen times (needs the agent worker):")
    print("     POST /api/workflows/finance-hunt/execute  (repeat), or enqueue via the console")
    print("  2. drive one evolution cycle:")
    print("     python scripts/run_evolution_cycle.py finance-hunt")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
