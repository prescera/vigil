"""Persistence for evolution cycles and the crystallised Tier-1 detector set.

Backed by ``SystemConfig`` JSON (via ``ConfigService``) rather than a bespoke
table: it keeps the whole feature a thin connective layer, is hot-reloadable, and
is audit-logged for free by ``set_system_config``. Two keys:

  * ``evolution.cycles``    — {"cycles": [<cycle dict>, ...]}  (newest last)
  * ``evolution.detectors`` — {"rules": [<DetectorRule dict>, ...]}

The cold-start detector set is empty; rules appear here only via codify-back.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from core.evolution.detectors import cold_start_detectors
from core.evolution.models import DetectorRule

CYCLES_KEY = "evolution.cycles"
DETECTORS_KEY = "evolution.detectors"


class EvolutionStore:
    def __init__(self, config_service: Any = None) -> None:
        if config_service is None:
            from core.storage.config_service import get_config_service

            config_service = get_config_service()
        self._config = config_service

    # ---------------------------------------------------------------- cycles
    def list_cycles(self) -> List[Dict[str, Any]]:
        blob = self._config.get_system_config(CYCLES_KEY, {"cycles": []}) or {}
        return list(blob.get("cycles", []))

    def get_cycle(self, cycle_id: str) -> Optional[Dict[str, Any]]:
        return next((c for c in self.list_cycles() if c.get("cycle_id") == cycle_id), None)

    def save_cycle(self, cycle: Dict[str, Any]) -> None:
        """Upsert one cycle by ``cycle_id`` (delete-then-append, so a re-run of
        the same cycle replaces rather than duplicates)."""
        cycles = [c for c in self.list_cycles() if c.get("cycle_id") != cycle.get("cycle_id")]
        cycles.append(cycle)
        self._config.set_system_config(
            CYCLES_KEY,
            {"cycles": cycles},
            config_type="evolution",
            change_reason=f"cycle {cycle.get('cycle_id')} -> {cycle.get('stage')}",
        )

    # ------------------------------------------------------------- detectors
    def list_detectors(self) -> List[DetectorRule]:
        blob = self._config.get_system_config(DETECTORS_KEY, None)
        if not blob or not blob.get("rules"):
            return cold_start_detectors()
        return [DetectorRule.from_dict(r) for r in blob["rules"]]

    def save_detector(self, rule: DetectorRule) -> None:
        """Add or bump a Tier-1 detector. If one with the same id exists, keep the
        earliest ``first_cycle`` and raise ``validated_cycles`` — the rule earns
        its place by surviving across cycles, not by being re-written."""
        existing = {r.id: r for r in self.list_detectors()}
        prior = existing.get(rule.id)
        if prior is not None:
            rule.origin.setdefault("first_cycle", prior.origin.get("first_cycle"))
            rule.origin["validated_cycles"] = max(
                int(prior.origin.get("validated_cycles", 0)) + 1,
                int(rule.origin.get("validated_cycles", 1)),
            )
        existing[rule.id] = rule
        self._config.set_system_config(
            DETECTORS_KEY,
            {"rules": [r.to_dict() for r in existing.values()]},
            config_type="evolution",
            change_reason=f"crystallised detector {rule.id}",
        )
