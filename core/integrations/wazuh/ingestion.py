"""
Wazuh Ingestion Service - Ingest alerts from the Wazuh indexer.

Reads ``wazuh-alerts-*`` directly and converts each alert to a finding. Wazuh has
no alert workflow status, so there is no upstream status sync to push back to.
"""

import logging
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from core.ingestion.siem_ingestion_service import SIEMIngestionService
from core.integrations._base.config import resolve
from core.integrations.wazuh.client import WazuhService, service_from_config
from core.integrations.wazuh.descriptor import WAZUH
from core.time import utcnow

logger = logging.getLogger(__name__)

# Wazuh raises a great many level 3-6 alerts (logins, service starts, file
# integrity noise). Ingesting all of them floods the queue with findings nobody
# triages, so ingestion starts where the Wazuh dashboard's "medium" band does.
DEFAULT_MIN_RULE_LEVEL = 7

# Compliance tags Wazuh rules carry, surfaced as finding metadata.
_COMPLIANCE_KEYS = ("pci_dss", "gdpr", "hipaa", "nist_800_53", "tsc", "gpg13")


def severity_for_level(level: Any) -> str:
    """Map a Wazuh rule level (0-15) to a Vigil severity.

    Bands follow the Wazuh dashboard: 15 critical, 12-14 high, 7-11 medium,
    4-6 low, below that informational.
    """
    try:
        value = int(level)
    except (TypeError, ValueError):
        return "medium"
    if value >= 15:
        return "critical"
    if value >= 12:
        return "high"
    if value >= 7:
        return "medium"
    if value >= 4:
        return "low"
    return "info"


def _normalize_timestamp(raw: Any) -> str:
    """Wazuh writes ``2024-01-15T10:23:45.123+0000``; return ISO-8601 naive UTC."""
    if not raw:
        return utcnow().isoformat()
    try:
        parsed = datetime.strptime(str(raw), "%Y-%m-%dT%H:%M:%S.%f%z")
    except ValueError:
        try:
            parsed = datetime.fromisoformat(str(raw).replace("Z", "+00:00"))
        except ValueError:
            return str(raw)
    if parsed.tzinfo is not None:
        parsed = parsed.astimezone(timezone.utc).replace(tzinfo=None)
    return parsed.isoformat()


def _append(bucket: List[str], value: Any) -> None:
    if value and str(value) not in bucket:
        bucket.append(str(value))


class WazuhIngestion(SIEMIngestionService):
    """Wazuh ingestion service."""

    def __init__(self):
        super().__init__()
        self.siem_name = "Wazuh"
        self.config = resolve(WAZUH)
        self._wazuh_service: Optional[WazuhService] = None

    def _get_wazuh_service(self) -> Optional[WazuhService]:
        if self._wazuh_service:
            return self._wazuh_service
        try:
            self._wazuh_service = service_from_config(self.config)
            if self._wazuh_service is None:
                logger.error("Wazuh configuration incomplete: missing indexer_url")
            return self._wazuh_service
        except Exception as e:
            logger.error(f"Error creating Wazuh service: {e}")
            return None

    @property
    def min_rule_level(self) -> int:
        level = self.config.get("min_rule_level")
        return DEFAULT_MIN_RULE_LEVEL if level is None else level

    async def fetch_alerts(
        self,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        limit: int = 100,
    ) -> List[Dict[str, Any]]:
        try:
            svc = self._get_wazuh_service()
            if not svc:
                return []

            if not start_time:
                start_time = utcnow() - timedelta(hours=24)

            result = await svc.fetch_alerts(
                start_time=start_time,
                end_time=end_time,
                min_level=self.min_rule_level,
                size=limit,
            )
            if not result:
                return []

            hits = result.get("hits", {}).get("hits", [])
            logger.info(f"Fetched {len(hits)} alerts from Wazuh")
            return hits
        except Exception as e:
            logger.error(f"Error fetching Wazuh alerts: {e}")
            return []

    def transform_alert_to_finding(
        self, alert: Dict[str, Any]
    ) -> Optional[Dict[str, Any]]:
        try:
            source = alert.get("_source", {})
            # The indexer _id, not the alert's own ``id``: the latter is
            # "<epoch>.<offset>" and only unique per manager node.
            alert_id = alert.get("_id") or source.get("id") or uuid.uuid4().hex[:12]
            finding_id = f"wazuh-{alert_id}"

            rule = source.get("rule", {}) or {}
            agent = source.get("agent", {}) or {}
            data = source.get("data", {}) or {}
            win = (data.get("win", {}) or {}).get("eventdata", {}) or {}
            syscheck = source.get("syscheck", {}) or {}

            title = rule.get("description") or "Wazuh Alert"
            description = source.get("full_log") or title

            entity_context: Dict[str, List[str]] = {
                "src_ips": [],
                "dest_ips": [],
                "hostnames": [],
                "usernames": [],
                "file_hashes": [],
            }
            for key in ("srcip", "src_ip"):
                _append(entity_context["src_ips"], data.get(key))
            _append(entity_context["src_ips"], win.get("ipAddress"))
            for key in ("dstip", "dest_ip"):
                _append(entity_context["dest_ips"], data.get(key))
            _append(entity_context["hostnames"], agent.get("name"))
            for key in ("srcuser", "dstuser"):
                _append(entity_context["usernames"], data.get(key))
            _append(entity_context["usernames"], win.get("targetUserName"))
            for key in ("sha256_after", "sha1_after", "md5_after"):
                _append(entity_context["file_hashes"], syscheck.get(key))

            mitre = rule.get("mitre", {}) or {}
            mitre_predictions: Dict[str, float] = {
                str(tid): 0.9 for tid in (mitre.get("id") or []) if tid
            }

            level = rule.get("level")
            return {
                "finding_id": finding_id,
                "data_source": "wazuh",
                "timestamp": _normalize_timestamp(source.get("timestamp")),
                "severity": severity_for_level(level),
                "status": "new",
                "title": title,
                "description": description[:500] if description else "",
                "entity_context": entity_context,
                "raw_event": alert,
                "anomaly_score": 0.5,
                "mitre_predictions": mitre_predictions,
                "metadata": {
                    "wazuh_alert_id": source.get("id", ""),
                    "rule_id": rule.get("id", ""),
                    "rule_name": title,
                    "rule_level": level,
                    "rule_groups": rule.get("groups", []),
                    "agent_id": agent.get("id", ""),
                    "agent_name": agent.get("name", ""),
                    "agent_ip": agent.get("ip", ""),
                    "manager": (source.get("manager", {}) or {}).get("name", ""),
                    "location": source.get("location", ""),
                    "decoder": (source.get("decoder", {}) or {}).get("name", ""),
                    "index": alert.get("_index", ""),
                    "compliance": {
                        key: rule[key] for key in _COMPLIANCE_KEYS if rule.get(key)
                    },
                },
            }
        except Exception as e:
            logger.error(f"Error transforming Wazuh alert: {e}")
            return None
