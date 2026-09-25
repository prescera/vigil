"""Unit tests for core/integrations/wazuh/ingestion.py."""

import json
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from core.integrations.wazuh.ingestion import (
    DEFAULT_MIN_RULE_LEVEL,
    WazuhIngestion,
    severity_for_level,
)

pytestmark = pytest.mark.unit

FIXTURES_DIR = Path(__file__).resolve().parent.parent.parent / "fixtures"


def _config(**overrides):
    config = {
        "indexer_url": "https://indexer.test:9200",
        "indexer_username": "admin",
        "indexer_password": "secret",
        "api_url": None,
        "api_username": None,
        "api_password": None,
        "alerts_index": None,
        "min_rule_level": None,
        "verify_ssl": None,
    }
    config.update(overrides)
    return config


@pytest.fixture
def sample_alerts():
    with open(FIXTURES_DIR / "wazuh_alerts.json") as f:
        return json.load(f)


def _ingestion(**overrides):
    with patch("core.integrations.wazuh.ingestion.resolve") as mock_resolve:
        mock_resolve.return_value = _config(**overrides)
        svc = WazuhIngestion()
    svc.ingestion_service = MagicMock()
    return svc


@pytest.fixture
def ingestion():
    return _ingestion()


class TestSeverity:
    @pytest.mark.parametrize(
        ("level", "expected"),
        [
            (15, "critical"),
            (12, "high"),
            (14, "high"),
            (7, "medium"),
            (11, "medium"),
            (4, "low"),
            (3, "info"),
            ("10", "medium"),
            (None, "medium"),
        ],
    )
    def test_bands_follow_the_wazuh_dashboard(self, level, expected):
        assert severity_for_level(level) == expected


class TestTransformAlert:
    def test_sshd_brute_force(self, ingestion, sample_alerts):
        finding = ingestion.transform_alert_to_finding(sample_alerts[0])
        assert finding["finding_id"] == "wazuh-Xk3bQ5IBv1a2c3d4e5f6"
        assert finding["data_source"] == "wazuh"
        assert finding["severity"] == "medium"
        assert finding["title"].startswith("sshd: brute force")
        assert finding["timestamp"] == "2026-09-25T10:23:45.123000"
        assert finding["entity_context"]["src_ips"] == ["203.0.113.7"]
        assert finding["entity_context"]["hostnames"] == ["web01"]
        assert finding["entity_context"]["usernames"] == ["oracle"]
        assert finding["mitre_predictions"] == {"T1110": 0.9}
        meta = finding["metadata"]
        assert meta["rule_id"] == "5712"
        assert meta["rule_level"] == 10
        assert meta["agent_id"] == "003"
        assert meta["wazuh_alert_id"] == "1758795825.4412"
        assert meta["compliance"]["pci_dss"] == ["11.4", "10.2.4", "10.2.5"]
        assert "Invalid user oracle" in finding["description"]

    def test_windows_eventdata_entities(self, ingestion, sample_alerts):
        finding = ingestion.transform_alert_to_finding(sample_alerts[1])
        assert finding["severity"] == "high"
        assert finding["entity_context"]["src_ips"] == ["10.0.3.44"]
        assert finding["entity_context"]["usernames"] == ["svc_backup"]
        assert set(finding["mitre_predictions"]) == {"T1110.001", "T1078"}
        # No full_log: description falls back to the rule description.
        assert finding["description"] == "Multiple Windows logon failures"

    def test_syscheck_hashes(self, ingestion, sample_alerts):
        finding = ingestion.transform_alert_to_finding(sample_alerts[2])
        assert finding["severity"] == "critical"
        hashes = finding["entity_context"]["file_hashes"]
        assert hashes[0].startswith("a3f5c9e1")
        assert "0f1e2d3c4b5a69788796a5b4c3d2e1f0" in hashes
        assert finding["mitre_predictions"] == {}

    def test_minimal_alert_does_not_crash(self, ingestion):
        finding = ingestion.transform_alert_to_finding({"_id": "x1", "_source": {}})
        assert finding["finding_id"] == "wazuh-x1"
        assert finding["title"] == "Wazuh Alert"


class TestFetchAlerts:
    @pytest.mark.asyncio
    async def test_defaults_to_the_ingestion_min_level(self, ingestion, sample_alerts):
        svc = MagicMock()
        svc.fetch_alerts = AsyncMock(return_value={"hits": {"hits": sample_alerts}})
        ingestion._wazuh_service = svc

        alerts = await ingestion.fetch_alerts(
            start_time=datetime(2026, 9, 25), limit=50
        )

        assert len(alerts) == 3
        kwargs = svc.fetch_alerts.call_args.kwargs
        assert kwargs["min_level"] == DEFAULT_MIN_RULE_LEVEL
        assert kwargs["size"] == 50

    @pytest.mark.asyncio
    async def test_configured_min_level_zero_is_honoured(self, sample_alerts):
        # 0 is a real setting ("everything"), not unset.
        ingestion = _ingestion(min_rule_level=0)
        svc = MagicMock()
        svc.fetch_alerts = AsyncMock(return_value={"hits": {"hits": []}})
        ingestion._wazuh_service = svc

        await ingestion.fetch_alerts(start_time=datetime(2026, 9, 25))

        assert svc.fetch_alerts.call_args.kwargs["min_level"] == 0

    @pytest.mark.asyncio
    async def test_unconfigured_returns_empty(self):
        ingestion = _ingestion(indexer_url=None)
        assert await ingestion.fetch_alerts() == []

    @pytest.mark.asyncio
    async def test_search_failure_returns_empty(self, ingestion):
        svc = MagicMock()
        svc.fetch_alerts = AsyncMock(return_value=None)
        ingestion._wazuh_service = svc
        assert await ingestion.fetch_alerts() == []


@pytest.mark.asyncio
async def test_no_upstream_status_sync(ingestion):
    with pytest.raises(NotImplementedError):
        await ingestion.update_upstream_alert_status("x", "closed")


def test_adapter_registers_under_wazuh():
    from core.federation.registry import get_adapter

    with patch("core.federation.adapters._siem_base.is_integration_enabled") as on:
        on.return_value = False
        adapter = get_adapter("wazuh")
    assert adapter is not None
    assert adapter.name == "wazuh"
    assert adapter.default_interval() == 300


def test_aware_datetimes_render_without_a_double_offset():
    from core.integrations.wazuh.client import to_indexer_time

    aware = datetime(2026, 9, 25, 12, 0, tzinfo=timezone.utc)
    assert to_indexer_time(aware) == "2026-09-25T12:00:00Z"
    assert to_indexer_time(datetime(2026, 9, 25, 12, 0)) == "2026-09-25T12:00:00Z"
