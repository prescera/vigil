"""Wazuh federation adapter."""

from __future__ import annotations

from core.federation.adapters._siem_base import SIEMIngestionAdapter
from core.federation.contract import FederationAdapter, register_adapter
from core.integrations.wazuh.ingestion import WazuhIngestion


def _factory() -> FederationAdapter:
    def make_service():

        return WazuhIngestion()

    return SIEMIngestionAdapter(
        name="wazuh",
        integration_id="wazuh",
        default_interval=300,  # SIEM cadence
        service_factory=make_service,
        external_id_prefix="wazuh",
    )


register_adapter("wazuh", _factory)
