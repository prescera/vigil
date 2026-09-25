"""Wazuh descriptor — source of truth for Wazuh's registry entries."""

from core.integrations._base.descriptor import (
    IntegrationDescriptor,
    IntegrationField,
    register_descriptor,
)

WAZUH = register_descriptor(
    IntegrationDescriptor(
        id="wazuh",
        category="SIEM",
        mcp_server_names=("wazuh",),
        fields=(
            # Wazuh indexer (OpenSearch): where alerts live. Required for
            # ingestion and search.
            IntegrationField("indexer_url"),
            IntegrationField("indexer_username"),
            IntegrationField("indexer_password", secret=True),
            # Wazuh server API: agents and their inventory. Optional.
            IntegrationField("api_url"),
            IntegrationField("api_username"),
            IntegrationField("api_password", secret=True),
            IntegrationField("alerts_index"),
            IntegrationField("min_rule_level", value_type="int"),
            IntegrationField("verify_ssl", value_type="bool"),
        ),
    )
)
