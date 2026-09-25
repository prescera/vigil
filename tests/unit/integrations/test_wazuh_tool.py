"""MCP tool server reads Wazuh config through resolve(), not WAZUH_* env."""

import json
from unittest.mock import AsyncMock, patch

import pytest

from core.integrations.wazuh import tool as wazuh_tool

pytestmark = pytest.mark.unit


@pytest.fixture(autouse=True)
def _reset_cached_service():
    wazuh_tool._wazuh_service = None
    yield
    wazuh_tool._wazuh_service = None


def _resolved(**overrides):
    config = {
        "indexer_url": "https://indexer.test:9200",
        "indexer_username": "admin",
        "indexer_password": "secret-from-store",
        "api_url": None,
        "api_username": None,
        "api_password": None,
        "alerts_index": None,
        "min_rule_level": None,
        "verify_ssl": None,
    }
    config.update(overrides)
    return config


def _payload(content):
    return json.loads(content[0].text)


def test_resolved_fields_reach_the_client():
    with patch.object(wazuh_tool, "resolve", return_value=_resolved()):
        svc = wazuh_tool.get_wazuh_service()
    assert svc is not None
    assert svc.indexer_password == "secret-from-store"
    assert svc.alerts_index == "wazuh-alerts-*"


def test_missing_indexer_is_not_configured():
    with patch.object(wazuh_tool, "resolve", return_value=_resolved(indexer_url=None)):
        assert wazuh_tool.get_wazuh_service() is None


@pytest.mark.parametrize(
    ("raw", "hours"), [("24h", 24), ("7d", 168), (12, 12), ("junk", 24)]
)
def test_time_range_parsing(raw, hours):
    assert wazuh_tool._hours(raw) == hours


@pytest.mark.asyncio
async def test_unconfigured_call_says_so():
    with patch.object(wazuh_tool, "resolve", return_value=_resolved(indexer_url=None)):
        out = _payload(
            await wazuh_tool.handle_call_tool("wazuh_search_alerts", {"query": "*"})
        )
    assert out == {"error": "Wazuh service not configured"}


@pytest.mark.asyncio
async def test_search_alerts_caps_rows_and_summarizes():
    with patch.object(wazuh_tool, "resolve", return_value=_resolved()):
        svc = wazuh_tool.get_wazuh_service()
    svc.search_query_string = AsyncMock(
        return_value={
            "hits": {
                "total": {"value": 1},
                "hits": [
                    {
                        "_id": "a1",
                        "_source": {
                            "timestamp": "2026-09-25T10:00:00.000+0000",
                            "rule": {
                                "id": "5712",
                                "level": 10,
                                "mitre": {"id": ["T1110"]},
                            },
                            "agent": {"id": "003", "name": "web01"},
                        },
                    }
                ],
            }
        }
    )

    out = _payload(
        await wazuh_tool.handle_call_tool(
            "wazuh_search_alerts",
            {"query": "rule.id:5712", "time_range": "7d", "max_results": 5000},
        )
    )

    kwargs = svc.search_query_string.call_args.kwargs
    assert kwargs["hours"] == 168
    assert kwargs["size"] == 500
    assert out["total"] == 1
    assert out["results"][0]["rule_id"] == "5712"
    assert out["results"][0]["mitre"] == ["T1110"]


@pytest.mark.asyncio
async def test_agent_tools_need_the_server_api():
    with patch.object(wazuh_tool, "resolve", return_value=_resolved()):
        out = _payload(await wazuh_tool.handle_call_tool("wazuh_list_agents", {}))
    assert "api_url" in out["error"]


@pytest.mark.asyncio
async def test_listed_tools_are_the_ones_dispatched():
    names = {t.name for t in await wazuh_tool.handle_list_tools()}
    assert names == {
        "wazuh_search_alerts",
        "wazuh_search_by_ioc",
        "wazuh_list_agents",
        "wazuh_get_agent_inventory",
    }
