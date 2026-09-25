"""Unit tests for core/integrations/wazuh/client.py."""

import json
from datetime import datetime

import httpx
import pytest
import respx

from core.integrations.wazuh.client import WazuhService, service_from_config

pytestmark = pytest.mark.unit

INDEXER = "https://indexer.test:9200"
API = "https://manager.test:55000"


@pytest.fixture
def service():
    return WazuhService(
        indexer_url=INDEXER,
        indexer_username="admin",
        indexer_password="secret",
        api_url=API,
        api_username="wazuh-wui",
        api_password="api-secret",
        verify_ssl=False,
    )


class TestConstruction:
    def test_api_client_requires_url(self):
        svc = WazuhService(indexer_url=INDEXER)
        with pytest.raises(ValueError, match="api_url is required"):
            svc._build_api_client()

    def test_config_defaults_apply_on_none(self):
        svc = service_from_config(
            {
                "indexer_url": INDEXER,
                "alerts_index": None,
                "verify_ssl": None,
            }
        )
        assert svc.alerts_index == "wazuh-alerts-*"
        assert svc.verify_ssl is True

    def test_verify_ssl_false_is_preserved(self):
        svc = service_from_config({"indexer_url": INDEXER, "verify_ssl": False})
        assert svc.verify_ssl is False

    def test_missing_indexer_is_unconfigured(self):
        assert service_from_config({"indexer_url": None}) is None


class TestIndexer:
    @respx.mock
    @pytest.mark.asyncio
    async def test_fetch_alerts_filters_window_and_level(self, service):
        route = respx.post(f"{INDEXER}/wazuh-alerts-*/_search").mock(
            return_value=httpx.Response(200, json={"hits": {"hits": []}})
        )

        await service.fetch_alerts(
            start_time=datetime(2026, 9, 25, 10, 0), min_level=7, size=25
        )

        body = json.loads(route.calls[0].request.content)
        filters = body["query"]["bool"]["filter"]
        assert {"range": {"timestamp": {"gte": "2026-09-25T10:00:00Z"}}} in filters
        assert {"range": {"rule.level": {"gte": 7}}} in filters
        assert body["size"] == 25
        assert body["sort"] == [{"timestamp": {"order": "desc"}}]
        assert route.calls[0].request.headers["Authorization"].startswith("Basic ")
        await service.close()

    @respx.mock
    @pytest.mark.asyncio
    async def test_level_zero_adds_no_level_filter(self, service):
        route = respx.post(f"{INDEXER}/wazuh-alerts-*/_search").mock(
            return_value=httpx.Response(200, json={"hits": {"hits": []}})
        )
        await service.fetch_alerts(start_time=datetime(2026, 9, 25), min_level=0)
        filters = json.loads(route.calls[0].request.content)["query"]["bool"]["filter"]
        assert len(filters) == 1
        await service.close()

    @respx.mock
    @pytest.mark.asyncio
    async def test_search_by_ioc_names_decoder_fields(self, service):
        route = respx.post(f"{INDEXER}/wazuh-alerts-*/_search").mock(
            return_value=httpx.Response(200, json={"hits": {"hits": []}})
        )
        await service.search_by_ioc("ip", "203.0.113.7", hours=48)
        body = json.loads(route.calls[0].request.content)
        match = body["query"]["bool"]["must"][0]["multi_match"]
        assert match["query"] == "203.0.113.7"
        assert "data.srcip" in match["fields"]
        assert "data.win.eventdata.ipAddress" in match["fields"]
        assert match["lenient"] is True
        assert body["query"]["bool"]["filter"][0]["range"]["timestamp"]["gte"] == (
            "now-48h"
        )
        await service.close()

    @pytest.mark.asyncio
    async def test_search_by_unknown_ioc_type_raises(self, service):
        with pytest.raises(ValueError):
            await service.search_by_ioc("domain", "example.com")

    @respx.mock
    @pytest.mark.asyncio
    async def test_search_error_returns_none(self, service):
        respx.post(f"{INDEXER}/wazuh-alerts-*/_search").mock(
            return_value=httpx.Response(500, text="boom")
        )
        assert await service.search({"match_all": {}}) is None
        await service.close()


class TestServerApi:
    @respx.mock
    @pytest.mark.asyncio
    async def test_authenticates_then_sends_bearer(self, service):
        auth = respx.post(f"{API}/security/user/authenticate").mock(
            return_value=httpx.Response(200, json={"data": {"token": "jwt-1"}})
        )
        agents = respx.get(f"{API}/agents").mock(
            return_value=httpx.Response(
                200,
                json={
                    "data": {
                        "affected_items": [{"id": "001"}],
                        "total_affected_items": 1,
                    }
                },
            )
        )

        data = await service.list_agents(status="active")

        assert data["total_affected_items"] == 1
        assert auth.calls[0].request.headers["Authorization"].startswith("Basic ")
        request = agents.calls[0].request
        assert request.headers["Authorization"] == "Bearer jwt-1"
        assert request.url.params["status"] == "active"
        await service.close()

    @respx.mock
    @pytest.mark.asyncio
    async def test_reauthenticates_once_on_expired_token(self, service):
        service._api_token = "stale"
        respx.post(f"{API}/security/user/authenticate").mock(
            return_value=httpx.Response(200, json={"data": {"token": "fresh"}})
        )
        route = respx.get(f"{API}/syscollector/003/processes").mock(
            side_effect=[
                httpx.Response(401),
                httpx.Response(200, json={"data": {"affected_items": []}}),
            ]
        )

        data = await service.get_agent_inventory("003", "processes")

        assert data == {"affected_items": []}
        assert route.calls[1].request.headers["Authorization"] == "Bearer fresh"
        await service.close()

    @pytest.mark.asyncio
    async def test_unknown_inventory_kind_raises(self, service):
        with pytest.raises(ValueError):
            await service.get_agent_inventory("003", "users")

    @respx.mock
    @pytest.mark.asyncio
    async def test_connection_reports_both_surfaces(self, service):
        respx.get(f"{INDEXER}/").mock(
            return_value=httpx.Response(
                200,
                json={"cluster_name": "wazuh-cluster", "version": {"number": "2.13.0"}},
            )
        )
        respx.post(f"{API}/security/user/authenticate").mock(
            return_value=httpx.Response(200, json={"data": {"token": "t"}})
        )
        respx.get(f"{API}/").mock(
            return_value=httpx.Response(200, json={"data": {"api_version": "4.9.0"}})
        )

        ok, msg = await service.test_connection()

        assert ok is True
        assert "2.13.0" in msg and "wazuh-cluster" in msg and "4.9.0" in msg
        await service.close()
