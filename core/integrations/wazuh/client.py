"""Wazuh indexer + server API client for SIEM integration.

Wazuh splits across two HTTP surfaces. The **indexer** (an OpenSearch fork,
port 9200) stores every alert the manager raises, under ``wazuh-alerts-*``; it
is what ingestion and search read. The **server API** (port 55000) knows the
agents and their syscollector inventory; it takes basic auth once to mint a
JWT and expects that bearer token on every later call.
"""

import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

import httpx

logger = logging.getLogger(__name__)

DEFAULT_ALERTS_INDEX = "wazuh-alerts-*"

# Syscollector inventory kinds the server API exposes per agent.
INVENTORY_KINDS = ("os", "hardware", "packages", "processes", "ports", "netaddr")

# Where each IOC type shows up in a Wazuh alert. Decoders put the same concept
# under different keys (sshd writes data.srcip, Windows eventchannel writes
# data.win.eventdata.ipAddress), so a lookup has to name each of them.
IOC_FIELDS: Dict[str, List[str]] = {
    "ip": [
        "data.srcip",
        "data.dstip",
        "data.src_ip",
        "data.dest_ip",
        "agent.ip",
        "data.win.eventdata.ipAddress",
        "data.win.eventdata.sourceIp",
        "data.win.eventdata.destinationIp",
    ],
    "hash": [
        "syscheck.md5_after",
        "syscheck.sha1_after",
        "syscheck.sha256_after",
        "data.virustotal.source.md5",
        "data.virustotal.source.sha1",
    ],
    "username": [
        "data.srcuser",
        "data.dstuser",
        "data.win.eventdata.targetUserName",
        "data.win.eventdata.subjectUserName",
        "syscheck.uname_after",
    ],
    "hostname": [
        "agent.name",
        "predecoder.hostname",
        "data.win.system.computer",
    ],
}


def to_indexer_time(value: datetime) -> str:
    """Render a datetime as the ISO-8601 UTC string a range query accepts.

    Vigil's clock is naive UTC (``core.time.utcnow``); an aware value is
    converted rather than suffixed, so ``+00:00Z`` can never be produced.
    """
    if value.tzinfo is not None:
        value = value.astimezone(timezone.utc).replace(tzinfo=None)
    return value.isoformat() + "Z"


class WazuhService:
    """Client for the Wazuh indexer and (optionally) the Wazuh server API."""

    def __init__(
        self,
        indexer_url: str,
        indexer_username: Optional[str] = None,
        indexer_password: Optional[str] = None,
        api_url: Optional[str] = None,
        api_username: Optional[str] = None,
        api_password: Optional[str] = None,
        alerts_index: str = DEFAULT_ALERTS_INDEX,
        verify_ssl: bool = True,
    ):
        self.indexer_url = indexer_url.rstrip("/")
        self.indexer_username = indexer_username
        self.indexer_password = indexer_password
        self.api_url = (api_url or "").rstrip("/") or None
        self.api_username = api_username
        self.api_password = api_password
        self.alerts_index = alerts_index
        self.verify_ssl = verify_ssl

        self._indexer_client: Optional[httpx.AsyncClient] = None
        self._api_client: Optional[httpx.AsyncClient] = None
        self._api_token: Optional[str] = None

    # ------------------------------------------------------------------
    # Client lifecycle
    # ------------------------------------------------------------------

    def _build_indexer_client(self) -> httpx.AsyncClient:
        auth = None
        if self.indexer_username and self.indexer_password:
            auth = httpx.BasicAuth(self.indexer_username, self.indexer_password)
        return httpx.AsyncClient(
            base_url=self.indexer_url,
            headers={"Content-Type": "application/json"},
            auth=auth,
            verify=self.verify_ssl,
            timeout=30.0,
        )

    def _build_api_client(self) -> httpx.AsyncClient:
        if not self.api_url:
            raise ValueError("api_url is required for Wazuh server API calls")
        return httpx.AsyncClient(
            base_url=self.api_url,
            headers={"Content-Type": "application/json"},
            verify=self.verify_ssl,
            timeout=30.0,
        )

    @property
    def indexer_client(self) -> httpx.AsyncClient:
        if self._indexer_client is None or self._indexer_client.is_closed:
            self._indexer_client = self._build_indexer_client()
        return self._indexer_client

    @property
    def api_client(self) -> httpx.AsyncClient:
        if self._api_client is None or self._api_client.is_closed:
            self._api_client = self._build_api_client()
        return self._api_client

    async def close(self) -> None:
        if self._indexer_client and not self._indexer_client.is_closed:
            await self._indexer_client.aclose()
        if self._api_client and not self._api_client.is_closed:
            await self._api_client.aclose()

    # ------------------------------------------------------------------
    # Server API authentication
    # ------------------------------------------------------------------

    async def _authenticate(self) -> str:
        if not (self.api_username and self.api_password):
            raise ValueError("api_username and api_password are required")
        resp = await self.api_client.post(
            "/security/user/authenticate",
            auth=httpx.BasicAuth(self.api_username, self.api_password),
        )
        resp.raise_for_status()
        token = resp.json().get("data", {}).get("token")
        if not token:
            raise ValueError("Wazuh API returned no token")
        self._api_token = token
        return token

    async def _api_get(
        self, path: str, params: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """GET against the server API, re-authenticating once on a 401.

        Tokens expire (900s by default), so a long-lived tool process will
        eventually present a stale one; one retry with a fresh token covers
        that without looping on bad credentials.
        """
        token = self._api_token or await self._authenticate()
        resp = await self.api_client.get(
            path, params=params, headers={"Authorization": f"Bearer {token}"}
        )
        if resp.status_code == 401:
            token = await self._authenticate()
            resp = await self.api_client.get(
                path, params=params, headers={"Authorization": f"Bearer {token}"}
            )
        resp.raise_for_status()
        return resp.json()

    # ------------------------------------------------------------------
    # Connection test
    # ------------------------------------------------------------------

    async def test_connection(self) -> Tuple[bool, str]:
        """Test connectivity to the indexer (and the server API if configured)."""
        try:
            resp = await self.indexer_client.get("/")
            resp.raise_for_status()
            info = resp.json()
            version = info.get("version", {}).get("number", "unknown")
            cluster = info.get("cluster_name", "unknown")
            msg = f"Connected to Wazuh indexer {version} (cluster: {cluster})"

            if self.api_url:
                api_info = await self._api_get("/")
                api_version = api_info.get("data", {}).get("api_version", "unknown")
                msg += f"; Wazuh server API {api_version}"

            logger.info(msg)
            return True, msg

        except httpx.HTTPStatusError as exc:
            err = f"HTTP {exc.response.status_code}: {exc.response.text[:200]}"
            logger.error(f"Wazuh connection test failed: {err}")
            return False, err
        except Exception as exc:
            logger.error(f"Wazuh connection test error: {exc}")
            return False, str(exc)

    # ------------------------------------------------------------------
    # Indexer search
    # ------------------------------------------------------------------

    async def search(
        self,
        query: Dict[str, Any],
        index: Optional[str] = None,
        size: int = 100,
        sort: Optional[List[Dict[str, Any]]] = None,
    ) -> Optional[Dict[str, Any]]:
        """Run an OpenSearch query and return the raw response body."""
        target = index or self.alerts_index
        body: Dict[str, Any] = {"query": query, "size": size}
        if sort:
            body["sort"] = sort
        try:
            resp = await self.indexer_client.post(f"/{target}/_search", json=body)
            resp.raise_for_status()
            return resp.json()
        except Exception as exc:
            logger.error(f"Wazuh indexer search error: {exc}")
            return None

    async def fetch_alerts(
        self,
        start_time: datetime,
        end_time: Optional[datetime] = None,
        min_level: int = 0,
        size: int = 100,
    ) -> Optional[Dict[str, Any]]:
        """Alerts raised in a time window at or above a rule level, newest first."""
        window: Dict[str, str] = {"gte": to_indexer_time(start_time)}
        if end_time:
            window["lte"] = to_indexer_time(end_time)
        filters: List[Dict[str, Any]] = [{"range": {"timestamp": window}}]
        if min_level > 0:
            filters.append({"range": {"rule.level": {"gte": min_level}}})
        return await self.search(
            query={"bool": {"filter": filters}},
            size=size,
            sort=[{"timestamp": {"order": "desc"}}],
        )

    async def search_query_string(
        self,
        query_string: str,
        hours: int = 24,
        min_level: int = 0,
        index: Optional[str] = None,
        size: int = 100,
    ) -> Optional[Dict[str, Any]]:
        """Lucene query-string search over alerts, bounded to the last ``hours``."""
        filters: List[Dict[str, Any]] = [
            {"range": {"timestamp": {"gte": f"now-{hours}h"}}}
        ]
        if min_level > 0:
            filters.append({"range": {"rule.level": {"gte": min_level}}})
        return await self.search(
            query={
                "bool": {
                    "must": [
                        {
                            "query_string": {
                                "query": query_string or "*",
                                "default_operator": "AND",
                                "lenient": True,
                            }
                        }
                    ],
                    "filter": filters,
                }
            },
            index=index,
            size=size,
            sort=[{"timestamp": {"order": "desc"}}],
        )

    async def search_by_ioc(
        self,
        ioc_type: str,
        value: str,
        hours: int = 24,
        index: Optional[str] = None,
        size: int = 100,
    ) -> Optional[Dict[str, Any]]:
        """Alerts in the last ``hours`` whose IOC-bearing fields match ``value``."""
        fields = IOC_FIELDS.get(ioc_type)
        if not fields:
            raise ValueError(f"Unknown ioc_type: {ioc_type}")
        return await self.search(
            query={
                "bool": {
                    # lenient: several of these fields are typed ip or keyword
                    # depending on the Wazuh template version, and a hostname
                    # queried against an ip field would otherwise fail the search.
                    "must": [
                        {
                            "multi_match": {
                                "query": value,
                                "fields": fields,
                                "lenient": True,
                            }
                        }
                    ],
                    "filter": [{"range": {"timestamp": {"gte": f"now-{hours}h"}}}],
                }
            },
            index=index,
            size=size,
            sort=[{"timestamp": {"order": "desc"}}],
        )

    # ------------------------------------------------------------------
    # Server API — agents
    # ------------------------------------------------------------------

    async def list_agents(
        self,
        status: Optional[str] = None,
        search: Optional[str] = None,
        limit: int = 100,
    ) -> Optional[Dict[str, Any]]:
        """List agents, optionally filtered by status and a free-text search."""
        params: Dict[str, Any] = {"limit": limit}
        if status:
            params["status"] = status
        if search:
            params["search"] = search
        try:
            return (await self._api_get("/agents", params=params)).get("data", {})
        except Exception as exc:
            logger.error(f"Error listing Wazuh agents: {exc}")
            return None

    async def get_agent_inventory(
        self, agent_id: str, kind: str, limit: int = 100
    ) -> Optional[Dict[str, Any]]:
        """One syscollector inventory table for one agent."""
        if kind not in INVENTORY_KINDS:
            raise ValueError(f"Unknown inventory kind: {kind}")
        try:
            body = await self._api_get(
                f"/syscollector/{agent_id}/{kind}", params={"limit": limit}
            )
            return body.get("data", {})
        except Exception as exc:
            logger.error(f"Error fetching Wazuh {kind} for agent {agent_id}: {exc}")
            return None


def service_from_config(config: Dict[str, Any]) -> Optional[WazuhService]:
    """Build a client from a ``resolve(WAZUH)`` result, or None if unconfigured.

    ``resolve()`` returns every declared field, present-but-None when unset, so
    ``.get(k, default)`` would never fire; defaults are applied on ``None``.
    """
    if not config.get("indexer_url"):
        return None
    verify = config.get("verify_ssl")
    return WazuhService(
        indexer_url=config["indexer_url"],
        indexer_username=config.get("indexer_username"),
        indexer_password=config.get("indexer_password"),
        api_url=config.get("api_url"),
        api_username=config.get("api_username"),
        api_password=config.get("api_password"),
        alerts_index=config.get("alerts_index") or DEFAULT_ALERTS_INDEX,
        verify_ssl=True if verify is None else verify,
    )
