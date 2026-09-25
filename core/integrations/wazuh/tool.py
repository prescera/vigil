"""Wazuh MCP tool server.

Exposes Wazuh indexer alert search and server API agent inventory as MCP tools
for use by Vigil's AI agents. Read-only: active response is deliberately not
exposed here, because containment belongs behind the approval workflow in
``core.response``.
"""

import sys
from pathlib import Path

# Spawned as ``python3 core/integrations/wazuh/tool.py`` with a narrowed env, so
# the repo root is not on sys.path and PYTHONPATH is not forwarded. Add it here so
# the ``core.*`` imports below resolve; otherwise they fail and every query
# silently reports "not configured".
_REPO_ROOT = str(Path(__file__).resolve().parents[3])
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

import asyncio
import json
import logging

import mcp.server.stdio
import mcp.types as types
from mcp.server import NotificationOptions, Server
from mcp.server.models import InitializationOptions

from core.integrations._base.config import resolve
from core.integrations.wazuh.client import (
    INVENTORY_KINDS,
    IOC_FIELDS,
    service_from_config,
)
from core.integrations.wazuh.descriptor import WAZUH

logger = logging.getLogger(__name__)
_wazuh_service = None

# The telemetry_search capability bound caps a call at 500 rows.
_MAX_RESULTS = 500


def result(data):
    return [types.TextContent(type="text", text=json.dumps(data, indent=2))]


def get_wazuh_service():
    global _wazuh_service
    if _wazuh_service is not None:
        return _wazuh_service
    try:
        _wazuh_service = service_from_config(resolve(WAZUH))
        return _wazuh_service
    except Exception:
        return None


def _hours(time_range) -> int:
    """'24h' / '7d' / 12 -> hours. Falls back to 24 on anything unreadable."""
    text = str(time_range or "24h").strip().lower()
    try:
        if text.endswith("d"):
            return int(text[:-1]) * 24
        if text.endswith("h"):
            return int(text[:-1])
        return int(text)
    except ValueError:
        return 24


def _summarize(hit: dict) -> dict:
    source = hit.get("_source", {})
    rule = source.get("rule", {}) or {}
    agent = source.get("agent", {}) or {}
    return {
        "_id": hit.get("_id"),
        "timestamp": source.get("timestamp"),
        "rule_id": rule.get("id"),
        "rule_level": rule.get("level"),
        "rule_description": rule.get("description"),
        "rule_groups": rule.get("groups", []),
        "mitre": (rule.get("mitre", {}) or {}).get("id", []),
        "agent": {
            "id": agent.get("id"),
            "name": agent.get("name"),
            "ip": agent.get("ip"),
        },
        "location": source.get("location"),
        "data": source.get("data", {}),
        "full_log": (source.get("full_log") or "")[:1000],
    }


def _hits_result(data: dict, **extra) -> list:
    hits = data.get("hits", {})
    total = hits.get("total", {})
    return result(
        {
            **extra,
            "total": total.get("value", 0) if isinstance(total, dict) else total,
            "results": [_summarize(h) for h in hits.get("hits", [])],
        }
    )


# ------------------------------------------------------------------
# Tool listing
# ------------------------------------------------------------------


async def handle_list_tools():
    return [
        types.Tool(
            name="wazuh_search_alerts",
            description=(
                "Search Wazuh alerts with a Lucene query string, e.g. "
                "'rule.groups:authentication_failed AND agent.name:web01' or "
                "'data.srcip:203.0.113.7'. Fields follow the wazuh-alerts schema "
                "(rule.*, agent.*, data.*, syscheck.*, full_log)."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "query": {
                        "type": "string",
                        "description": "Lucene query string; '*' for everything",
                    },
                    "time_range": {
                        "type": "string",
                        "description": "Relative time range, e.g. '24h', '7d'",
                        "default": "24h",
                    },
                    "min_level": {
                        "type": "integer",
                        "description": "Minimum Wazuh rule level (0-15)",
                        "default": 0,
                    },
                    "index": {
                        "type": "string",
                        "description": "Target index (default: configured alerts index)",
                    },
                    "max_results": {"type": "integer", "default": 100},
                },
                "required": ["query"],
            },
        ),
        types.Tool(
            name="wazuh_search_by_ioc",
            description="Search Wazuh alerts for an IOC (IP, file hash, username, hostname)",
            inputSchema={
                "type": "object",
                "properties": {
                    "ioc_type": {"type": "string", "enum": sorted(IOC_FIELDS)},
                    "ioc_value": {"type": "string"},
                    "hours": {"type": "integer", "default": 24},
                    "index": {"type": "string"},
                    "max_results": {"type": "integer", "default": 100},
                },
                "required": ["ioc_type", "ioc_value"],
            },
        ),
        types.Tool(
            name="wazuh_list_agents",
            description=(
                "List Wazuh agents (endpoints) with status, OS, IP and last "
                "keep-alive. Requires the Wazuh server API to be configured."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "status": {
                        "type": "string",
                        "enum": [
                            "active",
                            "disconnected",
                            "pending",
                            "never_connected",
                        ],
                    },
                    "search": {
                        "type": "string",
                        "description": "Free-text match on name, IP, OS, etc.",
                    },
                    "max_results": {"type": "integer", "default": 100},
                },
            },
        ),
        types.Tool(
            name="wazuh_get_agent_inventory",
            description=(
                "Fetch one syscollector inventory table (processes, ports, "
                "packages, network addresses, OS, hardware) for a Wazuh agent. "
                "Requires the Wazuh server API to be configured."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "agent_id": {
                        "type": "string",
                        "description": "Wazuh agent ID, e.g. '001'",
                    },
                    "kind": {"type": "string", "enum": list(INVENTORY_KINDS)},
                    "max_results": {"type": "integer", "default": 100},
                },
                "required": ["agent_id", "kind"],
            },
        ),
    ]


# ------------------------------------------------------------------
# Tool dispatch
# ------------------------------------------------------------------


async def handle_call_tool(name: str, arguments: dict | None):
    svc = get_wazuh_service()
    if svc is None:
        return result({"error": "Wazuh service not configured"})

    args = arguments or {}
    if name == "wazuh_search_alerts":
        return await _search_alerts(svc, args)
    elif name == "wazuh_search_by_ioc":
        return await _search_by_ioc(svc, args)
    elif name == "wazuh_list_agents":
        return await _list_agents(svc, args)
    elif name == "wazuh_get_agent_inventory":
        return await _get_agent_inventory(svc, args)
    else:
        return result({"error": f"Unknown tool: {name}"})


async def _search_alerts(svc, args: dict):
    data = await svc.search_query_string(
        args.get("query") or "*",
        hours=_hours(args.get("time_range")),
        min_level=int(args.get("min_level") or 0),
        index=args.get("index"),
        size=min(int(args.get("max_results") or 100), _MAX_RESULTS),
    )
    if data is None:
        return result({"error": "Search failed"})
    return _hits_result(data)


async def _search_by_ioc(svc, args: dict):
    ioc_type = args["ioc_type"]
    ioc_value = args["ioc_value"]
    if ioc_type not in IOC_FIELDS:
        return result({"error": f"Unknown ioc_type: {ioc_type}"})

    data = await svc.search_by_ioc(
        ioc_type,
        ioc_value,
        hours=int(args.get("hours") or 24),
        index=args.get("index"),
        size=min(int(args.get("max_results") or 100), _MAX_RESULTS),
    )
    if data is None:
        return result({"error": "Search failed"})
    return _hits_result(data, ioc_type=ioc_type, ioc_value=ioc_value)


async def _list_agents(svc, args: dict):
    if not svc.api_url:
        return result({"error": "Wazuh server API (api_url) not configured"})
    data = await svc.list_agents(
        status=args.get("status"),
        search=args.get("search"),
        limit=min(int(args.get("max_results") or 100), _MAX_RESULTS),
    )
    if data is None:
        return result({"error": "Failed to list agents"})
    return result(
        {
            "total": data.get("total_affected_items", 0),
            "agents": [
                {
                    "id": a.get("id"),
                    "name": a.get("name"),
                    "ip": a.get("ip"),
                    "status": a.get("status"),
                    "os": (a.get("os", {}) or {}).get("name"),
                    "version": a.get("version"),
                    "group": a.get("group", []),
                    "last_keep_alive": a.get("lastKeepAlive"),
                }
                for a in data.get("affected_items", [])
            ],
        }
    )


async def _get_agent_inventory(svc, args: dict):
    if not svc.api_url:
        return result({"error": "Wazuh server API (api_url) not configured"})
    kind = args["kind"]
    if kind not in INVENTORY_KINDS:
        return result({"error": f"Unknown inventory kind: {kind}"})
    data = await svc.get_agent_inventory(
        args["agent_id"],
        kind,
        limit=min(int(args.get("max_results") or 100), _MAX_RESULTS),
    )
    if data is None:
        return result({"error": f"Failed to fetch {kind} inventory"})
    return result(
        {
            "agent_id": args["agent_id"],
            "kind": kind,
            "total": data.get("total_affected_items", 0),
            "items": data.get("affected_items", []),
        }
    )


# ------------------------------------------------------------------
# Main
# ------------------------------------------------------------------


async def _on_list_tools(_ctx, _params):
    return types.ListToolsResult(tools=await handle_list_tools())


async def _on_call_tool(_ctx, params):
    try:
        content = await handle_call_tool(params.name, params.arguments)
    except Exception as exc:
        return types.CallToolResult(
            content=[types.TextContent(type="text", text=str(exc))],
            is_error=True,
        )
    return types.CallToolResult(content=content)


server = Server(
    "wazuh",
    on_list_tools=_on_list_tools,
    on_call_tool=_on_call_tool,
)


async def main():
    async with mcp.server.stdio.stdio_server() as (read, write):
        await server.run(
            read,
            write,
            InitializationOptions(
                server_name="wazuh",
                server_version="0.1.0",
                capabilities=server.get_capabilities(
                    notification_options=NotificationOptions(),
                    experimental_capabilities={},
                ),
            ),
        )


if __name__ == "__main__":
    asyncio.run(main())
