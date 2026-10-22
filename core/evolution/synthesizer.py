"""Synthesize a hunt Playbook from a textual description of an APT.

The first half of the evolution story: a description of an adversary becomes a
file-based ``WORKFLOW.md`` hunt with declared hypotheses, ``attack_techniques``
and ``data_domains``, which then runs, accumulates a trace population, and is
evolved by the controller once its runs expose a gap.

The model writes the hunt; the estate grounds it. The prompt carries the
telemetry domains and the entities actually present in the Findings table, and
the draft is checked against them before anything is written:

- every ``data_domains`` entry must be a domain the estate or the shipped
  threat-hunt vocabulary knows, since the scorer and the probe compare it to a
  finding's ``data_source``;
- every hypothesis should name an estate entity verbatim, since the miner keys
  a hypothesis's subjects off the entity tokens in its statement
  (``trace_miner._subjects_from_statement``) — one that names none can run but
  can never be scored, so it is reported as a warning;
- phases are limited to known agents and to the tools this deployment serves.

The model is told to declare only the domains that carry each hypothesis's
primary signal. ``HELD_BACK_DOMAINS`` are then withheld outright -- a deliberate
gap, the synthesized counterpart of finance-hunt's: the seeded estate's staging
evidence lives in exactly those domains, so a hypothesis that needs it stays
inconclusive until the evolution loop discovers and adds them.
"""

from __future__ import annotations

import json
import logging
import re
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml

from core.evolution.trace_miner import _subjects_from_statement

logger = logging.getLogger(__name__)

DEFINITIONS_DIR = Path(__file__).resolve().parents[1] / "workflows" / "definitions"

# The shipped threat-hunt playbook's vocabulary; admitted alongside whatever
# data_source values the estate holds so an empty estate can still synthesize.
BASE_DOMAINS = (
    "net_flow", "dns", "http", "proxy", "endpoint", "process_lineage",
    "win_events", "auth", "email", "cloud",
)

# Never declared by a synthesized hunt, so the evolution demo has a gap to close:
# the probe finds present-but-uncited evidence here and the augment adds it back.
HELD_BACK_DOMAINS = ("endpoint", "process_lineage")

# search_findings reads Vigil's own Findings table; lookup_indicators the indicator
# store. telemetry_search is left out on purpose: it needs a self-hosted SIEM, the
# same reason finance-hunt does not grant it.
HUNT_TOOLS = ("search_findings", "lookup_indicators")

# Kept short for a live demo: each iteration is a lead turn plus a dispatched
# worker (~2-4 min on Sonnet), and the demo's gap hypothesis is meant to end
# inconclusive anyway. scripts/run_finance_hunt.py runs 8.
RUN_ITERATIONS = 3
RUN_MAX_COST_USD = 0.75

_ESTATE_SAMPLE = 5000
_ENTITY_LIMIT = 40
_HOST_KEYS = ("hostnames", "hostname", "host", "computer_name")
_USER_KEYS = ("users", "usernames", "user", "username")


class SynthesisError(Exception):
    """The draft could not be produced or is unusable."""


# --------------------------------------------------------------------------- #
# Estate
# --------------------------------------------------------------------------- #


@dataclass
class Estate:
    """What the Findings table holds: telemetry domains and named entities."""

    domains: Counter = field(default_factory=Counter)
    # casefolded entity value -> "host" | "user"
    kinds: Dict[str, str] = field(default_factory=dict)
    # casefolded entity value -> domains it appears in
    entity_domains: Dict[str, set] = field(default_factory=lambda: defaultdict(set))
    entity_counts: Counter = field(default_factory=Counter)
    # casefolded entity value -> the most recent finding that names it
    anchor: Dict[str, str] = field(default_factory=dict)

    def vocabulary(self) -> List[str]:
        domains = set(BASE_DOMAINS) | {str(d) for d in self.domains}
        return sorted(domains - set(HELD_BACK_DOMAINS))

    def top_entities(self, limit: int = _ENTITY_LIMIT) -> List[str]:
        return [e for e, _ in self.entity_counts.most_common(limit)]


def _values(ctx: Dict[str, Any], keys) -> List[str]:
    out: List[str] = []
    for key in keys:
        item = ctx.get(key)
        for v in item if isinstance(item, list) else [item]:
            if v:
                out.append(str(v).strip().casefold())
    return out


def read_estate(data_service: Any = None) -> Estate:
    """Fold the Findings table into the domains and entities a hunt can name."""
    if data_service is None:
        from core.storage.database_data_service import DatabaseDataService

        data_service = DatabaseDataService()
    findings = data_service.get_findings(limit=_ESTATE_SAMPLE) or []
    # newest first, so the first finding to name an entity is its anchor
    findings = sorted(findings, key=lambda f: str(f.get("timestamp") or ""), reverse=True)

    estate = Estate()
    for f in findings:
        ds = f.get("data_source")
        if ds:
            estate.domains[str(ds)] += 1
        ctx = f.get("entity_context")
        if not isinstance(ctx, dict):
            continue
        for kind, keys in (("host", _HOST_KEYS), ("user", _USER_KEYS)):
            for value in _values(ctx, keys):
                estate.kinds.setdefault(value, kind)
                estate.entity_counts[value] += 1
                if ds:
                    estate.entity_domains[value].add(str(ds))
                if f.get("finding_id"):
                    estate.anchor.setdefault(value, str(f["finding_id"]))
    return estate


# --------------------------------------------------------------------------- #
# Prompt
# --------------------------------------------------------------------------- #

_SYSTEM = (
    "You are a threat-hunt designer for a SOC platform. Given a description of an "
    "APT, you write a hypothesis-driven hunt over the organisation's own estate. "
    "Return STRICT JSON only: no prose, no markdown, no code fences."
)


def _agents() -> Dict[str, str]:
    try:
        from core.agents.manager import SOCAgentLibrary

        return {k: p.specialization for k, p in SOCAgentLibrary.get_all_agents().items()}
    except Exception as exc:  # noqa: BLE001
        logger.warning("could not load agent library: %r", exc)
        return {
            "threat_hunter": "hypothesis-driven hunting",
            "network_analyst": "network traffic analysis",
            "threat_intel": "indicator enrichment and attribution",
        }


def build_prompt(description: str, estate: Estate, agents: Dict[str, str]) -> str:
    offered = [(d, n) for d, n in estate.domains.most_common() if d not in HELD_BACK_DOMAINS]
    if offered:
        domains = "\n".join(f"- `{d}` ({n} findings)" for d, n in offered)
    else:
        domains = "(the estate holds no findings yet)"
    vocab = ", ".join(estate.vocabulary())
    entities = "\n".join(
        f"- `{e}` ({estate.kinds[e]}; seen in {', '.join(sorted(estate.entity_domains[e] - set(HELD_BACK_DOMAINS))) or 'no domain'})"
        for e in estate.top_entities()
    ) or "(none)"
    agent_lines = "\n".join(f"- `{k}`: {v}" for k, v in agents.items())

    schema = {
        "name": "kebab-case id, e.g. apt29-cloud-hunt",
        "title": "Human title for the hunt",
        "description": "One sentence: what this hunt looks for",
        "use_case": "When to run it",
        "trigger_examples": ["How an analyst would ask for this hunt"],
        "hypotheses": [
            "2-3 falsifiable statements, each naming one estate entity verbatim",
        ],
        "attack_techniques": ["T1071.004"],
        "data_domains": ["dns"],
        "objectives": ["What the hunt must establish"],
        "phases": [
            {
                "id": "threat_hunter",
                "agent": "threat_hunter",
                "name": "Behavioural hunting",
                "tools": list(HUNT_TOOLS),
                "instructions": "What this agent does for each hypothesis",
            }
        ],
        "narrative": "2-3 short markdown paragraphs on the adversary and the hunt's logic",
    }

    return (
        f"## APT description\n{description.strip()}\n\n"
        f"## Telemetry domains in the estate\n{domains}\n\n"
        f"Allowed data_domains vocabulary: {vocab}\n\n"
        f"## Entities in the estate\n{entities}\n\n"
        f"## Agents\n{agent_lines}\n\n"
        f"## Tools\n{', '.join(HUNT_TOOLS)}\n\n"
        "## Requirements\n"
        "- Translate the APT's tradecraft into 2-3 hypotheses about THIS estate (fewer "
        "hypotheses keep each run short). Each "
        "hypothesis must name exactly one entity from the entity list, spelled exactly "
        "as listed, so its runs can be keyed and scored.\n"
        "- attack_techniques: the MITRE ATT&CK IDs the hypotheses test.\n"
        "- data_domains: only the domains that carry each hypothesis's primary signal, "
        "from the allowed vocabulary. Do not add domains speculatively.\n"
        "- phases: 2-4 phases using only the listed agents and tools; `id` unique.\n\n"
        "## Output schema\nReturn ONE JSON object matching:\n"
        f"{json.dumps(schema, indent=2)}"
    )


# --------------------------------------------------------------------------- #
# Draft -> Playbook
# --------------------------------------------------------------------------- #


def extract_json(text: str) -> Optional[Dict[str, Any]]:
    fence = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", text, re.DOTALL)
    candidate = fence.group(1) if fence else None
    if candidate is None:
        match = re.search(r"\{.*\}", text, re.DOTALL)
        candidate = match.group(0) if match else text
    try:
        parsed = json.loads(candidate)
    except json.JSONDecodeError:
        return None
    return parsed if isinstance(parsed, dict) else None


def slugify(name: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", str(name).casefold()).strip("-")
    return slug[:48].strip("-") or "apt-hunt"


def _strings(value: Any) -> List[str]:
    if not isinstance(value, list):
        return []
    return [str(v).strip() for v in value if str(v).strip()]


@dataclass
class Playbook:
    workflow_id: str
    metadata: Dict[str, Any]
    body: str
    warnings: List[str] = field(default_factory=list)


def normalize(
    draft: Dict[str, Any], estate: Estate, agents: Dict[str, str], *, workflow_id: str
) -> Playbook:
    """Check a model draft against the estate and shape it into a hunt Playbook."""
    warnings: List[str] = []

    hypotheses = _strings(draft.get("hypotheses"))
    if not hypotheses:
        raise SynthesisError("the draft declared no hypotheses")
    for h in hypotheses:
        named = [s for s in _subjects_from_statement(h) if s in estate.kinds]
        if not named:
            warnings.append(
                f"names no estate entity, so its runs cannot be scored: {h!r}"
            )

    vocab = set(estate.vocabulary())
    declared = _strings(draft.get("data_domains"))
    domains = [d for d in dict.fromkeys(declared) if d in vocab]
    held = [d for d in declared if d in HELD_BACK_DOMAINS]
    if held:
        warnings.append(f"held back for evolution to discover: {', '.join(held)}")
    dropped = [d for d in declared if d not in vocab and d not in HELD_BACK_DOMAINS]
    if dropped:
        warnings.append(f"dropped data_domains outside the vocabulary: {', '.join(dropped)}")
    if not domains:
        raise SynthesisError("the draft declared no usable data_domains")

    phases: List[Dict[str, Any]] = []
    seen: set[str] = set()
    for raw in draft.get("phases") or []:
        if not isinstance(raw, dict):
            continue
        agent = str(raw.get("agent") or raw.get("agent_id") or "").strip()
        if agent not in agents:
            warnings.append(f"dropped a phase for unknown agent {agent!r}")
            continue
        pid = slugify(raw.get("id") or agent).replace("-", "_")
        while pid in seen:
            pid += "_2"
        seen.add(pid)
        tools = [t for t in _strings(raw.get("tools")) if t in HUNT_TOOLS] or ["search_findings"]
        phases.append({
            "id": pid,
            "agent": agent,
            "name": str(raw.get("name") or agent.replace("_", " ").title()),
            "tools": tools,
            "instructions": str(raw.get("instructions") or "").strip() + "\n",
        })
    if not phases:
        raise SynthesisError("the draft has no phase with a known agent")

    title = str(draft.get("title") or draft.get("name") or workflow_id).strip()
    metadata: Dict[str, Any] = {
        "name": workflow_id,
        "description": str(draft.get("description") or title).strip(),
        "use_case": str(draft.get("use_case") or "").strip(),
        "trigger_examples": _strings(draft.get("trigger_examples")) or [f"Run the {title} hunt"],
        "run_kind": "hunt",
        "hypotheses": hypotheses,
        "attack_techniques": _strings(draft.get("attack_techniques")),
        "data_domains": domains,
        "objectives": _strings(draft.get("objectives")) or [
            "Report each hypothesis as proven, disproven or inconclusive, with reasons",
        ],
        "phases": phases,
    }
    narrative = str(draft.get("narrative") or "").strip()
    body = f"# {title}\n\nSynthesized from an APT description.\n\n{narrative}\n"
    return Playbook(workflow_id=workflow_id, metadata=metadata, body=body, warnings=warnings)


class _BlockDumper(yaml.SafeDumper):
    pass


def _str_presenter(dumper: yaml.SafeDumper, data: str):
    style = "|" if "\n" in data else None
    return dumper.represent_scalar("tag:yaml.org,2002:str", data, style=style)


_BlockDumper.add_representer(str, _str_presenter)


def render(playbook: Playbook) -> str:
    front = yaml.dump(
        playbook.metadata, Dumper=_BlockDumper, sort_keys=False,
        default_flow_style=False, allow_unicode=True, width=100,
    ).rstrip()
    return f"---\n{front}\n---\n\n{playbook.body}"


def unique_id(base: str, taken: set[str], definitions_dir: Path) -> str:
    candidate, n = base, 2
    while candidate in taken or (definitions_dir / candidate).exists():
        candidate = f"{base}-{n}"
        n += 1
    return candidate


async def synthesize(
    description: str,
    *,
    taken_ids: set[str],
    claude: Any = None,
    data_service: Any = None,
    definitions_dir: Path = DEFINITIONS_DIR,
) -> Dict[str, Any]:
    """Write a new hunt Playbook for ``description`` and return what was written."""
    if not description or not description.strip():
        raise SynthesisError("an APT description is required")

    if claude is None:
        from core.llm.harness.claude import ClaudeService

        claude = ClaudeService()
    if not claude.has_api_key():
        raise SynthesisError("no LLM provider is configured")

    estate = read_estate(data_service)
    agents = _agents()
    raw = claude.chat(
        message=build_prompt(description, estate, agents),
        system_prompt=_SYSTEM,
        max_tokens=4096,
    )
    draft = extract_json(raw or "")
    if not draft:
        raise SynthesisError("could not parse a playbook from the model response")

    workflow_id = unique_id(slugify(draft.get("name") or draft.get("title") or ""), taken_ids, definitions_dir)
    playbook = normalize(draft, estate, agents, workflow_id=workflow_id)
    content = render(playbook)

    path = definitions_dir / workflow_id / "WORKFLOW.md"
    path.parent.mkdir(parents=True, exist_ok=False)
    path.write_text(content, encoding="utf-8")
    logger.info("synthesized hunt playbook %s at %s", workflow_id, path)

    return {
        "workflow_id": workflow_id,
        "path": str(path),
        "playbook": playbook.metadata,
        "content": content,
        "warnings": playbook.warnings,
    }


# --------------------------------------------------------------------------- #
# Running a synthesized hunt
# --------------------------------------------------------------------------- #


def run_parameters(metadata: Dict[str, Any], estate: Estate) -> Dict[str, Any]:
    """The execute parameters for one headless run of a hunt Playbook.

    Mirrors scripts/run_finance_hunt.py: a finding anchors the run, each
    hypothesis declares its subjects (typed from the estate, since a statement
    alone does not say whether a token is a host or a user), and
    approve_hypotheses is left unset so the run advances without a human.
    """
    subjects: Dict[str, List[str]] = {}
    anchor: Optional[str] = None
    for h in _strings(metadata.get("hypotheses")):
        typed = [f"{estate.kinds[s]}:{s}" for s in _subjects_from_statement(h) if s in estate.kinds]
        if typed:
            subjects[h] = typed
            if anchor is None:
                anchor = estate.anchor.get(typed[0].split(":", 1)[1])

    params: Dict[str, Any] = {
        "iterations": RUN_ITERATIONS,
        "max_cost_usd": RUN_MAX_COST_USD,
    }
    if subjects:
        params["hypothesis_subjects"] = subjects
    if anchor:
        params["finding_id"] = anchor
    else:
        params["context"] = str(metadata.get("description") or metadata.get("name"))
    return params
