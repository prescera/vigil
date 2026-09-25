"""Activation: apply a validated augment to a workflow's Playbook.

The activation target (decided for the demo) is the file-based ``WORKFLOW.md``:
the resolver builds a fresh ``WorkflowsService`` per run and loads definitions
from disk, so rewriting the front matter takes effect on the next run with no
deploy. Revert restores the captured prior content.

Scope note: this rewrites the YAML front matter via a safe_load / safe_dump
round-trip, which reflows it and drops comments. That is fine for a generated or
forked playbook (the demo's ``finance-hunt``); a hand-authored shipped playbook
with load-bearing comments would want a surgical edit (ruamel round-trip) — left
as a follow-up rather than pretended-away here.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Sequence

import yaml

_FRONTMATTER = re.compile(r"^---\s*\n(.*?)\n---\s*(?:\n|$)", re.DOTALL)


@dataclass
class PlaybookEditResult:
    """What an activation did, enough to render a diff and to revert."""

    path: str
    added_domains: List[str] = field(default_factory=list)
    added_phases: List[str] = field(default_factory=list)
    before_content: str = ""
    after_content: str = ""
    data_domains_before: List[str] = field(default_factory=list)
    data_domains_after: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "path": self.path,
            "added_domains": self.added_domains,
            "added_phases": self.added_phases,
            "data_domains_before": self.data_domains_before,
            "data_domains_after": self.data_domains_after,
        }


def _split(content: str) -> "tuple[Dict[str, Any], str]":
    match = _FRONTMATTER.match(content)
    if not match:
        raise ValueError("no YAML front matter found in playbook")
    metadata = yaml.safe_load(match.group(1)) or {}
    if not isinstance(metadata, dict):
        raise ValueError("front matter is not a mapping")
    body = content[match.end():]
    return metadata, body


def _reassemble(metadata: Dict[str, Any], body: str) -> str:
    dumped = yaml.safe_dump(metadata, sort_keys=False, default_flow_style=False).rstrip()
    body = body.lstrip("\n")
    return f"---\n{dumped}\n---\n\n{body}" if body else f"---\n{dumped}\n---\n"


def plan_edit(
    content: str,
    *,
    add_data_domains: Sequence[str] = (),
    add_phases: Sequence[Dict[str, Any]] = (),
) -> PlaybookEditResult:
    """Pure core: compute the edited content from the current content. No I/O, so
    the augment is tested against an in-memory playbook."""
    metadata, body = _split(content)

    domains = list(metadata.get("data_domains") or [])
    before_domains = list(domains)
    added_domains: List[str] = []
    for domain in add_data_domains:
        if domain not in domains:
            domains.append(domain)
            added_domains.append(domain)
    if "data_domains" in metadata or add_data_domains:
        metadata["data_domains"] = domains

    phases = list(metadata.get("phases") or [])
    existing_ids = {
        str(p.get("phase_id") or p.get("id") or p.get("name"))
        for p in phases
        if isinstance(p, dict)
    }
    added_phases: List[str] = []
    for phase in add_phases:
        pid = str(phase.get("phase_id") or phase.get("id") or phase.get("name"))
        if pid not in existing_ids:
            phases.append(phase)
            existing_ids.add(pid)
            added_phases.append(pid)
    if phases:
        metadata["phases"] = phases

    after = _reassemble(metadata, body)
    return PlaybookEditResult(
        path="",
        added_domains=added_domains,
        added_phases=added_phases,
        before_content=content,
        after_content=after,
        data_domains_before=before_domains,
        data_domains_after=domains,
    )


def apply_playbook_edit(
    path: Path | str,
    *,
    add_data_domains: Sequence[str] = (),
    add_phases: Sequence[Dict[str, Any]] = (),
) -> PlaybookEditResult:
    """Augment the WORKFLOW.md at ``path`` and write it atomically. Returns the
    result (carrying ``before_content`` for revert)."""
    path = Path(path)
    content = path.read_text(encoding="utf-8")
    result = plan_edit(
        content, add_data_domains=add_data_domains, add_phases=add_phases
    )
    result.path = str(path)
    _atomic_write(path, result.after_content)
    return result


def revert_playbook(path: Path | str, before_content: str) -> None:
    """Restore a playbook to the content captured before an activation."""
    _atomic_write(Path(path), before_content)


def _atomic_write(path: Path, content: str) -> None:
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(content, encoding="utf-8")
    os.replace(tmp, path)
