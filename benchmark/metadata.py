"""Typed metadata containers for benchmark samples."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass
class PRDetails:
    title: str = ""
    body: str = ""


@dataclass
class MaliciousSampleMetadata:
    repo: str
    pr_number: int
    category: str
    axis1: str
    axis2: str
    axis3: str
    branch: str = ""
    files_changed: list[str] = field(default_factory=list)
    group_id: str | None = None
    sequence_index: int | None = None
    sequence_total: int | None = None
    group_pr_numbers: list[int] | None = None
    pr_details: dict[int, PRDetails] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        # Serialise PRDetails values to plain dicts (asdict already does this,
        # but we keep keys as ints so downstream code can look up by pr_number).
        d["pr_details"] = {
            pr_num: {"title": det["title"], "body": det["body"]}
            for pr_num, det in d["pr_details"].items()
        }
        return d


@dataclass
class SequenceSampleMetadata:
    repo: str
    pr_numbers: list[int]
    pr_details: dict[int, PRDetails]
    group_id: str
    category: str
    axis1: str
    axis2: str
    axis3: str

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["pr_details"] = {
            pr_num: {"title": det["title"], "body": det["body"]}
            for pr_num, det in d["pr_details"].items()
        }
        return d


@dataclass
class BenignSampleMetadata:
    repo: str
    pr_number: int
    vuln_id: str = ""
    cwe_id: str = ""
    cwe_slug: str = ""
    branch: str = ""
    files_changed: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
