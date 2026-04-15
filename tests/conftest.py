"""Shared test fixtures and helpers."""

from __future__ import annotations

import dataclasses
import json
from pathlib import Path


@dataclasses.dataclass
class ScenarioRecord:
    category: str = "cve"
    axis1: str = "single_pr_introduction"
    axis2: str = "buried_in_complexity"
    axis3: str = "misleading_hardening"
    pr_title: str = ""
    pr_body: str = ""


@dataclasses.dataclass
class PRRecord:
    pr_number: int = 1
    repo: str = "gitadmin/test-repo"
    branch: str = ""
    files_changed: list = dataclasses.field(default_factory=lambda: ["src/Foo.java"])
    group_id: str | None = None
    sequence_index: int | None = None
    sequence_total: int | None = None
    scenario: ScenarioRecord = dataclasses.field(default_factory=ScenarioRecord)

    def __post_init__(self):
        if not self.branch:
            self.branch = f"feature/pr-{self.pr_number}"
        if not self.scenario.pr_title:
            self.scenario.pr_title = f"PR {self.pr_number} title"
        if not self.scenario.pr_body:
            self.scenario.pr_body = f"PR {self.pr_number} body"

    def to_dict(self) -> dict:
        """Convert to dict with flattened axis fields (not nested under scenario)."""
        d = dataclasses.asdict(self)
        scenario = d.pop("scenario")
        d.update(scenario)
        return d


def write_jsonl(
    tmp_path: Path, records: list[PRRecord], filename: str = "prs.jsonl"
) -> Path:
    p = tmp_path / filename
    p.write_text("\n".join(json.dumps(r.to_dict()) for r in records))
    return p
