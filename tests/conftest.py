"""Shared test fixtures and helpers.

PRRecord mirrors the flat JSON schema used in the HuggingFace dataset and
local JSONL files consumed by benchmark/task.py and benchmark/benign_task.py.

Fields sourced from record.get(...) calls in the benchmark code:
    pr_number       – required int
    repo            – "owner/name"
    branch          – feature branch name
    files_changed   – list of file paths
    group_id        – multi-PR group identifier (None for standalone PRs)
    sequence_index  – 0-based position within the group
    sequence_total  – total PRs in the group
    category        – e.g. "cve"
    axis1           – attack strategy axis
    axis2           – concealment axis
    axis3           – framing axis
    pr_title        – PR title string
    pr_body         – PR description string

NOTE: ScenarioRecord no longer exists. The old test helper nested axis fields
under a separate dataclass and flattened them in to_dict(). That nesting was
test-only fiction — the real dataset records are flat. PRRecord now matches
the actual flat structure directly.
"""

from __future__ import annotations

import dataclasses
import json
from pathlib import Path

from benchmark.config import (
    HF_DATASET_DEFAULT,
    SUPPORTED_BENIGN_DATASET_VERSIONS,
    SUPPORTED_CWES,
    SUPPORTED_DATASET_VERSIONS,
)

# ---------------------------------------------------------------------------
# HuggingFace dataset path helpers
# ---------------------------------------------------------------------------

HF_REPO = HF_DATASET_DEFAULT

# Smallest CWE used as a stable sample for network/schema tests.
_SCHEMA_SAMPLE_CWE = "cwe79"

# One (cwe, version) file path per supported version — used in parametrized
# schema contract tests so every version is validated against PRRecord.
HF_MALICIOUS_SAMPLE_FILES = [
    (version, f"{_SCHEMA_SAMPLE_CWE}/{version}/generated_prs.jsonl")
    for version in sorted(SUPPORTED_DATASET_VERSIONS)
]
HF_BENIGN_SAMPLE_FILES = [
    (version, f"{_SCHEMA_SAMPLE_CWE}/benign/{version}/generated_prs.jsonl")
    for version in sorted(SUPPORTED_BENIGN_DATASET_VERSIONS)
]


@dataclasses.dataclass
class PRRecord:
    pr_number: int = 1
    repo: str = "gitadmin/test-repo"
    branch: str = ""
    files_changed: list = dataclasses.field(default_factory=lambda: ["src/Foo.java"])
    group_id: str | None = None
    sequence_index: int | None = None
    sequence_total: int | None = None
    category: str = "cve"
    axis1: str = "single_pr_introduction"
    axis2: str = "buried_in_complexity"
    axis3: str = "misleading_hardening"
    pr_title: str = ""
    pr_body: str = ""

    def __post_init__(self):
        if not self.branch:
            self.branch = f"feature/pr-{self.pr_number}"
        if not self.pr_title:
            self.pr_title = f"PR {self.pr_number} title"
        if not self.pr_body:
            self.pr_body = f"PR {self.pr_number} body"

    def to_dict(self) -> dict:
        return dataclasses.asdict(self)


def write_jsonl(
    tmp_path: Path, records: list[PRRecord], filename: str = "prs.jsonl"
) -> Path:
    p = tmp_path / filename
    p.write_text("\n".join(json.dumps(r.to_dict()) for r in records))
    return p
