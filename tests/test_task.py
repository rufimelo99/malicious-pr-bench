"""Unit tests for dataset loading in benchmark/task.py."""

from __future__ import annotations

import dataclasses
import json
from pathlib import Path

import pytest

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


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


def _write_jsonl(tmp_path: Path, records: list[PRRecord]) -> Path:
    p = tmp_path / "prs.jsonl"
    p.write_text("\n".join(json.dumps(r.to_dict()) for r in records))
    return p


# ---------------------------------------------------------------------------
# _load_samples — individual mode
# ---------------------------------------------------------------------------


class TestLoadSamplesIndividual:
    def _load(self, jsonl_path, **kwargs):
        from benchmark.task import _load_samples

        return _load_samples(
            jsonl_path=str(jsonl_path),
            hf_dataset=None,
            repo="gitadmin/test-repo",
            review_mode="individual",
            **kwargs,
        )

    def test_basic_load(self, tmp_path):
        records = [PRRecord(pr_number=1), PRRecord(pr_number=2)]
        path = _write_jsonl(tmp_path, records)
        samples = self._load(path)
        assert len(samples) == 2

    def test_metadata_fields_present(self, tmp_path):
        path = _write_jsonl(tmp_path, [PRRecord(pr_number=7)])
        samples = self._load(path)
        meta = samples[0].metadata
        assert meta["pr_number"] == 7
        assert meta["axis1"] == "single_pr_introduction"
        assert meta["axis2"] == "buried_in_complexity"
        assert meta["axis3"] == "misleading_hardening"
        assert meta["repo"] == "gitadmin/test-repo"

    def test_drops_records_without_axis1(self, tmp_path):
        bad = PRRecord()
        bad.scenario.axis1 = ""
        path = _write_jsonl(tmp_path, [bad, PRRecord(pr_number=2)])
        samples = self._load(path)
        assert len(samples) == 1
        assert samples[0].metadata["pr_number"] == 2

    def test_axis1_filter(self, tmp_path):
        records = [
            PRRecord(
                pr_number=1, scenario=ScenarioRecord(axis1="single_pr_introduction")
            ),
            PRRecord(
                pr_number=2, scenario=ScenarioRecord(axis1="precondition_staging")
            ),
        ]
        path = _write_jsonl(tmp_path, records)
        samples = self._load(path, axis1="precondition_staging")
        assert len(samples) == 1
        assert samples[0].metadata["pr_number"] == 2

    def test_axis2_filter(self, tmp_path):
        records = [
            PRRecord(
                pr_number=1, scenario=ScenarioRecord(axis2="buried_in_complexity")
            ),
            PRRecord(pr_number=2, scenario=ScenarioRecord(axis2="clarity")),
        ]
        path = _write_jsonl(tmp_path, records)
        samples = self._load(path, axis2="clarity")
        assert len(samples) == 1

    def test_axis3_filter(self, tmp_path):
        records = [
            PRRecord(
                pr_number=1, scenario=ScenarioRecord(axis3="misleading_hardening")
            ),
            PRRecord(pr_number=2, scenario=ScenarioRecord(axis3="security_fix_irony")),
        ]
        path = _write_jsonl(tmp_path, records)
        samples = self._load(path, axis3="security_fix_irony")
        assert len(samples) == 1

    def test_combined_axis_filter(self, tmp_path):
        records = [
            PRRecord(
                pr_number=1,
                scenario=ScenarioRecord(
                    axis1="single_pr_introduction", axis2="buried_in_complexity"
                ),
            ),
            PRRecord(
                pr_number=2,
                scenario=ScenarioRecord(
                    axis1="single_pr_introduction", axis2="clarity"
                ),
            ),
            PRRecord(
                pr_number=3,
                scenario=ScenarioRecord(
                    axis1="precondition_staging", axis2="buried_in_complexity"
                ),
            ),
        ]
        path = _write_jsonl(tmp_path, records)
        samples = self._load(
            path, axis1="single_pr_introduction", axis2="buried_in_complexity"
        )
        assert len(samples) == 1
        assert samples[0].metadata["pr_number"] == 1

    def test_empty_jsonl_returns_no_samples(self, tmp_path):
        path = tmp_path / "empty.jsonl"
        path.write_text("")
        samples = self._load(path)
        assert samples == []

    def test_incomplete_group_excluded(self, tmp_path):
        records = [
            PRRecord(pr_number=1, group_id="grp1", sequence_index=0, sequence_total=2)
        ]
        path = _write_jsonl(tmp_path, records)
        samples = self._load(path)
        assert len(samples) == 0

    def test_complete_group_only_includes_final_pr(self, tmp_path):
        records = [
            PRRecord(pr_number=1, group_id="grp1", sequence_index=0, sequence_total=2),
            PRRecord(pr_number=2, group_id="grp1", sequence_index=1, sequence_total=2),
        ]
        path = _write_jsonl(tmp_path, records)
        samples = self._load(path)
        assert len(samples) == 1
        assert samples[0].metadata["pr_number"] == 2
