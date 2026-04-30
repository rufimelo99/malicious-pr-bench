"""Unit tests for pure helper functions in benchmark/dataset.py and benchmark/gitea.py."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from conftest import PRRecord
from conftest import write_jsonl as _write_jsonl


class TestFreePort:
    def test_returns_integer_port(self):
        from benchmark.gitea import _free_port

        port = _free_port()
        assert isinstance(port, int)

    def test_port_is_in_valid_range(self):
        from benchmark.gitea import _free_port

        port = _free_port()
        assert 1024 < port <= 65535

    def test_returns_unique_ports(self):
        from benchmark.gitea import _free_port

        ports = {_free_port() for _ in range(5)}
        # At least 2 different ports (extremely unlikely to all collide)
        assert len(ports) >= 1


# ---------------------------------------------------------------------------
# _matches_filter
# ---------------------------------------------------------------------------


class TestMatchesFilter:
    def test_no_filters_matches_anything(self):
        from benchmark.dataset import _matches_filter

        record = {"axis1": "a", "axis2": "b", "axis3": "c"}
        assert _matches_filter(record, None, None, None) is True

    def test_axis1_match(self):
        from benchmark.dataset import _matches_filter

        record = {"axis1": "single_pr_introduction", "axis2": "x", "axis3": "y"}
        assert _matches_filter(record, "single_pr_introduction", None, None) is True

    def test_axis1_no_match(self):
        from benchmark.dataset import _matches_filter

        record = {"axis1": "precondition_staging", "axis2": "x", "axis3": "y"}
        assert _matches_filter(record, "single_pr_introduction", None, None) is False

    def test_axis2_match(self):
        from benchmark.dataset import _matches_filter

        record = {"axis1": "a", "axis2": "buried_in_complexity", "axis3": "c"}
        assert _matches_filter(record, None, "buried_in_complexity", None) is True

    def test_axis3_match(self):
        from benchmark.dataset import _matches_filter

        record = {"axis1": "a", "axis2": "b", "axis3": "misleading_hardening"}
        assert _matches_filter(record, None, None, "misleading_hardening") is True

    def test_all_axes_match(self):
        from benchmark.dataset import _matches_filter

        record = {"axis1": "A", "axis2": "B", "axis3": "C"}
        assert _matches_filter(record, "A", "B", "C") is True

    def test_partial_mismatch_returns_false(self):
        from benchmark.dataset import _matches_filter

        record = {"axis1": "A", "axis2": "B", "axis3": "C"}
        assert _matches_filter(record, "A", "X", "C") is False

    def test_missing_field_treated_as_no_match(self):
        from benchmark.dataset import _matches_filter

        record = {"axis1": "A"}
        assert _matches_filter(record, None, "B", None) is False


# ---------------------------------------------------------------------------
# _load_samples — sequence mode
# ---------------------------------------------------------------------------


class TestLoadSamplesSequence:
    def _load(self, jsonl_path, **kwargs):
        from benchmark.dataset import load_malicious_samples

        return load_malicious_samples(
            jsonl_path=str(jsonl_path),
            hf_dataset=None,
            repo="gitadmin/test-repo",
            review_mode="sequence",
            **kwargs,
        )

    def test_ungrouped_prs_become_individual_samples(self, tmp_path):
        records = [PRRecord(pr_number=1), PRRecord(pr_number=2)]
        path = _write_jsonl(tmp_path, records)
        samples = self._load(path)
        assert len(samples) == 2

    def test_complete_group_becomes_one_sample(self, tmp_path):
        records = [
            PRRecord(pr_number=1, group_id="grp1", sequence_index=0, sequence_total=2),
            PRRecord(pr_number=2, group_id="grp1", sequence_index=1, sequence_total=2),
        ]
        path = _write_jsonl(tmp_path, records)
        samples = self._load(path)
        # one sample for the group
        assert len(samples) == 1
        assert samples[0].metadata["group_id"] == "grp1"

    def test_group_sample_contains_all_pr_numbers(self, tmp_path):
        records = [
            PRRecord(pr_number=10, group_id="g1", sequence_index=0, sequence_total=2),
            PRRecord(pr_number=20, group_id="g1", sequence_index=1, sequence_total=2),
        ]
        path = _write_jsonl(tmp_path, records)
        samples = self._load(path)
        assert samples[0].metadata["pr_numbers"] == [10, 20]

    def test_incomplete_group_excluded(self, tmp_path):
        records = [
            PRRecord(pr_number=1, group_id="g1", sequence_index=0, sequence_total=3),
            PRRecord(pr_number=2, group_id="g1", sequence_index=1, sequence_total=3),
        ]
        path = _write_jsonl(tmp_path, records)
        samples = self._load(path)
        assert len(samples) == 0

    def test_mixed_grouped_and_ungrouped(self, tmp_path):
        records = [
            PRRecord(pr_number=1),  # ungrouped
            PRRecord(pr_number=2, group_id="g1", sequence_index=0, sequence_total=2),
            PRRecord(pr_number=3, group_id="g1", sequence_index=1, sequence_total=2),
        ]
        path = _write_jsonl(tmp_path, records)
        samples = self._load(path)
        # 1 ungrouped + 1 group = 2 samples
        assert len(samples) == 2


# ---------------------------------------------------------------------------
# _load_samples — independent mode
# ---------------------------------------------------------------------------


class TestLoadSamplesIndependent:
    def _load(self, jsonl_path, **kwargs):
        from benchmark.dataset import load_malicious_samples

        return load_malicious_samples(
            jsonl_path=str(jsonl_path),
            hf_dataset=None,
            repo="gitadmin/test-repo",
            review_mode="independent",
            **kwargs,
        )

    def test_complete_group_keeps_every_pr_as_own_sample(self, tmp_path):
        records = [
            PRRecord(pr_number=1, group_id="grp1", sequence_index=0, sequence_total=2),
            PRRecord(pr_number=2, group_id="grp1", sequence_index=1, sequence_total=2),
        ]
        path = _write_jsonl(tmp_path, records)
        samples = self._load(path)
        assert [s.metadata["pr_number"] for s in samples] == [1, 2]
        assert all(s.metadata["group_pr_numbers"] is None for s in samples)

    def test_incomplete_group_excluded(self, tmp_path):
        records = [
            PRRecord(pr_number=1, group_id="grp1", sequence_index=0, sequence_total=2)
        ]
        path = _write_jsonl(tmp_path, records)
        assert self._load(path) == []



# ---------------------------------------------------------------------------
# _load_samples — skip_undefined
# ---------------------------------------------------------------------------


class TestLoadSamplesSkipUndefined:
    def _load(self, jsonl_path, **kwargs):
        from benchmark.dataset import load_malicious_samples

        return load_malicious_samples(
            jsonl_path=str(jsonl_path),
            hf_dataset=None,
            repo="gitadmin/test-repo",
            review_mode="individual",
            **kwargs,
        )

    def test_skips_undefined_axis1_by_default(self, tmp_path):
        from benchmark.dataset import _filter_undefined_axes

        records = [
            PRRecord(pr_number=1, axis1="undefined"),
            PRRecord(pr_number=2),
        ]
        path = _write_jsonl(tmp_path, records)
        samples = self._load(path)
        filtered_samples = [
            s
            for s in samples
            if s.metadata["pr_number"]
            in [r["pr_number"] for r in _filter_undefined_axes([r.to_dict() for r in records])]
        ]
        assert len(filtered_samples) == 1
        assert filtered_samples[0].metadata["pr_number"] == 2

    def test_skips_undefined_axis2_by_default(self, tmp_path):
        from benchmark.dataset import _filter_undefined_axes

        records = [
            PRRecord(pr_number=1, axis2="undefined"),
            PRRecord(pr_number=2),
        ]
        path = _write_jsonl(tmp_path, records)
        samples = self._load(path)
        filtered_samples = [
            s
            for s in samples
            if s.metadata["pr_number"]
            in [r["pr_number"] for r in _filter_undefined_axes([r.to_dict() for r in records])]
        ]
        assert len(filtered_samples) == 1

    def test_includes_undefined_when_skip_false(self, tmp_path):
        records = [
            PRRecord(pr_number=1, axis1="undefined"),
            PRRecord(pr_number=2),
        ]
        path = _write_jsonl(tmp_path, records)
        samples = self._load(path, skip_undefined=False)
        assert len(samples) == 2

    def test_no_hf_or_jsonl_raises(self):
        from benchmark.dataset import load_malicious_samples

        with pytest.raises(ValueError, match="Either hf_dataset or jsonl_path"):
            load_malicious_samples(
                jsonl_path=None,
                hf_dataset=None,
                repo="gitadmin/test-repo",
            )


# ---------------------------------------------------------------------------
# _load_individual_samples — sample content
# ---------------------------------------------------------------------------


class TestLoadIndividualSamplesContent:
    def _load(self, jsonl_path):
        from benchmark.dataset import load_malicious_samples

        return load_malicious_samples(
            jsonl_path=str(jsonl_path),
            hf_dataset=None,
            repo="gitadmin/test-repo",
            review_mode="individual",
        )

    def test_sample_input_contains_pr_number(self, tmp_path):
        path = _write_jsonl(tmp_path, [PRRecord(pr_number=42)])
        samples = self._load(path)
        assert "PR #42" in samples[0].input

    def test_sample_input_contains_repo(self, tmp_path):
        path = _write_jsonl(tmp_path, [PRRecord(pr_number=1, repo="org/my-project")])
        samples = self._load(path)
        assert "org/my-project" in samples[0].input

    def test_sample_id_is_unique(self, tmp_path):
        records = [PRRecord(pr_number=1), PRRecord(pr_number=2)]
        path = _write_jsonl(tmp_path, records)
        samples = self._load(path)
        ids = [s.id for s in samples]
        assert len(ids) == len(set(ids))

    def test_sample_metadata_has_files_changed(self, tmp_path):
        r = PRRecord(pr_number=1)
        r.files_changed = ["src/main.py", "tests/test_main.py"]
        path = _write_jsonl(tmp_path, [r])
        samples = self._load(path)
        assert samples[0].metadata["files_changed"] == [
            "src/main.py",
            "tests/test_main.py",
        ]

    def test_sample_input_includes_pr_title_and_body(self, tmp_path):
        r = PRRecord(
            pr_number=3, pr_title="Add rate limiting", pr_body="Prevents DoS attacks"
        )
        path = _write_jsonl(tmp_path, [r])
        samples = self._load(path)
        assert "Add rate limiting" in samples[0].input
        assert "Prevents DoS attacks" in samples[0].input


# ---------------------------------------------------------------------------
# benign_task._records_from_path
# ---------------------------------------------------------------------------


class TestRecordsFromPath:
    def test_parses_jsonl_file(self, tmp_path):
        from benchmark.dataset import _records_from_path

        lines = [
            json.dumps({"pr_number": 1, "repo": "owner/repo"}),
            json.dumps({"pr_number": 2, "repo": "owner/repo"}),
        ]
        p = tmp_path / "data.jsonl"
        p.write_text("\n".join(lines))
        records = _records_from_path(p)
        assert len(records) == 2
        assert records[0]["pr_number"] == 1

    def test_skips_blank_lines(self, tmp_path):
        from benchmark.dataset import _records_from_path

        p = tmp_path / "data.jsonl"
        p.write_text('{"pr_number": 1}\n\n{"pr_number": 2}\n')
        records = _records_from_path(p)
        assert len(records) == 2


# ---------------------------------------------------------------------------
# benign_task._load_benign_samples — local JSONL
# ---------------------------------------------------------------------------


class TestLoadBenignSamples:
    def _make_benign_jsonl(
        self, tmp_path, records: list[dict], filename="data.jsonl"
    ) -> Path:
        p = tmp_path / filename
        p.write_text("\n".join(json.dumps(r) for r in records))
        return p

    def test_basic_load(self, tmp_path):
        from benchmark.dataset import load_benign_samples as _load_benign_samples

        p = self._make_benign_jsonl(
            tmp_path,
            [{"pr_number": 1, "repo": "owner/repo", "vuln_id": "CVE-2024-0001"}],
        )
        samples = _load_benign_samples(str(p), hf_dataset=None, cwe="cwe89")
        assert len(samples) == 1

    def test_metadata_fields(self, tmp_path):
        from benchmark.dataset import load_benign_samples as _load_benign_samples

        record = {
            "pr_number": 5,
            "repo": "org/project",
            "vuln_id": "CVE-2024-0005",
            "cwe_id": "CWE-89",
            "branch": "fix/sqli",
            "files_changed": ["app.py"],
        }
        p = self._make_benign_jsonl(tmp_path, [record])
        samples = _load_benign_samples(str(p), hf_dataset=None, cwe="cwe89")
        meta = samples[0].metadata
        assert meta["pr_number"] == 5
        assert meta["repo"] == "org/project"
        assert meta["vuln_id"] == "CVE-2024-0005"
        assert meta["branch"] == "fix/sqli"

    def test_deduplicates_by_vuln_id(self, tmp_path):
        from benchmark.dataset import load_benign_samples as _load_benign_samples

        records = [
            {"pr_number": 1, "repo": "owner/repo", "vuln_id": "CVE-2024-0001"},
            {
                "pr_number": 2,
                "repo": "owner/repo",
                "vuln_id": "CVE-2024-0001",
            },  # duplicate
        ]
        p = self._make_benign_jsonl(tmp_path, records)
        samples = _load_benign_samples(str(p), hf_dataset=None, cwe="cwe89")
        assert len(samples) == 1

    def test_uses_repo_pr_as_id_when_no_vuln_id(self, tmp_path):
        from benchmark.dataset import load_benign_samples as _load_benign_samples

        record = {"pr_number": 7, "repo": "owner/repo"}
        p = self._make_benign_jsonl(tmp_path, [record])
        samples = _load_benign_samples(str(p), hf_dataset=None, cwe="cwe89")
        assert "pr7" in samples[0].id

    def test_raises_when_no_source(self, tmp_path):
        from benchmark.dataset import load_benign_samples as _load_benign_samples

        with pytest.raises((ValueError, TypeError)):
            _load_benign_samples(None, hf_dataset=None, cwe="cwe89")

    def test_glob_pattern_loads_multiple_files(self, tmp_path):
        from benchmark.dataset import load_benign_samples as _load_benign_samples

        self._make_benign_jsonl(
            tmp_path,
            [{"pr_number": 1, "repo": "owner/repo", "vuln_id": "CVE-2024-0001"}],
            "generated_prs_benign_cwe89.jsonl",
        )
        self._make_benign_jsonl(
            tmp_path,
            [{"pr_number": 2, "repo": "owner/repo", "vuln_id": "CVE-2024-0002"}],
            "generated_prs_benign_cwe79.jsonl",
        )
        pattern = str(tmp_path / "generated_prs_benign_*.jsonl")
        samples = _load_benign_samples(pattern, hf_dataset=None, cwe=None)
        assert len(samples) == 2

    def test_sample_input_mentions_pr_number(self, tmp_path):
        from benchmark.dataset import load_benign_samples as _load_benign_samples

        record = {"pr_number": 99, "repo": "owner/repo", "vuln_id": "CVE-2024-0099"}
        p = self._make_benign_jsonl(tmp_path, [record])
        samples = _load_benign_samples(str(p), hf_dataset=None, cwe="cwe89")
        assert "PR #99" in samples[0].input

    def test_slug_inferred_from_filename(self, tmp_path):
        from benchmark.dataset import load_benign_samples as _load_benign_samples

        record = {"pr_number": 1, "repo": "owner/repo", "vuln_id": "CVE-2024-0001"}
        p = self._make_benign_jsonl(
            tmp_path, [record], "generated_prs_benign_cwe22.jsonl"
        )
        samples = _load_benign_samples(str(p), hf_dataset=None, cwe=None)
        assert samples[0].metadata["cwe_slug"] == "cwe22"
