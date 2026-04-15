"""Schema contract tests: verify that real HF dataset records match PRRecord.

These tests download a small number of real records from HuggingFace and assert
that the fields the benchmark code reads are present and have the expected types.
They are skipped when the network is unavailable or HF credentials are missing.

Two dataset variants exist:
  - gpt5.2/          Raw records: axes nested under a 'scenario' key.
  - gpt5.2-filtered/ Processed records: axes flat at top level.

The benchmark code (task.py) reads axes from the TOP level, so it consumes the
gpt5.2-filtered variant. PRRecord mirrors that flat schema.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from conftest import HF_BENIGN_SAMPLE_FILES, HF_MALICIOUS_SAMPLE_FILES, HF_REPO


def _download(filename: str) -> list[dict]:
    from huggingface_hub import hf_hub_download

    path = hf_hub_download(repo_id=HF_REPO, filename=filename, repo_type="dataset")
    return [
        json.loads(line) for line in Path(path).read_text().splitlines() if line.strip()
    ]


def _first_record(filename: str):
    try:
        records = _download(filename)
    except Exception as exc:
        pytest.skip(f"Could not fetch dataset: {exc}")
    assert records, f"Dataset file is empty: {filename}"
    return records[0]


# ---------------------------------------------------------------------------
# Malicious dataset — parametrized over all supported versions
# ---------------------------------------------------------------------------


@pytest.mark.network
@pytest.mark.parametrize("version,filepath", HF_MALICIOUS_SAMPLE_FILES)
class TestMaliciousDatasetSchema:
    @pytest.fixture()
    def record(self, filepath):
        return _first_record(filepath)

    def test_has_pr_number(self, record, version, filepath):
        assert "pr_number" in record
        assert isinstance(record["pr_number"], int)

    def test_has_repo(self, record, version, filepath):
        assert "repo" in record
        assert isinstance(record["repo"], str)
        assert "/" in record["repo"]

    def test_has_branch(self, record, version, filepath):
        assert "branch" in record
        assert isinstance(record["branch"], str)

    def test_has_files_changed(self, record, version, filepath):
        assert "files_changed" in record
        assert isinstance(record["files_changed"], list)

    def test_axis1_is_flat(self, record, version, filepath):
        """axis1 must be at the top level — not nested under 'scenario'.
        Only the filtered variant has flat axes; raw variants nest them.
        """
        if "filtered" not in version:
            pytest.skip(
                f"Version '{version}' uses nested axes — only filtered is consumed by task.py"
            )
        assert "axis1" in record, (
            f"axis1 missing at top level in version '{version}'. "
            "The benchmark reads record.get('axis1') directly."
        )
        assert isinstance(record["axis1"], str)

    def test_axis2_is_flat(self, record, version, filepath):
        if "filtered" not in version:
            pytest.skip(f"Version '{version}' uses nested axes")
        assert "axis2" in record
        assert isinstance(record["axis2"], str)

    def test_axis3_is_flat(self, record, version, filepath):
        if "filtered" not in version:
            pytest.skip(f"Version '{version}' uses nested axes")
        assert "axis3" in record
        assert isinstance(record["axis3"], str)

    def test_category_is_flat(self, record, version, filepath):
        if "filtered" not in version:
            pytest.skip(f"Version '{version}' uses nested axes")
        assert "category" in record
        assert isinstance(record["category"], str)

    def test_raw_version_has_scenario_key(self, record, version, filepath):
        """Raw (non-filtered) versions should have axes nested under 'scenario'."""
        if "filtered" in version:
            pytest.skip(f"Version '{version}' is the filtered flat variant")
        assert (
            "scenario" in record
        ), f"Expected 'scenario' key in raw version '{version}'"
        assert "axis1" in record["scenario"]

    def test_pr_record_covers_filtered_version(self, record, version, filepath):
        """Every required PRRecord field must exist in the filtered dataset record."""
        if "filtered" not in version:
            pytest.skip("PRRecord maps to the filtered variant only")
        import dataclasses

        from conftest import PRRecord

        optional = {
            "group_id",
            "sequence_index",
            "sequence_total",
            "pr_title",
            "pr_body",
        }
        for field in dataclasses.fields(PRRecord):
            if field.name in optional:
                continue
            assert field.name in record, (
                f"PRRecord.{field.name} has no counterpart in version '{version}'. "
                "Update PRRecord or fix the field name."
            )


# ---------------------------------------------------------------------------
# Benign dataset — parametrized over all supported benign versions
# ---------------------------------------------------------------------------


@pytest.mark.network
@pytest.mark.parametrize("version,filepath", HF_BENIGN_SAMPLE_FILES)
class TestBenignDatasetSchema:
    @pytest.fixture()
    def record(self, filepath):
        return _first_record(filepath)

    def test_has_pr_number(self, record, version, filepath):
        assert "pr_number" in record
        assert isinstance(record["pr_number"], int)

    def test_has_repo(self, record, version, filepath):
        assert "repo" in record
        assert isinstance(record["repo"], str)

    def test_has_branch(self, record, version, filepath):
        assert "branch" in record
        assert isinstance(record["branch"], str)

    def test_has_files_changed(self, record, version, filepath):
        assert "files_changed" in record
        assert isinstance(record["files_changed"], list)

    def test_has_vuln_id(self, record, version, filepath):
        assert "vuln_id" in record
        assert isinstance(record["vuln_id"], str)

    def test_has_pr_title(self, record, version, filepath):
        assert "pr_title" in record
        assert isinstance(record["pr_title"], str)
