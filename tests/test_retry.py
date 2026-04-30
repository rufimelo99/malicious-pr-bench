import json
import tempfile
import zipfile
from pathlib import Path

import pytest


def create_test_eval_file(port: int, cwe: str, version: str, project_name: str, tool_mode: str = "sandbox") -> Path:
    """Helper to create a mock .eval file for testing."""
    temp_dir = tempfile.mkdtemp()
    eval_file = Path(temp_dir) / "test.eval"

    # Create minimal _journal/start.json structure
    journal_data = {
        "task": "reviewer_benchmark",
        "params": {
            "cwe": cwe,
            "version": version,
            "gitea_port": port,
            "gitea_project_name": project_name,
            "tool_mode": tool_mode,
        }
    }

    # Create zip file with the journal
    with zipfile.ZipFile(eval_file, 'w') as zf:
        zf.writestr("_journal/start.json", json.dumps(journal_data))

    return eval_file


def test_extract_metadata_from_eval_file():
    """Test extracting metadata from an eval log file."""
    from retry import extract_metadata

    eval_file = create_test_eval_file(
        port=8080,
        cwe="cwe79",
        version="gpt5.2-filtered",
        project_name="benchmark-test",
        tool_mode="sandbox"
    )

    try:
        metadata = extract_metadata(eval_file)

        assert metadata["port"] == 8080
        assert metadata["cwe"] == "cwe79"
        assert metadata["version"] == "gpt5.2-filtered"
        assert metadata["project_name"] == "benchmark-test"
        assert metadata["tool_mode"] == "sandbox"
    finally:
        eval_file.unlink()


def test_extract_metadata_missing_file():
    """Test error handling for missing files."""
    from retry import extract_metadata

    with pytest.raises(FileNotFoundError):
        extract_metadata(Path("/nonexistent/file.eval"))


def test_extract_metadata_invalid_json():
    """Test error handling for invalid JSON in log file."""
    from retry import extract_metadata

    temp_dir = tempfile.mkdtemp()
    eval_file = Path(temp_dir) / "invalid.eval"

    # Create zip with invalid JSON
    with zipfile.ZipFile(eval_file, 'w') as zf:
        zf.writestr("_journal/start.json", "invalid json {")

    try:
        with pytest.raises(ValueError, match="Invalid JSON"):
            extract_metadata(eval_file)
    finally:
        eval_file.unlink()


def test_build_image_name_malicious():
    """Test building Docker image name for malicious PRs."""
    from retry import build_image_name

    image = build_image_name(cwe="cwe79", version="gpt5.2-filtered", tool_mode="sandbox")
    assert image == "rufimelo/malicious-pr-cwe79:gpt5.2-filtered"


def test_build_image_name_benign():
    """Test building Docker image name for benign PRs."""
    from retry import build_image_name

    image = build_image_name(cwe="benign", version="gpt5.2_v2", tool_mode="sandbox")
    assert image == "rufimelo/benign-pull-requests:gpt5.2_v2"
