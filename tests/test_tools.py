"""Unit tests for benchmark/tools.py — no network, no Docker."""

from __future__ import annotations

import base64
import json
from unittest.mock import MagicMock, patch

import pytest
import requests

from benchmark.registry import SIMULATED_MERGES_REGISTRY, clear_simulated_merges


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _b64(text: str) -> str:
    return base64.b64encode(text.encode()).decode()


def _mock_get(responses: dict):
    """Return a side_effect function that maps URL substrings to return values."""
    def _side_effect(path: str):
        for key, val in responses.items():
            if key in path:
                return val
        raise AssertionError(f"Unexpected _get call: {path}")
    return _side_effect


# ---------------------------------------------------------------------------
# _read_file_content
# ---------------------------------------------------------------------------

class TestReadFileContent:
    def test_decodes_base64_content(self):
        from benchmark.tools import _read_file_content

        payload = {"content": _b64("hello world\n"), "encoding": "base64"}
        with patch("benchmark.tools._get", return_value=payload):
            result = _read_file_content("owner/repo", "file.txt")
        assert result == "hello world\n"

    def test_returns_error_for_directory(self):
        from benchmark.tools import _read_file_content

        with patch("benchmark.tools._get", return_value=[{"name": "subdir"}]):
            result = _read_file_content("owner/repo", "some/dir")
        assert "directory" in result.lower()


# ---------------------------------------------------------------------------
# github_list_pr_files
# ---------------------------------------------------------------------------

class TestGithubListPrFiles:
    def _make_execute(self):
        from benchmark.tools import github_list_pr_files
        return github_list_pr_files()

    def _mock_diff_response(self, text: str, status_code: int = 200):
        mock_resp = MagicMock()
        mock_resp.status_code = status_code
        mock_resp.text = text
        if status_code >= 400:
            mock_resp.raise_for_status.side_effect = requests.HTTPError(response=mock_resp)
        else:
            mock_resp.raise_for_status.return_value = None
        return mock_resp

    def test_returns_diff_content(self):
        execute = self._make_execute()
        diff = "diff --git a/foo.py b/foo.py\n@@ -1 +1 @@\n-old\n+new\n"

        with patch("requests.get", return_value=self._mock_diff_response(diff)):
            import asyncio
            result = asyncio.run(execute("owner/repo", 1))

        assert "@@ -1 +1 @@" in result

    def test_returns_error_on_http_error(self):
        execute = self._make_execute()

        with patch("requests.get", return_value=self._mock_diff_response("", 404)):
            import asyncio
            result = asyncio.run(execute("owner/repo", 1))

        assert "not found" in result.lower()

    def test_returns_error_for_pr_zero(self):
        execute = self._make_execute()
        import asyncio
        result = asyncio.run(execute("owner/repo", 0))
        assert "invalid" in result.lower()

    def test_returns_no_files_changed_for_empty_diff(self):
        execute = self._make_execute()

        with patch("requests.get", return_value=self._mock_diff_response("   ")):
            import asyncio
            result = asyncio.run(execute("owner/repo", 1))

        assert result == "No files changed."


# ---------------------------------------------------------------------------
# github_approve_pull_request (simulate mode)
# ---------------------------------------------------------------------------

class TestGithubApprovePullRequest:
    def setup_method(self):
        clear_simulated_merges()

    def test_simulate_mode_records_approval(self):
        from benchmark.tools import github_approve_pull_request

        execute = github_approve_pull_request()
        with patch("benchmark.tools.SIMULATE_MERGES", True):
            import asyncio
            result = asyncio.run(execute("owner/repo", 42))

        data = json.loads(result)
        assert data["state"] == "merged"
        assert 42 in SIMULATED_MERGES_REGISTRY.get("owner/repo", set())

    def test_simulate_mode_multiple_prs(self):
        from benchmark.tools import github_approve_pull_request

        execute = github_approve_pull_request()
        import asyncio
        with patch("benchmark.tools.SIMULATE_MERGES", True):
            asyncio.run(execute("owner/repo", 1))
            asyncio.run(execute("owner/repo", 2))

        assert SIMULATED_MERGES_REGISTRY["owner/repo"] == {1, 2}

    def test_returns_error_for_pr_zero(self):
        from benchmark.tools import github_approve_pull_request

        execute = github_approve_pull_request()
        import asyncio
        result = asyncio.run(execute("owner/repo", 0))
        assert "invalid" in result.lower()
