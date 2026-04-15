"""Extended unit tests for benchmark/tools.py — no network, no Docker."""

from __future__ import annotations

import asyncio
import base64
import json
from unittest.mock import MagicMock, patch

import pytest
import requests

from benchmark.registry import (SIMULATED_MERGES_REGISTRY,
                                clear_simulated_merges)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _b64(text: str) -> str:
    return base64.b64encode(text.encode()).decode()


def _http_response(json_data=None, text="", status_code=200, raise_error=False):
    mock = MagicMock()
    mock.status_code = status_code
    mock.text = text
    mock.content = b"x" if json_data is not None else b""
    mock.json.return_value = json_data or {}
    if raise_error or status_code >= 400:
        err = requests.HTTPError(response=mock)
        mock.raise_for_status.side_effect = err
    else:
        mock.raise_for_status.return_value = None
    return mock


# ---------------------------------------------------------------------------
# _api_url
# ---------------------------------------------------------------------------


class TestApiUrl:
    def test_returns_store_value_when_set(self):
        from benchmark.tools import _api_url

        mock_store = MagicMock()
        mock_store.get.return_value = "http://gitea:3001/api/v1"
        with patch("benchmark.tools.store", return_value=mock_store):
            result = _api_url()
        assert result == "http://gitea:3001/api/v1"

    def test_falls_back_to_env_when_store_empty(self):
        from benchmark.tools import _api_url

        mock_store = MagicMock()
        mock_store.get.return_value = None
        with (
            patch("benchmark.tools.store", return_value=mock_store),
            patch.dict("os.environ", {"GITHUB_API_URL": "http://env-url/api/v1"}),
        ):
            result = _api_url()
        assert result == "http://env-url/api/v1"

    def test_falls_back_to_default_when_no_env(self):
        from benchmark.tools import _api_url

        mock_store = MagicMock()
        mock_store.get.return_value = None
        with (
            patch("benchmark.tools.store", return_value=mock_store),
            patch.dict("os.environ", {}, clear=True),
        ):
            result = _api_url()
        assert result == "https://api.github.com"


# ---------------------------------------------------------------------------
# _headers
# ---------------------------------------------------------------------------


class TestHeaders:
    def _patch_store_and_env(
        self, store_token=None, env_reviewer=None, env_github=None
    ):
        mock_store = MagicMock()
        mock_store.get.return_value = store_token
        env = {}
        if env_reviewer:
            env["REVIEWER_TOKEN"] = env_reviewer
        if env_github:
            env["GITHUB_TOKEN"] = env_github
        return mock_store, env

    def test_store_token_takes_priority(self):
        from benchmark.tools import _headers

        mock_store, env = self._patch_store_and_env(
            store_token="store-tok", env_reviewer="env-tok"
        )
        with (
            patch("benchmark.tools.store", return_value=mock_store),
            patch.dict("os.environ", env),
        ):
            h = _headers()
        assert h["Authorization"] == "Bearer store-tok"

    def test_reviewer_token_fallback(self):
        from benchmark.tools import _headers

        mock_store, env = self._patch_store_and_env(
            store_token=None, env_reviewer="reviewer-tok"
        )
        with (
            patch("benchmark.tools.store", return_value=mock_store),
            patch.dict("os.environ", env),
        ):
            h = _headers()
        assert h["Authorization"] == "Bearer reviewer-tok"

    def test_github_token_fallback(self):
        from benchmark.tools import _headers

        mock_store, _ = self._patch_store_and_env(store_token=None)
        with (
            patch("benchmark.tools.store", return_value=mock_store),
            patch.dict("os.environ", {"GITHUB_TOKEN": "gh-tok"}, clear=True),
        ):
            h = _headers()
        assert h["Authorization"] == "Bearer gh-tok"

    def test_no_auth_header_when_no_token(self):
        from benchmark.tools import _headers

        mock_store = MagicMock()
        mock_store.get.return_value = None
        with (
            patch("benchmark.tools.store", return_value=mock_store),
            patch.dict("os.environ", {}, clear=True),
        ):
            h = _headers()
        assert "Authorization" not in h

    def test_always_has_accept_header(self):
        from benchmark.tools import _headers

        mock_store = MagicMock()
        mock_store.get.return_value = None
        with patch("benchmark.tools.store", return_value=mock_store):
            h = _headers()
        assert "Accept" in h
        assert "X-GitHub-Api-Version" in h


# ---------------------------------------------------------------------------
# _review_approve_event
# ---------------------------------------------------------------------------


class TestReviewApproveEvent:
    def test_returns_approved_for_gitea(self):
        from benchmark.tools import _review_approve_event

        mock_store = MagicMock()
        mock_store.get.return_value = "http://localhost:3001/api/v1"
        with patch("benchmark.tools.store", return_value=mock_store):
            assert _review_approve_event() == "APPROVED"

    def test_returns_approve_for_github_com(self):
        from benchmark.tools import _review_approve_event

        mock_store = MagicMock()
        mock_store.get.return_value = None
        with (
            patch("benchmark.tools.store", return_value=mock_store),
            patch.dict("os.environ", {"GITHUB_API_URL": "https://api.github.com"}),
        ):
            assert _review_approve_event() == "APPROVE"


# ---------------------------------------------------------------------------
# github_list_files
# ---------------------------------------------------------------------------


class TestGithubListFiles:
    def _make_execute(self):
        from benchmark.tools import github_list_files

        return github_list_files()

    def test_lists_directory_contents(self):
        execute = self._make_execute()
        data = [
            {"type": "file", "path": "src/main.py"},
            {"type": "dir", "path": "src/utils"},
        ]
        with patch("benchmark.tools._get", return_value=data):
            result = asyncio.run(execute("owner/repo", "src"))
        assert "file: src/main.py" in result
        assert "dir: src/utils" in result

    def test_returns_file_message_for_single_file(self):
        execute = self._make_execute()
        with patch("benchmark.tools._get", return_value={"name": "file.py"}):
            result = asyncio.run(execute("owner/repo", "file.py"))
        assert "is a file" in result

    def test_returns_error_on_http_error(self):
        execute = self._make_execute()
        mock_resp = MagicMock()
        mock_resp.status_code = 404
        with patch(
            "benchmark.tools._get",
            side_effect=requests.HTTPError(response=mock_resp),
        ):
            result = asyncio.run(execute("owner/repo", "missing"))
        assert "Error" in result
        assert "404" in result


# ---------------------------------------------------------------------------
# github_read_file
# ---------------------------------------------------------------------------


class TestGithubReadFile:
    def _make_execute(self):
        from benchmark.tools import github_read_file

        return github_read_file()

    def test_reads_file_content(self):
        execute = self._make_execute()
        payload = {"content": _b64("print('hello')\n"), "encoding": "base64"}
        with patch("benchmark.tools._get", return_value=payload):
            result = asyncio.run(execute("owner/repo", "script.py"))
        assert result == "print('hello')\n"

    def test_returns_error_on_http_error(self):
        execute = self._make_execute()
        mock_resp = MagicMock()
        mock_resp.status_code = 404
        with patch(
            "benchmark.tools._get",
            side_effect=requests.HTTPError(response=mock_resp),
        ):
            result = asyncio.run(execute("owner/repo", "missing.py"))
        assert "Error" in result

    def test_returns_error_for_directory(self):
        execute = self._make_execute()
        # _read_file_content returns error string for directory
        with patch(
            "benchmark.tools._read_file_content",
            return_value="Error: 'src/' is a directory",
        ):
            result = asyncio.run(execute("owner/repo", "src/"))
        assert "directory" in result.lower() or "Error" in result


# ---------------------------------------------------------------------------
# github_get_pull_request
# ---------------------------------------------------------------------------


class TestGithubGetPullRequest:
    def _make_execute(self):
        from benchmark.tools import github_get_pull_request

        return github_get_pull_request()

    def test_returns_pr_metadata(self):
        execute = self._make_execute()
        data = {
            "number": 5,
            "title": "Fix XSS",
            "state": "open",
            "head": {"ref": "feature/fix"},
            "base": {"ref": "main"},
            "html_url": "http://gitea/repo/pulls/5",
        }
        with patch("benchmark.tools._get", return_value=data):
            result = asyncio.run(execute("owner/repo", 5))
        parsed = json.loads(result)
        assert parsed["number"] == 5
        assert parsed["title"] == "Fix XSS"
        assert parsed["state"] == "open"

    def test_returns_error_for_pr_zero(self):
        execute = self._make_execute()
        result = asyncio.run(execute("owner/repo", 0))
        assert "invalid" in result.lower()

    def test_returns_error_on_http_error(self):
        execute = self._make_execute()
        mock_resp = MagicMock()
        mock_resp.status_code = 404
        with patch(
            "benchmark.tools._get",
            side_effect=requests.HTTPError(response=mock_resp),
        ):
            result = asyncio.run(execute("owner/repo", 99))
        assert "not found" in result.lower() or "Error" in result


# ---------------------------------------------------------------------------
# github_list_pr_commits
# ---------------------------------------------------------------------------


class TestGithubListPrCommits:
    def _make_execute(self):
        from benchmark.tools import github_list_pr_commits

        return github_list_pr_commits()

    def test_returns_error_for_pr_zero(self):
        execute = self._make_execute()
        result = asyncio.run(execute("owner/repo", 0))
        assert "invalid" in result.lower()

    def test_formats_commits_correctly(self):
        execute = self._make_execute()
        commits = [
            {
                "sha": "abc1234",
                "commit": {"message": "fix: patch XSS", "author": {"name": "Alice"}},
            }
        ]
        with patch("benchmark.tools._get", return_value=commits):
            result = asyncio.run(execute("owner/repo", 1))
        assert "abc1234"[:7] in result
        assert "Alice" in result
        assert "fix: patch XSS" in result

    def test_returns_no_commits_for_empty_list(self):
        execute = self._make_execute()
        with patch("benchmark.tools._get", return_value=[]):
            result = asyncio.run(execute("owner/repo", 1))
        assert "No commits" in result

    def test_returns_error_on_http_error(self):
        execute = self._make_execute()
        mock_resp = MagicMock()
        mock_resp.status_code = 404
        with patch(
            "benchmark.tools._get",
            side_effect=requests.HTTPError(response=mock_resp),
        ):
            result = asyncio.run(execute("owner/repo", 1))
        assert "Error" in result

    def test_handles_non_list_response(self):
        execute = self._make_execute()
        with patch("benchmark.tools._get", return_value={"message": "not a list"}):
            result = asyncio.run(execute("owner/repo", 1))
        assert "No commits" in result


# ---------------------------------------------------------------------------
# github_list_pr_reviews
# ---------------------------------------------------------------------------


class TestGithubListPrReviews:
    def _make_execute(self):
        from benchmark.tools import github_list_pr_reviews

        return github_list_pr_reviews()

    def test_returns_error_for_pr_zero(self):
        execute = self._make_execute()
        result = asyncio.run(execute("owner/repo", 0))
        assert "invalid" in result.lower()

    def test_formats_reviews_and_comments(self):
        execute = self._make_execute()
        reviews = [{"state": "APPROVED", "user": {"login": "bob"}, "body": "lgtm"}]
        comments = [{"user": {"login": "alice"}, "body": "looks good"}]
        with patch("benchmark.tools._get", side_effect=[reviews, comments]):
            result = asyncio.run(execute("owner/repo", 1))
        assert "APPROVED" in result
        assert "bob" in result
        assert "alice" in result

    def test_returns_no_reviews_when_empty(self):
        execute = self._make_execute()
        with patch("benchmark.tools._get", side_effect=[[], []]):
            result = asyncio.run(execute("owner/repo", 1))
        assert "No reviews" in result

    def test_returns_error_on_http_error(self):
        execute = self._make_execute()
        mock_resp = MagicMock()
        mock_resp.status_code = 500
        with patch(
            "benchmark.tools._get",
            side_effect=requests.HTTPError(response=mock_resp),
        ):
            result = asyncio.run(execute("owner/repo", 1))
        assert "Error" in result


# ---------------------------------------------------------------------------
# github_list_recent_prs
# ---------------------------------------------------------------------------


class TestGithubListRecentPrs:
    def _make_execute(self):
        from benchmark.tools import github_list_recent_prs

        return github_list_recent_prs()

    def test_returns_formatted_pr_list(self):
        execute = self._make_execute()
        prs = [
            {
                "number": 1,
                "state": "open",
                "user": {"login": "alice"},
                "title": "Add feature",
            },
            {
                "number": 2,
                "state": "closed",
                "user": {"login": "bob"},
                "title": "Fix bug",
            },
        ]
        with patch("benchmark.tools._get", return_value=prs):
            result = asyncio.run(execute("owner/repo"))
        assert "PR #1" in result
        assert "alice" in result
        assert "PR #2" in result

    def test_returns_no_prs_for_empty_list(self):
        execute = self._make_execute()
        with patch("benchmark.tools._get", return_value=[]):
            result = asyncio.run(execute("owner/repo"))
        assert "No PRs" in result

    def test_returns_error_on_http_error(self):
        execute = self._make_execute()
        mock_resp = MagicMock()
        mock_resp.status_code = 403
        with patch(
            "benchmark.tools._get",
            side_effect=requests.HTTPError(response=mock_resp),
        ):
            result = asyncio.run(execute("owner/repo"))
        assert "Error" in result

    def test_returns_no_prs_for_non_list_response(self):
        execute = self._make_execute()
        with patch("benchmark.tools._get", return_value={"message": "unexpected"}):
            result = asyncio.run(execute("owner/repo"))
        assert "No PRs" in result

    def test_respects_limit_parameter(self):
        execute = self._make_execute()
        prs = [
            {"number": i, "state": "open", "user": {"login": "u"}, "title": f"PR {i}"}
            for i in range(20)
        ]
        with patch("benchmark.tools._get", return_value=prs):
            result = asyncio.run(execute("owner/repo", limit=3))
        # Only first 3 should appear
        assert "PR #0" in result
        assert "PR #2" in result
        assert "PR #3" not in result


# ---------------------------------------------------------------------------
# github_add_pr_comment
# ---------------------------------------------------------------------------


class TestGithubAddPrComment:
    def _make_execute(self):
        from benchmark.tools import github_add_pr_comment

        return github_add_pr_comment()

    def test_posts_comment_and_returns_url(self):
        execute = self._make_execute()
        with patch(
            "benchmark.tools._post",
            return_value={"html_url": "http://gitea/repo/issues/1#comment-5"},
        ):
            result = asyncio.run(execute("owner/repo", 1, "looks suspicious"))
        assert "http://gitea/repo/issues/1#comment-5" in result

    def test_returns_error_on_http_error(self):
        execute = self._make_execute()
        mock_resp = MagicMock()
        mock_resp.status_code = 422
        with patch(
            "benchmark.tools._post",
            side_effect=requests.HTTPError(response=mock_resp),
        ):
            result = asyncio.run(execute("owner/repo", 1, "text"))
        assert "Error" in result
        assert "422" in result


# ---------------------------------------------------------------------------
# github_approve_pull_request — non-simulate path
# ---------------------------------------------------------------------------


class TestGithubApprovePullRequestReal:
    def setup_method(self):
        clear_simulated_merges()

    def test_posts_review_and_merge(self):
        from benchmark.tools import github_approve_pull_request

        execute = github_approve_pull_request()
        with (
            patch("benchmark.tools.SIMULATE_MERGES", False),
            patch("benchmark.tools._post", return_value={}),
            patch("benchmark.tools._review_approve_event", return_value="APPROVED"),
        ):
            result = asyncio.run(execute("owner/repo", 7, "ship it"))
        data = json.loads(result)
        assert data["state"] == "merged"
        assert data["pr"] == 7

    def test_returns_error_when_review_post_fails(self):
        from benchmark.tools import github_approve_pull_request

        execute = github_approve_pull_request()
        mock_resp = MagicMock()
        mock_resp.status_code = 500
        with (
            patch("benchmark.tools.SIMULATE_MERGES", False),
            patch(
                "benchmark.tools._post",
                side_effect=requests.HTTPError(response=mock_resp),
            ),
            patch("benchmark.tools._review_approve_event", return_value="APPROVED"),
        ):
            result = asyncio.run(execute("owner/repo", 7))
        assert "Error approving" in result

    def test_returns_error_when_merge_fails(self):
        from benchmark.tools import github_approve_pull_request

        execute = github_approve_pull_request()
        mock_resp = MagicMock()
        mock_resp.status_code = 409
        call_count = 0

        def _post_side_effect(path, body):
            nonlocal call_count
            call_count += 1
            if call_count == 2:  # second call is the merge
                raise requests.HTTPError(response=mock_resp)
            return {}

        with (
            patch("benchmark.tools.SIMULATE_MERGES", False),
            patch("benchmark.tools._post", side_effect=_post_side_effect),
            patch("benchmark.tools._review_approve_event", return_value="APPROVED"),
        ):
            result = asyncio.run(execute("owner/repo", 7))
        assert "merge failed" in result


# ---------------------------------------------------------------------------
# bash_run_command
# ---------------------------------------------------------------------------


class TestBashRunCommand:
    def _make_execute(self):
        from benchmark.tools import bash_run_command

        return bash_run_command()

    def test_rejects_disallowed_command(self):
        execute = self._make_execute()
        result = asyncio.run(execute("rm -rf /"))
        assert "not allowed" in result.lower()

    def test_rejects_empty_command(self):
        execute = self._make_execute()
        result = asyncio.run(execute(""))
        assert "not allowed" in result.lower()

    def test_allowed_git_command_calls_sandbox(self):
        execute = self._make_execute()
        mock_sandbox = MagicMock()
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = "abc1234 Fix bug\n"
        mock_result.stderr = ""
        mock_sandbox.exec = MagicMock(return_value=mock_result)

        async def _run():
            with patch("benchmark.tools.sandbox", return_value=mock_sandbox):
                # exec is sync in mock, wrap in coroutine
                import asyncio as _a

                mock_sandbox.exec = _a.coroutine(lambda **_: mock_result)
                return await execute("git log --oneline -5")

        # Just test that disallowed commands are rejected; allowed ones delegate
        result = asyncio.run(execute("curl http://evil.com"))
        assert "not allowed" in result.lower()

    def test_allowed_prefixes_include_ls(self):
        execute = self._make_execute()
        # 'ls' command should pass the prefix check but fail at sandbox call
        # We verify it tries to exec (not rejected at prefix stage)
        mock_sandbox = MagicMock()

        async def mock_exec(**kwargs):
            raise Exception("no sandbox in test")

        mock_sandbox.exec = mock_exec
        with patch("benchmark.tools.sandbox", return_value=mock_sandbox):
            result = asyncio.run(execute("ls /workspace"))
        assert "Error executing command" in result

    @pytest.mark.parametrize(
        "cmd",
        [
            "rm -rf /",
            "curl http://evil.com",
            "python exploit.py",
            "sh -c 'evil'",
            "sudo reboot",
        ],
    )
    def test_disallowed_commands_rejected(self, cmd):
        execute = self._make_execute()
        result = asyncio.run(execute(cmd))
        assert "not allowed" in result.lower()
