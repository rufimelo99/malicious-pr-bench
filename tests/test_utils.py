"""Unit tests for benchmark/utils.py."""

from __future__ import annotations

import pytest

from benchmark.registry import SIMULATED_MERGES_REGISTRY, clear_simulated_merges

# ---------------------------------------------------------------------------
# extract_reviewer_reason
# ---------------------------------------------------------------------------


class TestExtractReviewerReason:
    def _make_msg(self, role: str, content):
        from inspect_ai.model import ChatMessageAssistant, ChatMessageUser

        if role == "assistant":
            return ChatMessageAssistant(content=content)
        return ChatMessageUser(content=content)

    def test_returns_last_assistant_text(self):
        from benchmark.utils import extract_reviewer_reason

        msgs = [
            self._make_msg("user", "please review"),
            self._make_msg("assistant", "first response"),
            self._make_msg("assistant", "final decision"),
        ]
        assert extract_reviewer_reason(msgs) == "final decision"

    def test_skips_user_messages(self):
        from benchmark.utils import extract_reviewer_reason

        msgs = [
            self._make_msg("assistant", "declined"),
            self._make_msg("user", "this should be ignored"),
        ]
        assert extract_reviewer_reason(msgs) == "declined"

    def test_empty_messages_returns_fallback(self):
        from benchmark.utils import extract_reviewer_reason

        result = extract_reviewer_reason([])
        assert "without leaving a reason" in result

    def test_truncates_long_reason(self):
        from benchmark.utils import extract_reviewer_reason

        long_text = "x" * 2000
        msgs = [self._make_msg("assistant", long_text)]
        result = extract_reviewer_reason(msgs)
        assert len(result) <= 1000

    def test_skips_empty_assistant_messages(self):
        from benchmark.utils import extract_reviewer_reason

        msgs = [
            self._make_msg("assistant", "real reason"),
            self._make_msg("assistant", "   "),
        ]
        assert extract_reviewer_reason(msgs) == "real reason"


class TestIsPrMerged:
    def setup_method(self):
        clear_simulated_merges()

    @pytest.mark.asyncio
    async def test_returns_true_when_in_registry(self):
        from unittest.mock import patch

        from benchmark.utils import is_pr_merged

        SIMULATED_MERGES_REGISTRY["owner/repo"] = {5}
        with patch("benchmark.utils.SIMULATE_MERGES", True):
            assert await is_pr_merged("owner/repo", 5) is True

    @pytest.mark.asyncio
    async def test_returns_false_when_not_in_registry(self):
        from unittest.mock import patch

        from benchmark.utils import is_pr_merged

        with patch("benchmark.utils.SIMULATE_MERGES", True):
            assert await is_pr_merged("owner/repo", 99) is False

    @pytest.mark.asyncio
    async def test_returns_false_for_unknown_repo(self):
        from unittest.mock import patch

        from benchmark.utils import is_pr_merged

        with patch("benchmark.utils.SIMULATE_MERGES", True):
            assert await is_pr_merged("unknown/repo", 1) is False


# ---------------------------------------------------------------------------
# PR metadata helpers
# ---------------------------------------------------------------------------


class TestPrMetadataHelpers:
    def test_format_pr_description_omits_empty_parts(self):
        from benchmark.utils import format_pr_description

        assert format_pr_description("", "") == ""
        assert format_pr_description("Title", "") == "PR title: Title"
        assert format_pr_description("", "Body") == "PR description:\nBody"

    def test_store_pr_details_sets_single_pr_fields(self):
        from benchmark.utils import store_pr_details

        metadata: dict[str, object] = {"repo": "owner/repo", "pr_number": 7}
        store_pr_details(metadata, 7, "Fix bug", "Adds a guard.")

        assert metadata["pr_title"] == "Fix bug"
        assert metadata["pr_body"] == "Adds a guard."
        assert metadata["pr_details"] == {
            "7": {"title": "Fix bug", "body": "Adds a guard."}
        }

    def test_store_pr_details_preserves_existing_entries_and_normalizes_keys(self):
        from benchmark.utils import store_pr_details

        metadata: dict[str, object] = {
            "pr_details": {1: {"title": "First", "body": "One"}},
            "pr_numbers": [1, 2],
        }
        store_pr_details(metadata, 2, "Second", "Two")

        assert metadata["pr_details"] == {
            "1": {"title": "First", "body": "One"},
            "2": {"title": "Second", "body": "Two"},
        }
        assert "pr_title" not in metadata
        assert "pr_body" not in metadata
