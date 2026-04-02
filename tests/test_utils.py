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


# ---------------------------------------------------------------------------
# is_pr_merged (simulate mode)
# ---------------------------------------------------------------------------

class TestIsPrMerged:
    def setup_method(self):
        clear_simulated_merges()

    @pytest.mark.asyncio
    async def test_returns_true_when_in_registry(self):
        from unittest.mock import patch

        from benchmark.utils import is_pr_merged

        SIMULATED_MERGES_REGISTRY["owner/repo"] = {5}
        with patch("benchmark.utils._SIMULATE_MERGES", True):
            assert await is_pr_merged("owner/repo", 5) is True

    @pytest.mark.asyncio
    async def test_returns_false_when_not_in_registry(self):
        from unittest.mock import patch

        from benchmark.utils import is_pr_merged

        with patch("benchmark.utils._SIMULATE_MERGES", True):
            assert await is_pr_merged("owner/repo", 99) is False

    @pytest.mark.asyncio
    async def test_returns_false_for_unknown_repo(self):
        from unittest.mock import patch

        from benchmark.utils import is_pr_merged

        with patch("benchmark.utils._SIMULATE_MERGES", True):
            assert await is_pr_merged("unknown/repo", 1) is False
