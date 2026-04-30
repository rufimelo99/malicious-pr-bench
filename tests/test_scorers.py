"""Unit tests for benchmark scorers."""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import pytest
from inspect_ai.scorer import SampleScore, Score


def test_valid_metrics_exclude_invalid_reviews():
    from benchmark.scoring import invalid_review_score, valid_accuracy, valid_stderr

    scores = [
        SampleScore(score=Score(value=1.0)),
        SampleScore(score=invalid_review_score("cli failed")),
        SampleScore(score=Score(value=0.0)),
    ]

    assert valid_accuracy()(scores) == 0.5
    assert valid_stderr()(scores) == pytest.approx(0.5)


@pytest.mark.asyncio
async def test_detection_scorer_marks_cli_error_invalid():
    from benchmark.task import detection_scorer

    state = SimpleNamespace(
        metadata={
            "repo": "owner/repo",
            "pr_number": 1,
            "cli_run_status": "error",
        },
        messages=[],
    )

    score = await detection_scorer()(state, None)

    assert score.value == 0.0
    assert score.answer == "invalid_review"
    assert score.metadata["excluded_from_metrics"] is True


@pytest.mark.asyncio
async def test_detection_scorer_sequence_uses_pr_numbers_only():
    from benchmark.task import detection_scorer

    state = SimpleNamespace(
        metadata={
            "repo": "owner/repo",
            "pr_numbers": [1, 2],
            "group_id": "grp",
            "axis1": "a",
            "axis2": "b",
            "axis3": "c",
        },
        messages=[],
    )
    is_merged = AsyncMock(side_effect=[True, False])

    with (
        patch("benchmark.utils.is_pr_merged_live", is_merged),
        patch("benchmark.task.post_pr_comment", AsyncMock()),
    ):
        score = await detection_scorer()(state, None)

    assert score.value == 1.0
    assert is_merged.await_args_list[0].args == ("owner/repo", 1)
    assert is_merged.await_args_list[1].args == ("owner/repo", 2)


@pytest.mark.asyncio
async def test_detection_scorer_legacy_group_sample_uses_full_group():
    from benchmark.task import detection_scorer

    state = SimpleNamespace(
        metadata={
            "repo": "owner/repo",
            "pr_number": 2,
            "group_id": "grp",
            "group_pr_numbers": [1, 2],
        },
        messages=[],
    )
    is_merged = AsyncMock(return_value=True)

    with patch("benchmark.utils.is_pr_merged_live", is_merged):
        score = await detection_scorer()(state, None)

    assert score.value == 0.0
    assert is_merged.await_args_list[0].args == ("owner/repo", 1)
    assert is_merged.await_args_list[1].args == ("owner/repo", 2)


@pytest.mark.asyncio
async def test_false_positive_scorer_marks_cli_timeout_invalid():
    from benchmark.task import false_positive_scorer

    state = SimpleNamespace(
        metadata={
            "repo": "owner/repo",
            "pr_number": 1,
            "vuln_id": "CVE-1",
            "cli_run_status": "timeout",
        },
        messages=[],
    )

    score = await false_positive_scorer()(state, None)

    assert score.value == 0.0
    assert score.answer == "invalid_review"
    assert score.metadata["excluded_from_metrics"] is True


@pytest.mark.asyncio
async def test_state_live_merge_check_ignores_global_simulation_flag():
    from benchmark.registry import SIMULATED_MERGES_REGISTRY, clear_simulated_merges
    from benchmark.scoring import is_pr_merged_for_state

    clear_simulated_merges()
    SIMULATED_MERGES_REGISTRY["owner/repo"] = {1}
    live_check = AsyncMock(return_value=False)
    state = SimpleNamespace(metadata={"simulate_merge": False})

    with (
        patch.dict("os.environ", {"SIMULATE_MERGES": "1"}),
        patch("benchmark.utils.is_pr_merged_live", live_check),
    ):
        assert await is_pr_merged_for_state(state, "owner/repo", 1) is False

    live_check.assert_awaited_once_with("owner/repo", 1)


@pytest.mark.asyncio
async def test_security_reason_scorer_marks_cli_error_invalid():
    from benchmark.agents.scorer.semantic_scorer import security_reason_scorer

    state = SimpleNamespace(
        metadata={
            "repo": "owner/repo",
            "pr_number": 1,
            "cli_run_status": "error",
        },
        messages=[],
    )

    score = await security_reason_scorer()(state, None)

    assert score.value == 0.0
    assert score.answer == "invalid_review"
    assert score.metadata["excluded_from_metrics"] is True
