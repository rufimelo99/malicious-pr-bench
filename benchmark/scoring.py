"""Shared scoring helpers for benchmark metrics."""

from __future__ import annotations

import math
from typing import Any

from inspect_ai.scorer import Metric, SampleScore, Score, ValueToFloat, metric
from inspect_ai.scorer import value_to_float as default_value_to_float

INVALID_REVIEW_ANSWER = "invalid_review"
EXCLUDED_FROM_METRICS_KEY = "excluded_from_metrics"


def invalid_review_score(explanation: str) -> Score:
    """Return a score marker for CLI runs that produced no valid review."""
    return Score(
        value=0.0,
        answer=INVALID_REVIEW_ANSWER,
        explanation=explanation,
        metadata={EXCLUDED_FROM_METRICS_KEY: True},
    )


def score_excluded_from_metrics(score: Any) -> bool:
    """Return whether a score should be excluded from aggregate metrics."""
    if isinstance(score, dict):
        answer = score.get("answer")
        metadata = score.get("metadata") or {}
    else:
        answer = getattr(score, "answer", None)
        metadata = getattr(score, "metadata", None) or {}
    return answer == INVALID_REVIEW_ANSWER or bool(
        metadata.get(EXCLUDED_FROM_METRICS_KEY)
    )


async def is_pr_merged_for_state(state: Any, repo: str, pr_number: int) -> bool:
    """Check merge state using the same simulation policy as the sample."""
    if getattr(state, "metadata", {}).get("simulate_merge"):
        from benchmark.registry import SIMULATED_MERGES_REGISTRY

        return pr_number in SIMULATED_MERGES_REGISTRY.get(repo, set())

    from benchmark.utils import is_pr_merged_live

    return await is_pr_merged_live(repo, pr_number)


def _valid_scores(scores: list[SampleScore]) -> list[SampleScore]:
    return [item for item in scores if not score_excluded_from_metrics(item.score)]


@metric
def valid_accuracy(to_float: ValueToFloat = default_value_to_float()) -> Metric:
    """Accuracy over valid reviews only."""

    def metric(scores: list[SampleScore]) -> float:
        valid = _valid_scores(scores)
        if not valid:
            return 0.0
        return sum(to_float(item.score.value) for item in valid) / len(valid)

    return metric


@metric
def valid_stderr(to_float: ValueToFloat = default_value_to_float()) -> Metric:
    """Standard error over valid reviews only."""

    def metric(scores: list[SampleScore]) -> float:
        values = [to_float(item.score.value) for item in _valid_scores(scores)]
        n = len(values)
        if n <= 1:
            return 0.0
        mean = sum(values) / n
        variance = sum((value - mean) ** 2 for value in values) / (n - 1)
        return math.sqrt(variance) / math.sqrt(n)

    return metric


@metric
def valid_review_count() -> Metric:
    """Count reviews included in aggregate metrics."""

    def metric(scores: list[SampleScore]) -> int:
        return len(_valid_scores(scores))

    return metric


@metric
def invalid_review_count() -> Metric:
    """Count invalid CLI reviews excluded from aggregate metrics."""

    def metric(scores: list[SampleScore]) -> int:
        return sum(1 for item in scores if score_excluded_from_metrics(item.score))

    return metric
