"""GitHub / Gitea API tools for the reviewer agent."""

from __future__ import annotations

from inspect_ai.tool import Tool, tool

# Tracks simulated merges when SIMULATE_MERGES env var is set.
# Keys are repo slugs; values are sets of PR numbers the agent approved.
SIMULATED_MERGES_REGISTRY: dict[str, set[int]] = {}


def clear_simulated_merges() -> None:
    """Reset all tracked simulated merges (call before each benchmark run)."""
    SIMULATED_MERGES_REGISTRY.clear()
