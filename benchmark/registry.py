"""GitHub / Gitea API tools for the reviewer agent."""

from __future__ import annotations

# Tracks simulated merges when SIMULATE_MERGES env var is set.
# Keys are repo slugs; values are sets of PR numbers the agent approved.
SIMULATED_MERGES_REGISTRY: dict[str, set[int]] = {}


def clear_simulated_merges() -> None:
    """Reset all tracked simulated merges (call before each benchmark run)."""
    SIMULATED_MERGES_REGISTRY.clear()


def clear_simulated_merges_for(repo: str, pr_numbers: list[int]) -> None:
    """Clear simulated approvals for the PRs in one sample."""
    approved = SIMULATED_MERGES_REGISTRY.get(repo)
    if not approved:
        return
    for pr_number in pr_numbers:
        approved.discard(int(pr_number))
    if not approved:
        SIMULATED_MERGES_REGISTRY.pop(repo, None)
