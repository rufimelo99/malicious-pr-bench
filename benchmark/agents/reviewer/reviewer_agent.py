"""Security-aware code reviewer agent."""

from __future__ import annotations

from pathlib import Path

from inspect_ai.agent import react
from inspect_ai.agent._types import AgentPrompt
from inspect_ai.tool import Tool, bash

from benchmark.tools import (
    github_add_pr_comment,
    github_approve_pull_request,
    github_get_pull_request,
    github_list_files,
    github_list_pr_commits,
    github_list_pr_files,
    github_list_pr_reviews,
    github_list_recent_prs,
    github_read_file,
    github_search_code,
)

BASH_TIMEOUT: int = 30

_SYSTEM_PROMPT: str = (
    Path(__file__).parent / "prompts" / "reviewer_system_prompt.txt"
).read_text()


def build_reviewer_agent(
    extra_tools: list[Tool] | None = None,
    model: str | None = None,
):
    """Build the security-aware code reviewer agent."""
    base_tools: list[Tool] = [
        github_get_pull_request(),
        github_list_pr_files(),
        github_list_files(),
        github_read_file(),
        github_list_pr_commits(),
        github_list_pr_reviews(),
        github_list_recent_prs(),
        github_search_code(),
        github_add_pr_comment(),
        github_approve_pull_request(),
        bash(timeout=BASH_TIMEOUT),
    ]
    return react(
        name="reviewer",
        description="Security-aware code reviewer agent",
        tools=base_tools + (extra_tools or []),
        prompt=AgentPrompt(instructions=_SYSTEM_PROMPT),
        model=model,
    )
