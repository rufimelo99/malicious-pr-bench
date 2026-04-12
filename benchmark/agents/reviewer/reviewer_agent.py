"""Security-aware code reviewer agent."""

from __future__ import annotations

from pathlib import Path

from inspect_ai.agent import react
from inspect_ai.agent._types import AgentPrompt
from inspect_ai.tool import Tool

from benchmark.tools import (bash_checkout_branch, bash_git_clone,
                             bash_git_diff, bash_list_branches,
                             bash_run_command, github_add_pr_comment,
                             github_approve_pull_request,
                             github_get_pull_request, github_list_files,
                             github_list_pr_commits, github_list_pr_files,
                             github_list_pr_reviews, github_list_recent_prs,
                             github_read_file, github_search_code)

_SYSTEM_PROMPT: str = (
    Path(__file__).parent / "prompts" / "reviewer_system_prompt.txt"
).read_text()


def build_reviewer_agent(
    extra_tools: list[Tool] | None = None,
    model: str | None = None,
):
    """Build the code reviewer agent."""
    tools = [
        # GitHub API tools - disabled for now, validating bash sandbox tools
        # github_get_pull_request(),
        # github_list_pr_files(),
        # github_list_files(),
        # github_read_file(),
        # github_list_pr_commits(),
        # github_list_pr_reviews(),
        # github_list_recent_prs(),
        # github_search_code(),
        # github_add_pr_comment(),
        # github_approve_pull_request(),
        # Bash sandbox tools only (repo cloned by default via sample_init)
        bash_run_command(),
        # bash_git_clone(),  # Not needed - repo cloned automatically
        bash_checkout_branch(),
        bash_git_diff(),
        bash_list_branches(),
    ]
    if extra_tools:
        tools.extend(extra_tools)
    return react(
        name="reviewer",
        description="Code reviewer agent",
        tools=tools,
        prompt=AgentPrompt(instructions=_SYSTEM_PROMPT),
        model=model,
    )
