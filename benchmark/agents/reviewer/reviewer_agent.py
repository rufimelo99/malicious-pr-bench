"""Security-aware code reviewer agent."""

from __future__ import annotations

from pathlib import Path
from typing import Literal

from inspect_ai.agent import react
from inspect_ai.agent._types import AgentPrompt
from inspect_ai.tool import Tool

from benchmark.tools import (bash_checkout_branch, bash_git_diff,
                             bash_list_branches, bash_run_command,
                             github_add_pr_comment,
                             github_approve_pull_request,
                             github_get_pull_request, github_list_files,
                             github_list_pr_commits, github_list_pr_files,
                             github_list_pr_reviews, github_list_recent_prs,
                             github_read_file, github_search_code)

_PROMPTS_DIR = Path(__file__).parent / "prompts"

# One system prompt per tool mode
_SYSTEM_PROMPTS: dict[str, str] = {
    "gitea": (_PROMPTS_DIR / "reviewer_system_prompt.txt").read_text(),
    "sandbox": (_PROMPTS_DIR / "reviewer_system_prompt_sandbox.txt").read_text(),
}

ToolMode = Literal["gitea", "sandbox"]


def build_reviewer_agent(
    extra_tools: list[Tool] | None = None,
    model: str | None = None,
    tool_mode: ToolMode = "sandbox",
):
    """Build the code reviewer agent.

    Parameters
    ----------
    tool_mode : "gitea" | "sandbox"
        Controls which tools the agent has access to and which system prompt is used.

        - ``"gitea"``   — Full Gitea/GitHub API toolset (github_* tools + approve).
        - ``"sandbox"`` — Bash sandbox tools + approve only. Repo pre-cloned at
                          /workspace/repo. No direct API read access.
    """
    if tool_mode == "gitea":
        tools: list[Tool] = [
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
        ]
    else:  # "sandbox"
        tools = [
            bash_run_command(),
            github_approve_pull_request(),
        ]

    if extra_tools:
        tools.extend(extra_tools)

    return react(
        name="reviewer",
        description="Code reviewer agent",
        tools=tools,
        prompt=AgentPrompt(instructions=_SYSTEM_PROMPTS[tool_mode]),
        model=model,
    )
