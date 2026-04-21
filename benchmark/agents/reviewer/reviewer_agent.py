"""Security-aware code reviewer agent."""

from __future__ import annotations

from inspect_ai.agent import react
from inspect_ai.agent._types import AgentPrompt
from inspect_ai.tool import Tool

from benchmark.agents.prompt_utils import load_prompt
from benchmark.config import PROMPT_FILES, PromptVariant, ToolMode
from benchmark.tools import (bash_run_command, github_add_pr_comment,
                             github_approve_pull_request,
                             github_get_pull_request, github_list_files,
                             github_list_pr_commits, github_list_pr_files,
                             github_list_pr_reviews, github_list_recent_prs,
                             github_read_file, github_search_code)

# Prompts by variant (loaded from config)
_VARIANT_PROMPTS = {
    variant: load_prompt(filename) for variant, filename in PROMPT_FILES.items()
}

# Prompts by tool mode and variant
_SYSTEM_PROMPTS: dict[str, dict[str, str]] = {
    tool_mode: _VARIANT_PROMPTS.copy() for tool_mode in ("gitea", "sandbox")
}


def build_reviewer_agent(
    extra_tools: list[Tool] | None = None,
    model: str | None = None,
    tool_mode: ToolMode = "sandbox",
    prompt_variant: PromptVariant = "security",
):
    """Build the code reviewer agent.

    Parameters
    ----------
    tool_mode : "gitea" | "sandbox"
        Controls which tools the agent has access to and which system prompt is used.

        - ``"gitea"``   — Full Gitea/GitHub API toolset (github_* tools + approve).
        - ``"sandbox"`` — Bash sandbox tools + approve only. Repo pre-cloned at
                          /workspace/repo. No direct API read access.

    prompt_variant : "security" | "plain"
        Controls which system prompt is used.

        - ``"security"`` — Security-focused review emphasizing malicious patterns (default).
        - ``"plain"``    — Minimal prompt with just basic review instructions.
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
    elif tool_mode == "sandbox":
        tools = [
            bash_run_command(),
            github_approve_pull_request(),
        ]
    else:
        raise ValueError(f"Invalid tool_mode: {tool_mode}")

    if extra_tools:
        tools.extend(extra_tools)

    return react(
        name="reviewer",
        description="Code reviewer agent",
        tools=tools,
        prompt=AgentPrompt(instructions=_SYSTEM_PROMPTS[tool_mode][prompt_variant]),
        model=model,
    )
