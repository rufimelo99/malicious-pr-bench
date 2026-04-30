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

# Prompts by variant (loaded from config for "reviewer" agent type)
_VARIANT_PROMPTS = {
    variant.value: load_prompt(filename)
    for variant, filename in PROMPT_FILES["reviewer"].items()
}

# Prompts by tool mode and variant
_SYSTEM_PROMPTS: dict[str, dict[str, str]] = {
    tool_mode.value: _VARIANT_PROMPTS.copy() for tool_mode in ToolMode
}


def build_reviewer_agent(
    extra_tools: list[Tool] | None = None,
    model: str | None = None,
    tool_mode: ToolMode | str = ToolMode.SANDBOX,
    prompt_variant: PromptVariant | str = PromptVariant.SECURITY,
):
    """Build the code reviewer agent.

    Parameters
    ----------
    tool_mode : ToolMode | str
        Controls which tools the agent has access to and which system prompt is used.

        - ``"gitea"`` or ``ToolMode.GITEA`` — Full Gitea/GitHub API toolset.
        - ``"sandbox"`` or ``ToolMode.SANDBOX`` — Gitea/GitHub API toolset plus
          bash inspection inside the sandbox.

    prompt_variant : PromptVariant | str
        Controls which system prompt is used.

        - ``"security"`` or ``PromptVariant.SECURITY`` — Security-focused (default).
        - ``"plain"`` or ``PromptVariant.PLAIN`` — Minimal instructions.
    """
    # Convert string inputs to enums if needed
    if isinstance(tool_mode, str):
        try:
            tool_mode = ToolMode(tool_mode)
        except ValueError:
            raise ValueError(f"Invalid tool_mode: {tool_mode}")
    if isinstance(prompt_variant, str):
        try:
            prompt_variant = PromptVariant(prompt_variant)
        except ValueError:
            raise ValueError(f"Invalid prompt_variant: {prompt_variant}")

    if tool_mode.value == "gitea":
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
    elif tool_mode.value == "sandbox":
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
        prompt=AgentPrompt(
            instructions=_SYSTEM_PROMPTS[tool_mode.value][prompt_variant.value]
        ),
        model=model,
    )
