"""Unit tests for benchmark/agents/reviewer/reviewer_agent.py."""

from __future__ import annotations

import pytest


class TestBuildReviewerAgent:
    def test_gitea_mode_builds_without_error(self):
        from benchmark.agents.reviewer.reviewer_agent import build_reviewer_agent

        agent = build_reviewer_agent(tool_mode="gitea")
        assert agent is not None

    def test_sandbox_mode_builds_without_error(self):
        from benchmark.agents.reviewer.reviewer_agent import build_reviewer_agent

        agent = build_reviewer_agent(tool_mode="sandbox")
        assert agent is not None

    def test_invalid_tool_mode_raises(self):
        from benchmark.agents.reviewer.reviewer_agent import build_reviewer_agent

        with pytest.raises(ValueError, match="Invalid tool_mode"):
            build_reviewer_agent(tool_mode="unknown")

    def test_gitea_mode_uses_gitea_prompt(self):
        from benchmark.agents.reviewer.reviewer_agent import _SYSTEM_PROMPTS

        assert "gitea" in _SYSTEM_PROMPTS
        assert len(_SYSTEM_PROMPTS["gitea"]) > 0

    def test_sandbox_mode_uses_sandbox_prompt(self):
        from benchmark.agents.reviewer.reviewer_agent import _SYSTEM_PROMPTS

        assert "sandbox" in _SYSTEM_PROMPTS
        assert len(_SYSTEM_PROMPTS["sandbox"]) > 0

    def test_system_prompts_are_different(self):
        from benchmark.agents.reviewer.reviewer_agent import _SYSTEM_PROMPTS

        assert _SYSTEM_PROMPTS["gitea"] != _SYSTEM_PROMPTS["sandbox"]

    def test_extra_tools_are_accepted(self):
        from unittest.mock import MagicMock

        from benchmark.agents.reviewer.reviewer_agent import build_reviewer_agent

        extra = MagicMock()
        # Should not raise
        agent = build_reviewer_agent(tool_mode="sandbox", extra_tools=[extra])
        assert agent is not None

    def test_model_parameter_accepted(self):
        from benchmark.agents.reviewer.reviewer_agent import build_reviewer_agent

        agent = build_reviewer_agent(tool_mode="sandbox", model="openai/gpt-4o")
        assert agent is not None
