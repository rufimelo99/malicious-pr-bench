"""Unit tests for local CLI bridge helpers."""

from __future__ import annotations

import json
from unittest.mock import AsyncMock, MagicMock


def test_copilot_cli_extracts_nested_jsonl_content():
    from benchmark.agents.cli_bridge.copilot_cli import CopilotCLIBridge

    review = {
        "decision": "decline",
        "reason": "unsafe",
        "security_concerns": ["xss"],
    }
    event = {"type": "assistant.message", "data": {"content": json.dumps(review)}}

    assert json.loads(CopilotCLIBridge._extract_from_jsonl(json.dumps(event))) == review


def test_cli_bridge_loads_repo_root_dotenv(monkeypatch, tmp_path):
    import benchmark.agents.cli_bridge.base as base

    env_file = tmp_path / ".env"
    env_file.write_text("ROOT_DOTENV_TEST=value\n")
    bridge_file = tmp_path / "benchmark" / "agents" / "cli_bridge" / "base.py"
    bridge_file.parent.mkdir(parents=True)
    bridge_file.write_text("")

    monkeypatch.delenv("ROOT_DOTENV_TEST", raising=False)
    monkeypatch.setattr(base, "__file__", str(bridge_file))

    base.CLIAgentBridge._load_dotenv()

    assert base.os.environ["ROOT_DOTENV_TEST"] == "value"


def test_cli_bridge_prompt_matches_cli_contract():
    from benchmark.agents.cli_bridge.base import CLIAgentBridge

    class DummyBridge(CLIAgentBridge):
        async def _invoke_in_sandbox(self, prompt, workdir, output_file, sb):
            return 0, ""

    prompt = CLIAgentBridge._build_prompt(
        DummyBridge(),
        repo_slug="owner/repo",
        pr_number=7,
        pr_title="Fix escaping",
        pr_body="body",
        base_sha="base123",
        head_sha="head456",
    )

    assert "git diff --stat <base_sha>..<head_sha>" in prompt
    assert "Base SHA: base123" in prompt
    assert "Head SHA: head456" in prompt
    assert "github_approve_pull_request" in prompt
    assert "not available here" in prompt
    assert "submit()" in prompt


def test_codex_bridge_forwards_openai_env(monkeypatch):
    from benchmark.agents.cli_bridge.codex import CodexBridge

    monkeypatch.setenv("OPENAI_API_KEY", "test-key")
    monkeypatch.delenv("AZURE_OPENAI_API_KEY", raising=False)
    monkeypatch.setenv("AZUREAI_OPENAI_API_KEY", "azure-key")

    sandbox = MagicMock()
    sandbox.exec = AsyncMock(
        return_value=MagicMock(returncode=0, stdout="{}", stderr="")
    )

    bridge = object.__new__(CodexBridge)
    bridge.timeout = 1
    bridge.model = None
    bridge.schema_path = "/tmp/schema.json"

    import asyncio

    asyncio.run(
        bridge._invoke_in_sandbox(
            prompt="review",
            workdir="/workspace/repo",
            output_file="/workspace/review.json",
            sb=sandbox,
        )
    )

    env = sandbox.exec.await_args.kwargs["env"]
    assert env["OPENAI_API_KEY"] == "test-key"
    assert env["AZURE_OPENAI_API_KEY"] == "azure-key"
