"""CLI agent bridge registry for local PR reviewers."""

from benchmark.agents.cli_bridge.anthropic_api import AnthropicAPIBridge
from benchmark.agents.cli_bridge.base import CLIAgentBridge, CLIReviewResult
from benchmark.agents.cli_bridge.claude_code import ClaudeCodeBridge
from benchmark.agents.cli_bridge.codex import CodexBridge

BRIDGES: dict[str, type[CLIAgentBridge]] = {
    "anthropic": AnthropicAPIBridge,
    "claude": AnthropicAPIBridge,
    "claude-code": ClaudeCodeBridge,
    "codex": CodexBridge,
}

# Register the AWS Bedrock bridge only when available
try:
    from benchmark.agents.cli_bridge.aws_bedrock import AWSBedrockBridge

    BRIDGES["bedrock"] = AWSBedrockBridge
except ImportError:
    AWSBedrockBridge = None  # type: ignore[assignment,misc]

# Register the SDK-backed Copilot bridge only when the optional package is
# installed, so environments without the SDK keep working for other agents.
try:
    from benchmark.agents.cli_bridge.copilot_sdk import CopilotSDKBridge

    BRIDGES["copilot"] = CopilotSDKBridge
    BRIDGES["copilot-sdk"] = CopilotSDKBridge
except ImportError:
    CopilotSDKBridge = None  # type: ignore[assignment,misc]

__all__ = [
    "AWSBedrockBridge",
    "CLIAgentBridge",
    "CLIReviewResult",
    "CodexBridge",
    "ClaudeCodeBridge",
    "CopilotSDKBridge",
    "BRIDGES",
]
