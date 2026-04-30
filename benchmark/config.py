"""Centralised configuration for the benchmark."""

import os
from enum import Enum
from pathlib import Path

# Timeout (seconds) for all outbound HTTP requests to GitHub / Gitea APIs.
HTTP_TIMEOUT = 60
CLI_TIMEOUT = 600

# Sentinel value telling reset_gitea() to allocate an available host port.
AUTO_GITEA_PORT = 0

# Default dataset to use for evaluation.
HF_DATASET_DEFAULT = "SocialAITBD/malicious-pull-requests"

# All CWE subsets available in the HF dataset.
SUPPORTED_CWES: frozenset[str] = frozenset(
    {
        "cwe22",
        "cwe78",
        "cwe79",
        "cwe89",
        "cwe94",
        "cwe125",
        "cwe352",
        "cwe416",
        "cwe787",
        "cwe862",
    }
)

# Dataset version identifiers — these are path segments inside the HF repo.
SUPPORTED_DATASET_VERSIONS: frozenset[str] = frozenset({"gpt5.2-filtered"})
DEFAULT_DATASET_VERSION: str = "gpt5.2-filtered"

SUPPORTED_BENIGN_DATASET_VERSIONS: frozenset[str] = frozenset({"gpt5.2_v2"})
DEFAULT_BENIGN_DATASET_VERSION: str = "gpt5.2_v2"


# Supported modes and variants
class ToolMode(str, Enum):
    """Tool mode for reviewer agent."""

    GITEA = "gitea"
    SANDBOX = "sandbox"


class PromptVariant(str, Enum):
    """Prompt variant for reviewer agent."""

    SECURITY = "security"
    PLAIN = "plain"


# Prompt file mappings for each variant and agent type
PROMPT_FILES: dict[str, dict[PromptVariant, str]] = {
    "reviewer": {
        PromptVariant.SECURITY: "reviewer_system_prompt_security",
        PromptVariant.PLAIN: "reviewer_system_prompt_plain",
    },
    "cli": {
        PromptVariant.SECURITY: "cli_reviewer_system_prompt_security",
        PromptVariant.PLAIN: "cli_reviewer_system_prompt_plain",
    },
}

# GitHub / Gitea API constants.
GITHUB_ACCEPT = "application/vnd.github+json"
GITHUB_API_VERSION = "2022-11-28"

def env_flag(name: str, default: bool = False) -> bool:
    """Parse a boolean environment flag."""
    value = os.environ.get(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def simulate_merges_enabled() -> bool:
    """Return whether approvals should be recorded in memory."""
    return env_flag("SIMULATE_MERGES", False)


# Backwards-compatible snapshot for callers that only need import-time defaults.
SIMULATE_MERGES: bool = simulate_merges_enabled()

# Docker image name templates for Gitea benchmark containers.
# Format: MALICIOUS_IMAGE_TEMPLATE.format(cwe="cwe79", version="gpt5.2-filtered")
MALICIOUS_IMAGE_TEMPLATE = "rufimelo/malicious-pr-{cwe}:{version}"
BENIGN_IMAGE_TEMPLATE = "rufimelo/benign-pull-requests:{version}"

# Per-sample store() keys for Gitea connection info.
# In sandbox mode each sample spins up its own Gitea instance on a unique port;
# these keys let the tools read the correct URL and token for their sample.
GITEA_STORE_API_URL = "gitea_api_url"
GITEA_STORE_TOKEN = "gitea_token"

# Fixed paths inside every sandbox container.
SANDBOX_REPO_PATH = "/workspace/repo"
SANDBOX_OUTPUT_FILE = "/workspace/review.json"
SANDBOX_EXPLOIT_FILE = "/workspace/exploit.py"
SANDBOX_REPORT_FILE = "/workspace/report.json"
SANDBOX_QUERY_FILE = "/workspace/query.sc"

# Environment variables forwarded from the host into sandbox containers.
FORWARDED_ENV_VARS = [
    "OPENAI_API_KEY",
    "OPENAI_BASE_URL",
    "OPENAI_ORG_ID",
    "OPENAI_ORGANIZATION",
    "OPENAI_PROJECT",
    "AZURE_OPENAI_API_KEY",
    "AZUREAI_OPENAI_API_KEY",
    "AZURE_OPENAI_ENDPOINT",
    "AZURE_OPENAI_API_VERSION",
    "CODEX_HOME",
    "ANTHROPIC_API_KEY",
    "CLAUDE_CODE_USE_BEDROCK",
    "AWS_REGION",
    "AWS_DEFAULT_REGION",
    "AWS_ACCESS_KEY_ID",
    "AWS_SECRET_ACCESS_KEY",
    "AWS_SESSION_TOKEN",
    "AWS_PROFILE",
    "AWS_BEARER_TOKEN_BEDROCK",
    "CLAUDE_CODE_OAUTH_TOKEN",
    "COPILOT_GITHUB_TOKEN",
]

SANDBOX_COMPOSE = Path(__file__).parent.parent / "scripts" / "sandbox-compose.yaml"
SANDBOX_COMPOSE_REVIEWER = (
    Path(__file__).parent.parent / "scripts" / "sandbox-compose-reviewer.yaml"
)
SANDBOX_COMPOSE_COPILOT = (
    Path(__file__).parent.parent / "scripts" / "sandbox-compose-copilot.yaml"
)
