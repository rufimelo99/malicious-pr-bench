"""Centralised configuration for the benchmark."""

import os

# Timeout (seconds) for all outbound HTTP requests to GitHub / Gitea APIs.
HTTP_TIMEOUT = 60

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
SUPPORTED_DATASET_VERSIONS: frozenset[str] = frozenset(
    {
        "gpt5.2",
        "gpt5.2-filtered",
    }
)
SUPPORTED_BENIGN_DATASET_VERSIONS: frozenset[str] = frozenset(
    {
        "gpt5.2",
        "gpt5.2_v2",
    }
)
# GitHub / Gitea API constants.
GITHUB_ACCEPT = "application/vnd.github+json"
GITHUB_API_VERSION = "2022-11-28"

# Whether to simulate merges in-memory instead of hitting Gitea.
SIMULATE_MERGES: bool = os.environ.get("SIMULATE_MERGES", "true").lower()

# Docker image name templates for Gitea benchmark containers.
# Format: MALICIOUS_IMAGE_TEMPLATE.format(cwe="cwe79", version="gpt5.2-filtered")
MALICIOUS_IMAGE_TEMPLATE = "rufimelo/malicious-pr-{cwe}:{version}"
BENIGN_IMAGE_TEMPLATE = "rufimelo/benign-pull-requests:{version}"

# Per-sample store() keys for Gitea connection info.
# In sandbox mode each sample spins up its own Gitea instance on a unique port;
# these keys let the tools read the correct URL and token for their sample.
GITEA_STORE_API_URL = "gitea_api_url"
GITEA_STORE_TOKEN = "gitea_token"

# Fixed repo path inside the API-agent sandbox container.
SANDBOX_REPO_PATH = "/workspace/repo"
