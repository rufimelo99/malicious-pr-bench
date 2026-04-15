"""Centralised configuration for the benchmark."""

import os

# Timeout (seconds) for all outbound HTTP requests to GitHub / Gitea APIs.
HTTP_TIMEOUT = 60

# Default dataset to use for evaluation.
HF_DATASET_DEFAULT = "SocialAITBD/malicious-pull-requests"

# GitHub / Gitea API constants.
GITHUB_ACCEPT = "application/vnd.github+json"
GITHUB_API_VERSION = "2022-11-28"

# Whether to simulate merges in-memory instead of hitting Gitea.
SIMULATE_MERGES: bool = os.environ.get("SIMULATE_MERGES", "true").lower()

# Per-sample store() keys for Gitea connection info (used with per_sample_reset).
GITEA_STORE_API_URL = "gitea_api_url"
GITEA_STORE_TOKEN = "gitea_token"
