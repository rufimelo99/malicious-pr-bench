"""Centralised configuration for the benchmark."""

# Timeout (seconds) for all outbound HTTP requests to GitHub / Gitea APIs.
HTTP_TIMEOUT = 60

# Default dataset to use for evaluation.
HF_DATASET_DEFAULT = "SocialAITBD/malicious-pull-requests"