#!/usr/bin/env python3
"""Helper script to retry failed evaluation tasks.

Usage:
    uv run python retry <log_file>

The script will:
1. Extract metadata from the .eval file (port, image, project name)
2. Start a Gitea container with those parameters
3. Run `inspect eval-retry` to restart failed tasks
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path


def extract_metadata(log_file: Path) -> dict[str, str | int]:
    """Extract metadata from a .eval log file.

    Parameters
    ----------
    log_file : Path
        Path to the .eval file (which is a ZIP archive).

    Returns
    -------
    dict[str, str | int]
        Dictionary with keys: port, cwe, version, project_name, tool_mode

    Raises
    ------
    FileNotFoundError
        If the log file does not exist.
    ValueError
        If the JSON is invalid or required fields are missing.
    """
    if not log_file.exists():
        raise FileNotFoundError(f"Log file not found: {log_file}")

    try:
        with zipfile.ZipFile(log_file, 'r') as zf:
            # Read the start journal which contains the parameters
            with zf.open("_journal/start.json") as f:
                start_data = json.load(f)
    except KeyError as e:
        raise ValueError(f"Missing _journal/start.json in eval file: {e}") from e
    except json.JSONDecodeError as e:
        raise ValueError(f"Invalid JSON in _journal/start.json: {e}") from e

    # Extract required parameters from the journal
    params = start_data.get("params", {})

    required_fields = ["cwe", "version", "gitea_port", "gitea_project_name"]
    for field in required_fields:
        if field not in params:
            raise ValueError(f"Missing required field in log file: {field}")

    return {
        "port": int(params["gitea_port"]),
        "cwe": params["cwe"],
        "version": params["version"],
        "project_name": params["gitea_project_name"],
        "tool_mode": params.get("tool_mode", "sandbox"),
    }


def build_image_name(cwe: str, version: str, tool_mode: str) -> str:
    """Build the Docker image name from CWE and version.

    Parameters
    ----------
    cwe : str
        The CWE identifier (e.g., "cwe79", "benign").
    version : str
        The dataset version (e.g., "gpt5.2-filtered", "gpt5.2_v2").
    tool_mode : str
        The tool mode used ("sandbox" or "gitea").

    Returns
    -------
    str
        The full Docker image name (e.g., "rufimelo/malicious-pr-cwe79:gpt5.2-filtered").
    """
    # Benign PRs use a different image template
    if cwe == "benign":
        return f"rufimelo/benign-pull-requests:{version}"

    # Malicious PRs use the CWE-specific template
    return f"rufimelo/malicious-pr-{cwe}:{version}"


def start_gitea(image: str, port: int, project_name: str) -> tuple[str, str]:
    """Start a Gitea container using the existing reset_gitea function.

    Parameters
    ----------
    image : str
        Full Docker image name (e.g., "rufimelo/malicious-pr-cwe79:gpt5.2-filtered").
    port : int
        Host port for Gitea to listen on.
    project_name : str
        Docker Compose project name for this container.

    Returns
    -------
    tuple[str, str]
        (api_url, token) for accessing the Gitea API.

    Raises
    ------
    RuntimeError
        If Docker container fails to start or Gitea is not healthy.
    """
    # Import here to avoid adding benchmark dependency at module level
    from benchmark.gitea import reset_gitea

    print(f"\n{'='*60}")
    print(f"Starting Gitea container for retry")
    print(f"  Image: {image}")
    print(f"  Port: {port}")
    print(f"  Project: {project_name}")
    print(f"{'='*60}\n")

    try:
        api_url, token = reset_gitea(image=image, port=port, project_name=project_name)
        print(f"\n{'='*60}")
        print(f"Gitea started successfully")
        print(f"  API URL: {api_url}")
        print(f"{'='*60}\n")
        return api_url, token
    except RuntimeError as e:
        print(f"\nError starting Gitea: {e}", file=sys.stderr)
        raise


def run_retry(log_file: Path) -> int:
    """Run inspect eval-retry to restart failed tasks.

    Parameters
    ----------
    log_file : Path
        Path to the .eval log file to retry.

    Returns
    -------
    int
        Exit code from inspect eval-retry (0 = success, non-zero = failure).
    """
    print(f"\n{'='*60}")
    print(f"Running inspect eval-retry")
    print(f"  Log file: {log_file}")
    print(f"{'='*60}\n")

    # Run inspect eval-retry with the log file
    cmd = ["uv", "run", "inspect", "eval-retry", str(log_file)]

    result = subprocess.run(cmd)

    if result.returncode != 0:
        print(f"\nwarning: inspect eval-retry exited with code {result.returncode}", file=sys.stderr)

    return result.returncode


def main() -> int:
    """Main entry point for the retry script."""
    parser = argparse.ArgumentParser(
        description="Retry failed evaluation tasks by restarting Gitea and running inspect eval-retry"
    )
    parser.add_argument(
        "log_file",
        type=Path,
        help="Path to the .eval log file to retry (e.g., 2026-04-30T04-50-13-00-00_reviewer-benchmark_dWbUX3enBBZ2tzrpz8mgHU.eval)"
    )

    args = parser.parse_args()

    if not args.log_file.exists():
        print(f"Error: Log file not found: {args.log_file}", file=sys.stderr)
        return 1

    if not args.log_file.suffix == ".eval":
        print(f"Error: File must be a .eval file: {args.log_file}", file=sys.stderr)
        return 1

    print(f"Processing eval log: {args.log_file}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
