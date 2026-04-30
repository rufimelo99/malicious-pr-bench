#!/usr/bin/env python3
"""Helper script to retry failed evaluation tasks.

This script takes an .eval log file from a failed `inspect eval` run and:
1. Extracts metadata (port, CWE, version, project name)
2. Starts a Gitea Docker container with those parameters
3. Runs `inspect eval-retry` to restart failed tasks

Usage
-----
    uv run python retry <log_file>

Example
-------
    # Retry a failed evaluation
    uv run python retry 2026-04-30T04-50-13-00-00_reviewer-benchmark_dWbUX3enBBZ2tzrpz8mgHU.eval

Requirements
------------
- The .eval file must be from a `malicious_pr_bench` benchmark run
- Docker and docker-compose must be installed and running
- The script uses the existing benchmark/gitea.py and benchmark/docker_cleanup.py utilities

Notes
-----
- The Gitea container will be started on the same port as the original run
- The container will be cleaned up on script exit via signal handlers
- For debugging, use `docker ps` to see running containers
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

    # Extract parameters - they may be nested under eval.task_args_passed or eval.task_args
    params = start_data.get("eval", {}).get("task_args_passed", {})
    if not params:
        params = start_data.get("eval", {}).get("task_args", {})

    # For project name, check the plan if not in task args
    if "gitea_project" not in params:
        plan_steps = start_data.get("plan", {}).get("steps", [])
        if plan_steps:
            params["gitea_project"] = plan_steps[0].get("params", {}).get("gitea_project")

    required_fields = ["cwe", "version", "gitea_port"]
    for field in required_fields:
        if field not in params:
            raise ValueError(f"Missing required field in log file: {field}")

    # Use gitea_project if available, otherwise use a default project name
    project_name = params.get("gitea_project")
    if not project_name:
        project_name = f"mprb-{params.get('cwe', 'unknown')}"

    return {
        "port": int(params["gitea_port"]),
        "cwe": params["cwe"],
        "version": params["version"],
        "project_name": project_name,
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


def validate_metadata(metadata: dict[str, str | int]) -> None:
    """Validate extracted metadata for required fields and reasonable values.

    Raises
    ------
    ValueError
        If any metadata field is invalid.
    """
    # Port should be reasonable
    port = metadata.get("port", 0)
    if not isinstance(port, int) or port < 1 or port > 65535:
        raise ValueError(f"Invalid port number: {port}")

    # CWE should not be empty
    cwe = metadata.get("cwe")
    if not cwe or not isinstance(cwe, str):
        raise ValueError(f"Invalid CWE: {cwe}")

    # Version should not be empty
    version = metadata.get("version")
    if not version or not isinstance(version, str):
        raise ValueError(f"Invalid version: {version}")

    # Project name should not be empty
    project_name = metadata.get("project_name")
    if not project_name or not isinstance(project_name, str):
        raise ValueError(f"Invalid project name: {project_name}")


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

    try:
        result = subprocess.run(cmd, check=False)
    except FileNotFoundError:
        print(f"\nError: Could not find 'uv' command. Make sure it's installed and in PATH.", file=sys.stderr)
        return 127

    if result.returncode != 0:
        print(f"\nWarning: inspect eval-retry exited with code {result.returncode}", file=sys.stderr)

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

    # Step 1: Extract metadata from the log file
    try:
        metadata = extract_metadata(args.log_file)
        validate_metadata(metadata)
        print(f"\nExtracted metadata:")
        print(f"  CWE: {metadata['cwe']}")
        print(f"  Version: {metadata['version']}")
        print(f"  Port: {metadata['port']}")
        print(f"  Project: {metadata['project_name']}")
        print(f"  Tool Mode: {metadata['tool_mode']}")
    except (FileNotFoundError, ValueError) as e:
        print(f"Error extracting metadata: {e}", file=sys.stderr)
        return 1

    # Step 2: Build the Docker image name
    image = build_image_name(
        cwe=metadata["cwe"],
        version=metadata["version"],
        tool_mode=metadata["tool_mode"]
    )

    # Step 3: Start Gitea
    try:
        api_url, token = start_gitea(
            image=image,
            port=metadata["port"],
            project_name=metadata["project_name"]
        )
    except RuntimeError as e:
        print(f"Failed to start Gitea: {e}", file=sys.stderr)
        return 1

    # Step 4: Run inspect eval-retry
    exit_code = run_retry(args.log_file)

    if exit_code == 0:
        print(f"\n{'='*60}")
        print(f"Retry completed successfully!")
        print(f"{'='*60}")
    else:
        print(f"\n{'='*60}")
        print(f"Retry completed with exit code {exit_code}")
        print(f"{'='*60}")

    return exit_code


if __name__ == "__main__":
    sys.exit(main())
