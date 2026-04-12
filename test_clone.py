#!/usr/bin/env python3
"""Standalone test to verify Docker container repo cloning.

This test creates a sandbox Docker container with the Dockerfile.sandbox,
passes GITEA_REPO and GITEA_URL environment variables, and checks if the
repo gets cloned to /workspace/repo.

Usage:
    python test_clone.py <repo> [<gitea_base_url>]

Example:
    python test_clone.py owner/repo http://localhost:3001
"""

import asyncio
import sys
from pathlib import Path

from inspect_ai.util import sandbox
from inspect_ai.util._sandbox.environment import SandboxEnvironmentSpec


async def test_clone(repo: str, gitea_base_url: str = "http://localhost:3001"):
    """Test repo cloning in a sandbox container."""

    sandbox_dockerfile = Path(__file__).parent / "scripts" / "Dockerfile.sandbox"

    print(f"\n{'='*70}")
    print(f"Testing repo cloning in Docker sandbox")
    print(f"{'='*70}")
    print(f"Repository: {repo}")
    print(f"Gitea URL: {gitea_base_url}")
    print(f"Dockerfile: {sandbox_dockerfile}")
    print()

    # Create sandbox with Dockerfile
    spec = SandboxEnvironmentSpec(
        type="docker",
        image=str(sandbox_dockerfile),
    )

    # Set up environment variables for the entrypoint script
    env_vars = {
        "GITEA_REPO": repo,
        "GITEA_URL": gitea_base_url,
    }

    print(f"Environment variables: {env_vars}")
    print()

    try:
        # Create and enter sandbox
        print("[TEST] Creating sandbox container...")
        sb = sandbox(
            environment=spec,
            docker_build_context=Path(__file__).parent,
        )

        print("[TEST] Waiting a moment for container startup and cloning...")
        await asyncio.sleep(3)  # Give entrypoint script time to run

        # Check if repo was cloned
        print("[TEST] Checking if /workspace/repo exists...")
        result = await sb.exec(cmd=["ls", "-la", "/workspace"], timeout=10)
        print(f"[TEST] /workspace contents:\n{result.stdout}")
        if result.stderr:
            print(f"[TEST] Error: {result.stderr}")

        # Check /workspace/repo specifically
        print("\n[TEST] Checking /workspace/repo...")
        result = await sb.exec(cmd=["test", "-d", "/workspace/repo"], timeout=10)
        if result.returncode == 0:
            print("[TEST] ✓ /workspace/repo directory exists!")

            # List contents
            result = await sb.exec(cmd=["ls", "-la", "/workspace/repo"], timeout=10)
            print(f"[TEST] Repo contents:\n{result.stdout}")
        else:
            print("[TEST] ✗ /workspace/repo directory does NOT exist")

        # Try to manually clone from inside container (debug)
        print("\n[TEST] Testing git clone from inside container...")
        git_url = f"{gitea_base_url}/{repo}.git"
        print(f"[TEST] Git URL: {git_url}")
        result = await sb.exec(
            cmd=["git", "clone", git_url, "/tmp/test-clone"],
            timeout=30,
        )
        print(f"[TEST] Git clone result (return code {result.returncode}):")
        print(f"[TEST] stdout: {result.stdout}")
        if result.stderr:
            print(f"[TEST] stderr: {result.stderr}")

        # Check if it worked
        if result.returncode == 0:
            print("[TEST] ✓ Manual git clone succeeded!")
            result = await sb.exec(cmd=["ls", "-la", "/tmp/test-clone"], timeout=10)
            print(f"[TEST] Cloned repo contents:\n{result.stdout}")
        else:
            print(
                f"[TEST] ✗ Manual git clone failed with exit code {result.returncode}"
            )

    except Exception as e:
        print(f"[ERROR] {type(e).__name__}: {e}")
        import traceback

        traceback.print_exc()

    print(f"\n{'='*70}")
    print("Test complete")
    print(f"{'='*70}\n")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <repo> [<gitea_base_url>]")
        print(f"Example: {sys.argv[0]} owner/repo http://localhost:3001")
        sys.exit(1)

    repo = sys.argv[1]
    gitea_url = sys.argv[2] if len(sys.argv) > 2 else "http://localhost:3001"

    asyncio.run(test_clone(repo, gitea_url))
