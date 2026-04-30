"""Gitea container management and sandbox helpers."""

from __future__ import annotations

import base64
import json
import os
import re
import socket
import subprocess
import time
import urllib.request
import uuid
from pathlib import Path

from benchmark.config import GITEA_STORE_API_URL as _STORE_API_URL
from benchmark.config import HTTP_TIMEOUT, SANDBOX_REPO_PATH
from benchmark.docker_cleanup import track_project
from benchmark.logger import logger

_COMPOSE_FILE = Path(__file__).parent.parent / "scripts" / "docker-compose.yml"


def _free_port() -> int:
    """Find an available port on localhost."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("", 0))
        s.listen(1)
        port = s.getsockname()[1]
    return port


def _compose_project_name(raw: str) -> str:
    """Return a Docker Compose-safe project name."""
    name = re.sub(r"[^a-z0-9_-]+", "-", raw.lower()).strip("-_")
    if not name or not re.match(r"^[a-z0-9]", name):
        name = f"benchmark-{name}"
    return name[:63].rstrip("-_")


def unique_gitea_project_name(*parts: object) -> str:
    """Build a unique Docker Compose project name for one benchmark run."""
    labels = [str(part) for part in parts if part not in (None, "")]
    suffix = f"{os.getpid()}-{int(time.time() * 1000)}-{uuid.uuid4().hex[:8]}"
    return _compose_project_name("-".join(["mprb", *labels, suffix]))


def reset_gitea(
    image: str,
    port: int = 0,
    project_name: str | None = None,
) -> tuple[str, str]:
    """Tear down and restart a Gitea container, return (api_url, token).

    Parameters
    ----------
    image:
        Full Docker image name, e.g. ``rufimelo/malicious-pr-cwe79:gpt5.2-filtered``.
    port:
        Host port Gitea will listen on. Pass ``0`` to allocate a free port.
    project_name:
        Optional compose project name; use a unique value per sample to allow
        parallel containers without collisions.
    """
    if port <= 0:
        port = _free_port()
    if project_name is None:
        project_name = "benchmark"
    project_name = _compose_project_name(project_name)

    logger.info("Resetting Gitea container", image=image, port=port)
    env = {
        **os.environ,
        "DOCKER_IMAGE": image,
        "GITEA_PORT": str(port),
        "GITEA_ROOT_URL": f"http://localhost:{port}/",
    }
    compose = [
        "docker",
        "compose",
        "-f",
        str(_COMPOSE_FILE),
        "--project-name",
        project_name,
    ]

    track_project(project_name, _COMPOSE_FILE)

    print(f"==> Resetting Gitea container ({image}) on port {port}...")
    subprocess.run(
        [*compose, "down", "--volumes", "--remove-orphans"], env=env, check=False
    )
    subprocess.run([*compose, "rm", "-fsv"], env=env, check=False)
    result = subprocess.run(
        [*compose, "up", "-d", "--force-recreate"],
        env=env,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        logger.error(
            "Docker compose up failed",
            returncode=result.returncode,
            stderr=result.stderr,
        )
        raise RuntimeError(
            f"Failed to start Gitea container on port {port}:\n{result.stderr}"
        )

    base_url = f"http://localhost:{port}"
    print(f"  Waiting for Gitea on port {port}...", end="", flush=True)
    for _ in range(60):
        try:
            urllib.request.urlopen(f"{base_url}/api/healthz", timeout=2)
            break
        except Exception:
            print(".", end="", flush=True)
            time.sleep(5)
    else:
        raise RuntimeError(
            f"Gitea on port {port} did not become healthy after 5 minutes."
        )
    print(" ready.")

    creds = base64.b64encode(b"gitadmin:adminpass123").decode()
    token_name = f"bench-{port}-{int(time.time())}"
    req = urllib.request.Request(
        f"{base_url}/api/v1/users/gitadmin/tokens",
        data=json.dumps(
            {
                "name": token_name,
                "scopes": ["write:repository", "read:user", "write:issue"],
            }
        ).encode(),
        headers={"Content-Type": "application/json", "Authorization": f"Basic {creds}"},
        method="POST",
    )
    with urllib.request.urlopen(req) as resp:
        token = json.loads(resp.read())["sha1"]

    api_url = f"{base_url}/api/v1"
    print(f"  Token set. GITHUB_API_URL={api_url}")
    return api_url, token


async def clone_repo_to_sandbox(
    repo: str,
    branch: str | None = None,
    gitea_port: int | None = None,
) -> None:
    """Clone *repo* from Gitea into ``SANDBOX_REPO_PATH`` inside the running sandbox.

    Must be called from inside a solve() coroutine so that the per-sample
    sandbox container is already up and the store has been populated by
    ``reset_gitea``.

    Parameters
    ----------
    repo:
        ``owner/name`` repository path on Gitea.
    branch:
        If given, clone only this branch (``--branch --single-branch``).
    gitea_port:
        Host port Gitea listens on; used to build the clone URL directly when
        the inspect-ai store is not populated (e.g. in the PoV harness).
    """
    from inspect_ai.util import sandbox as _sandbox
    from inspect_ai.util import store

    if gitea_port is not None:
        base_url = f"http://gitea:{gitea_port}"
    else:
        api_url = store().get(_STORE_API_URL) or os.environ.get(
            "GITHUB_API_URL", "http://localhost:3001/api/v1"
        )
        # Inside the sandbox container localhost refers to the container itself.
        # The compose file adds "gitea" as an extra_hosts entry pointing to the
        # Docker host gateway, so the host port is reachable via "gitea:<port>".
        base_url = api_url.replace("/api/v1", "").replace("//localhost:", "//gitea:")

    git_url = f"{base_url}/{repo}.git"

    sb = _sandbox()
    await sb.exec(cmd=["rm", "-rf", SANDBOX_REPO_PATH], timeout=10)

    clone_cmd = ["git", "clone"]
    if branch:
        clone_cmd += ["--branch", branch, "--single-branch"]
    clone_cmd += [git_url, SANDBOX_REPO_PATH]

    logger.info(f"[sandbox] Cloning {git_url} → {SANDBOX_REPO_PATH}")
    result = await sb.exec(cmd=clone_cmd, timeout=120)
    if result.returncode != 0:
        logger.error("[sandbox] git clone failed", stderr=result.stderr)
        raise RuntimeError(f"Failed to clone {repo} into sandbox: {result.stderr}")
    print(f"[sandbox] ✓ Cloned {repo} successfully")


async def fetch_pr_details(repo: str, pr_number: int) -> tuple[str, str]:
    """Return ``(title, body)`` for a PR from Gitea, or empty strings on failure."""
    import httpx

    base = os.environ.get("GITHUB_API_URL", "http://localhost:3001/api/v1")
    token = os.environ.get("REVIEWER_TOKEN") or os.environ.get("GITHUB_TOKEN", "")
    try:
        async with httpx.AsyncClient(timeout=HTTP_TIMEOUT) as client:
            r = await client.get(
                f"{base}/repos/{repo}/pulls/{pr_number}",
                headers={"Authorization": f"token {token}"},
            )
            if r.status_code == 200:
                data = r.json()
                return str(data.get("title") or ""), str(data.get("body") or "")
    except Exception:
        pass
    return "", ""


async def post_pr_comment(repo: str, pr_number: int, comment: str) -> None:
    """Post *comment* on a PR issue thread; silently ignores failures."""
    import asyncio
    import urllib.error

    api_base = os.environ.get("GITHUB_API_URL", "http://localhost:3001/api/v1")
    token = os.environ.get("REVIEWER_TOKEN") or os.environ.get("GITHUB_TOKEN", "")
    url = f"{api_base}/repos/{repo}/issues/{pr_number}/comments"
    req = urllib.request.Request(
        url,
        data=json.dumps({"body": comment}).encode(),
        headers={"Authorization": f"token {token}", "Content-Type": "application/json"},
        method="POST",
    )
    try:
        await asyncio.to_thread(urllib.request.urlopen, req)
    except Exception:
        pass
