"""Inspect solver that routes PR reviews through local CLI coding agents."""

from __future__ import annotations

import asyncio
import os

from inspect_ai.model import ChatMessageAssistant
from inspect_ai.solver import Solver, TaskState, solver
from inspect_ai.util import sandbox as _sandbox
from inspect_ai.util import store

from benchmark.agents.cli_bridge import BRIDGES, CLIReviewResult
from benchmark.config import GITEA_STORE_API_URL as _STORE_API_URL
from benchmark.config import GITEA_STORE_TOKEN as _STORE_TOKEN
from benchmark.config import HTTP_TIMEOUT
from benchmark.logger import logger
from benchmark.registry import SIMULATED_MERGES_REGISTRY
from benchmark.tools import _api_url, _headers
from benchmark.utils import store_pr_details


async def _fetch_pr_data(repo: str, pr_number: int) -> dict:
    def _request() -> dict:
        import requests

        r = requests.get(
            f"{_api_url()}/repos/{repo}/pulls/{pr_number}",
            headers=_headers(),
            timeout=HTTP_TIMEOUT,
        )
        r.raise_for_status()
        return r.json()

    return await asyncio.to_thread(_request)


@solver
def cli_solver(
    agent: str = "codex",
    model: str | None = None,
    timeout: int = 600,
    cwe: str | None = None,
    reset: bool = False,
    gitea_port: int = 3001,
    version: str = "v0.0.0",
) -> Solver:
    """Inspect solver that dispatches PR reviews to a local CLI coding agent.

    CLI agents always run inside the per-sample sandbox container.
    Each sample gets its own Gitea instance on an ephemeral port.
    """
    import asyncio as _asyncio

    if agent not in BRIDGES:
        raise ValueError(
            f"Unknown CLI agent '{agent}'. "
            f"Expected one of: {', '.join(sorted(BRIDGES))}."
        )

    os.environ["SIMULATE_MERGES"] = "1"
    # Capture the real GitHub token now, before Gitea reset can overwrite it.
    _github_token = os.environ.get("GITHUB_TOKEN", "")
    bridge = BRIDGES[agent](timeout=timeout, model=model, github_token=_github_token)
    _reset_task: _asyncio.Task | None = None

    async def solve(state: TaskState, generate) -> TaskState:
        nonlocal _reset_task

        # Reset Gitea once before the first sample; all samples share it.
        if cwe:
            from benchmark.task import _reset_gitea

            if _reset_task is None:
                _reset_task = _asyncio.create_task(
                    _asyncio.to_thread(_reset_gitea, cwe, gitea_port, version)
                )
            api_url, gitea_token = await _reset_task
            os.environ["GITHUB_API_URL"] = api_url
            os.environ["REVIEWER_TOKEN"] = gitea_token
            store().set(_STORE_API_URL, api_url)
            store().set(_STORE_TOKEN, gitea_token)

        repo = str(state.metadata.get("repo", ""))
        pr_numbers = (
            state.metadata.get("pr_numbers")
            or state.metadata.get("group_pr_numbers")
            or [state.metadata["pr_number"]]
        )

        # Clone the repo into the sandbox container then grab the sandbox handle.
        from benchmark.task import _clone_repo_to_sandbox

        await _clone_repo_to_sandbox(repo)
        sb = _sandbox()

        reviews: list[dict[str, object]] = []

        for pr_number in pr_numbers:
            try:
                pr_data = await _fetch_pr_data(repo, int(pr_number))
                pr_title = str(pr_data.get("title") or "")
                pr_body = str(pr_data.get("body") or "")
                result = await bridge.run_review(
                    repo_slug=repo,
                    pr_number=int(pr_number),
                    pr_title=pr_title,
                    pr_body=pr_body,
                    base_sha=str(pr_data["base"]["sha"]),
                    head_sha=str(pr_data["head"]["sha"]),
                    sandbox=sb,
                )
                store_pr_details(state.metadata, int(pr_number), pr_title, pr_body)
            except Exception as exc:
                logger.error("CLI review failed", repo=repo, pr_number=pr_number)
                result = CLIReviewResult(
                    decision="error",
                    reason=f"Failed to review PR #{pr_number}: {exc}",
                    security_concerns=[],
                    run_status="error",
                    raw_output=str(exc),
                    duration_seconds=0.0,
                )

            reviews.append(
                {
                    "pr_number": int(pr_number),
                    "decision": result.decision,
                    "run_status": result.run_status,
                    "reason": result.reason,
                    "security_concerns": result.security_concerns,
                    "raw_output": result.raw_output,
                    "duration_seconds": result.duration_seconds,
                }
            )

            if result.decision == "approve":
                SIMULATED_MERGES_REGISTRY.setdefault(repo, set()).add(int(pr_number))

        decisions = [str(r["decision"]) for r in reviews]
        state.metadata["cli_reviews"] = reviews
        state.metadata["cli_decision"] = (
            "approve"
            if all(d == "approve" for d in decisions)
            else "error" if any(d == "error" for d in decisions) else "decline"
        )
        state.metadata["cli_run_status"] = (
            "success"
            if all(str(r["run_status"]) == "success" for r in reviews)
            else (
                "timeout"
                if any(str(r["run_status"]) == "timeout" for r in reviews)
                else "error"
            )
        )
        state.metadata["cli_reason"] = "\n".join(
            str(r.get("reason", "")) for r in reviews
        )

        summary = "\n\n".join(
            f"PR #{r['pr_number']}\nDecision: {r['decision']}\n"
            f"Reason: {r['reason']}"
            for r in reviews
        )
        state.messages = [ChatMessageAssistant(content=summary)]
        return state

    return solve
