"""Inspect solver that routes PR reviews through local CLI coding agents."""

from __future__ import annotations

import asyncio
import logging
import os

from inspect_ai.model import ChatMessageAssistant
from inspect_ai.solver import Solver, TaskState, solver

from benchmark.agents.cli_bridge import BRIDGES, CLIReviewResult
from benchmark.config import HTTP_TIMEOUT
from benchmark.registry import SIMULATED_MERGES_REGISTRY
from benchmark.tools import _api_url, _headers
from benchmark.utils import store_pr_details

logger = logging.getLogger(__name__)


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
    import asyncio as _asyncio

    if agent not in BRIDGES:
        raise ValueError(
            f"Unknown CLI agent '{agent}'. "
            f"Expected one of: {', '.join(sorted(BRIDGES))}."
        )

    os.environ["SIMULATE_MERGES"] = "1"
    bridge = BRIDGES[agent](timeout=timeout, model=model)
    _reset_task: _asyncio.Task | None = None

    async def solve(state: TaskState, generate) -> TaskState:
        nonlocal _reset_task

        if reset and cwe:
            if _reset_task is None:
                from benchmark.task import _reset_gitea

                _reset_task = _asyncio.create_task(
                    _asyncio.to_thread(_reset_gitea, cwe, gitea_port, version)
                )
            await _reset_task

        repo = str(state.metadata.get("repo", ""))
        pr_numbers = (
            state.metadata.get("pr_numbers")
            or state.metadata.get("group_pr_numbers")
            or [state.metadata["pr_number"]]
        )

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
                    clone_url=str(pr_data["head"]["repo"]["clone_url"]),
                )
                store_pr_details(state.metadata, int(pr_number), pr_title, pr_body)
            except Exception as exc:
                logger.exception("CLI review failed for %s PR #%s", repo, pr_number)
                result = CLIReviewResult(
                    decision="error",
                    reason=f"Failed to review PR #{pr_number}: {exc}",
                    security_concerns=[],
                    run_status="error",
                    raw_output=str(exc),
                    duration_seconds=0.0,
                )

            reviews.append({
                "pr_number": int(pr_number),
                "decision": result.decision,
                "run_status": result.run_status,
                "reason": result.reason,
                "security_concerns": result.security_concerns,
                "raw_output": result.raw_output,
                "duration_seconds": result.duration_seconds,
            })

            if result.decision == "approve":
                SIMULATED_MERGES_REGISTRY.setdefault(repo, set()).add(int(pr_number))

        # Store results for the viewer and scorer
        decisions = [str(r["decision"]) for r in reviews]
        state.metadata["cli_reviews"] = reviews
        state.metadata["cli_decision"] = (
            "approve" if all(d == "approve" for d in decisions)
            else "error" if any(d == "error" for d in decisions)
            else "decline"
        )
        state.metadata["cli_run_status"] = (
            "success" if all(str(r["run_status"]) == "success" for r in reviews)
            else "timeout" if any(str(r["run_status"]) == "timeout" for r in reviews)
            else "error"
        )
        state.metadata["cli_reason"] = "\n".join(
            str(r.get("reason", "")) for r in reviews
        )

        # Scorer reads the last assistant message
        summary = "\n\n".join(
            f"PR #{r['pr_number']}\nDecision: {r['decision']}\n"
            f"Reason: {r['reason']}" for r in reviews
        )
        state.messages = [ChatMessageAssistant(content=summary)]
        return state

    return solve
