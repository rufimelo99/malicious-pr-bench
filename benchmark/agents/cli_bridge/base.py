"""Base classes for running local CLI coding agents as PR reviewers."""

from __future__ import annotations

import json
import logging
import os
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from inspect_ai.util._sandbox.environment import SandboxEnvironment

from benchmark.config import SANDBOX_OUTPUT_FILE, SANDBOX_REPO_PATH

logger = logging.getLogger(__name__)

# Load the shared system prompt from the reviewer agent
_PROMPTS_DIR = Path(__file__).resolve().parents[2] / "agents" / "reviewer" / "prompts"
_SANDBOX_SYSTEM_PROMPT = (
    _PROMPTS_DIR / "reviewer_system_prompt_sandbox.txt"
).read_text()

_TIMEOUT_EXIT_CODE = 124


@dataclass
class CLIReviewResult:
    decision: str
    reason: str
    security_concerns: list[str]
    run_status: str
    raw_output: str
    duration_seconds: float


class CLIAgentBridge(ABC):
    """Abstract base for CLI agent bridges.

    CLI bridges always run inside an inspect_ai sandbox container.
    The repo is pre-cloned at ``SANDBOX_REPO_PATH`` by the solver before
    ``run_review`` is called.
    """

    def __init__(
        self, timeout: int = 600, model: str | None = None, github_token: str = ""
    ):
        self.timeout = timeout
        self.model = model
        self.github_token = github_token
        self.schema_path = Path(__file__).with_name("review_schema.json").resolve()
        self.schema_text = self.schema_path.read_text(encoding="utf-8")
        self._load_dotenv()

    @staticmethod
    def _load_dotenv() -> None:
        """Source .env from the project root if present."""
        env_file = Path(__file__).resolve().parents[2] / ".env"
        if not env_file.exists():
            return
        for line in env_file.read_text().splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if line.startswith("export "):
                line = line[len("export ") :]
            key, _, val = line.partition("=")
            if key and val:
                os.environ.setdefault(key.strip(), val.strip().strip('"').strip("'"))

    @abstractmethod
    async def _invoke_in_sandbox(
        self,
        prompt: str,
        workdir: str,
        output_file: str,
        sb: "SandboxEnvironment",
    ) -> tuple[int, str]:
        """Invoke the agent inside *sb*. Return (exit_code, raw_output)."""

    async def run_review(
        self,
        repo_slug: str,
        pr_number: int,
        pr_title: str,
        pr_body: str,
        base_sha: str,
        head_sha: str,
        sandbox: "SandboxEnvironment",
    ) -> CLIReviewResult:
        """Run a security review inside the sandbox container.

        The repo must already be cloned at ``SANDBOX_REPO_PATH`` before
        this method is called (the solver is responsible for that).
        """
        start_time = time.perf_counter()
        raw_output = ""

        prompt = self._build_prompt(
            repo_slug=repo_slug,
            pr_number=pr_number,
            pr_title=pr_title,
            pr_body=pr_body,
            base_sha=base_sha,
            head_sha=head_sha,
        )

        try:
            exit_code, raw_output = await self._invoke_in_sandbox(
                prompt=prompt,
                workdir=SANDBOX_REPO_PATH,
                output_file=SANDBOX_OUTPUT_FILE,
                sb=sandbox,
            )
            duration = time.perf_counter() - start_time

            if exit_code == _TIMEOUT_EXIT_CODE:
                return self._error_result(
                    reason=f"CLI agent timed out after {self.timeout} seconds.",
                    raw_output=raw_output,
                    duration_seconds=duration,
                    run_status="timeout",
                )

            if exit_code != 0:
                return self._error_result(
                    reason=f"CLI agent exited with status {exit_code}.",
                    raw_output=raw_output,
                    duration_seconds=duration,
                )

            try:
                review_text = await sandbox.read_file(SANDBOX_OUTPUT_FILE, text=True)
            except Exception as exc:
                return self._error_result(
                    reason=f"Could not read review output from sandbox: {exc}",
                    raw_output=raw_output,
                    duration_seconds=time.perf_counter() - start_time,
                )

            parsed = self._parse_review_text(review_text)
            if parsed is None:
                return self._error_result(
                    reason="Failed to parse structured review output as JSON.",
                    raw_output=raw_output,
                    duration_seconds=time.perf_counter() - start_time,
                )

            return CLIReviewResult(
                decision=parsed["decision"],
                reason=parsed["reason"],
                security_concerns=parsed["security_concerns"],
                run_status="success",
                raw_output=raw_output,
                duration_seconds=time.perf_counter() - start_time,
            )

        except Exception as exc:
            logger.exception("CLI review failed for %s PR #%s", repo_slug, pr_number)
            duration = time.perf_counter() - start_time
            raw_output = "\n".join(
                part for part in (raw_output, str(exc)) if part
            ).strip()
            return self._error_result(
                reason=f"Unexpected bridge error: {exc}",
                raw_output=raw_output,
                duration_seconds=duration,
            )

    def _build_prompt(
        self,
        repo_slug: str,
        pr_number: int,
        pr_title: str,
        pr_body: str,
        base_sha: str,
        head_sha: str,
    ) -> str:
        body = pr_body.strip() if pr_body else "(empty)"
        title = pr_title.strip() if pr_title else "(untitled)"
        pr_context = (
            f"\n\nRepository: {repo_slug}\n"
            f"Pull request: #{pr_number}\n"
            f"Title: {title}\n"
            f"Body:\n{body}\n\n"
            f"Base SHA: {base_sha}\n"
            f"Head SHA: {head_sha}"
        )
        return (
            _SANDBOX_SYSTEM_PROMPT
            + pr_context
            + "\n\nAt the end, output a single JSON object matching this schema:\n"
            f"{self.schema_text}\n\n"
            "Return only JSON with keys `decision`, `reason`, and optional `security_concerns`. "
            'Set `decision` to `"approve"` or `"decline"`.'
        )

    def _parse_review_text(self, text: str) -> dict[str, str | list[str]] | None:
        try:
            payload = json.loads(text)
        except json.JSONDecodeError:
            return None
        return self._validate_parsed(payload)

    def _validate_parsed(self, payload: object) -> dict[str, str | list[str]] | None:
        if not isinstance(payload, dict):
            return None
        decision = payload.get("decision")
        reason = payload.get("reason")
        security_concerns = payload.get("security_concerns", [])
        if decision not in {"approve", "decline"} or not isinstance(reason, str):
            return None
        if not isinstance(security_concerns, list) or not all(
            isinstance(item, str) for item in security_concerns
        ):
            return None
        return {
            "decision": decision,
            "reason": reason,
            "security_concerns": security_concerns,
        }

    def _error_result(
        self,
        reason: str,
        raw_output: str,
        duration_seconds: float,
        run_status: str = "error",
    ) -> CLIReviewResult:
        return CLIReviewResult(
            decision="error",
            reason=reason,
            security_concerns=[],
            run_status=run_status,
            raw_output=raw_output,
            duration_seconds=duration_seconds,
        )

    def _timeout_error(self, agent_name: str) -> tuple[int, str]:
        """Return standard timeout error (exit code 124)."""
        return _TIMEOUT_EXIT_CODE, f"{agent_name} timed out after {self.timeout}s"
