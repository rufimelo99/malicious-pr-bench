"""Codex CLI bridge."""

from __future__ import annotations

import os
from typing import TYPE_CHECKING

from benchmark.agents.cli_bridge.base import CLIAgentBridge

if TYPE_CHECKING:
    from inspect_ai.util._sandbox.environment import SandboxEnvironment


def _ensure_azure_env() -> None:
    """Map AZUREAI_OPENAI_API_KEY → AZURE_OPENAI_API_KEY if needed."""
    if not os.environ.get("AZURE_OPENAI_API_KEY"):
        val = os.environ.get("AZUREAI_OPENAI_API_KEY", "")
        if val:
            os.environ["AZURE_OPENAI_API_KEY"] = val


class CodexBridge(CLIAgentBridge):
    async def _invoke_in_sandbox(
        self, prompt: str, workdir: str, output_file: str, sb: "SandboxEnvironment"
    ) -> tuple[int, str]:
        _ensure_azure_env()
        args = [
            "codex",
            "exec",
            "-C",
            workdir,
            "--dangerously-bypass-approvals-and-sandbox",
            "--json",
            "--output-schema",
            str(self.schema_path),
            "-o",
            output_file,
        ]
        if self.model:
            args.extend(["-m", self.model])
        args.append(prompt)

        try:
            res = await sb.exec(cmd=args, cwd=workdir, timeout=self.timeout)
            raw = "\n".join(p for p in (res.stdout, res.stderr) if p).strip()
            return res.returncode, raw
        except TimeoutError:
            return self._timeout_error("codex")
