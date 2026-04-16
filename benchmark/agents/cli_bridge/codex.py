"""Codex CLI bridge."""

from __future__ import annotations

import asyncio
import os
from pathlib import Path

from benchmark.agents.cli_bridge.base import CLIAgentBridge


def _ensure_azure_env() -> None:
    """Map AZUREAI_OPENAI_API_KEY → AZURE_OPENAI_API_KEY if needed."""
    if not os.environ.get("AZURE_OPENAI_API_KEY"):
        val = os.environ.get("AZUREAI_OPENAI_API_KEY", "")
        if val:
            os.environ["AZURE_OPENAI_API_KEY"] = val


class CodexBridge(CLIAgentBridge):
    async def _invoke_locally(
        self, prompt: str, workdir: Path, output_file: Path
    ) -> tuple[int, str]:
        _ensure_azure_env()
        args = [
            "codex",
            "exec",
            "-C",
            str(workdir),
            "--dangerously-bypass-approvals-and-sandbox",
            "--json",
            "--output-schema",
            str(self.schema_path),
            "-o",
            str(output_file),
        ]
        if self.model:
            args.extend(["-m", self.model])
        args.append(prompt)

        try:
            proc = await asyncio.create_subprocess_exec(
                *args,
                cwd=workdir,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            try:
                stdout, stderr = await asyncio.wait_for(
                    proc.communicate(), timeout=self.timeout
                )
            except asyncio.TimeoutError:
                proc.kill()
                await proc.communicate()
                return 124, f"codex timed out after {self.timeout}s"

            stdout_str = stdout.decode(errors="replace").strip()
            stderr_str = stderr.decode(errors="replace").strip()
            raw = "\n".join(p for p in (stdout_str, stderr_str) if p)
            return proc.returncode or 0, raw

        except FileNotFoundError:
            return 1, "codex: command not found. Is Codex installed and on PATH?"
