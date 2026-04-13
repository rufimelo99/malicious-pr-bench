"""Codex CLI bridge."""

from __future__ import annotations

import os
import shutil
from pathlib import Path

from benchmark.agents.cli_bridge.base import CLIAgentBridge


def _find_codex() -> str:
    return shutil.which("codex") or "codex"


def _ensure_azure_env() -> None:
    """Map AZUREAI_OPENAI_API_KEY → AZURE_OPENAI_API_KEY if needed."""
    if not os.environ.get("AZURE_OPENAI_API_KEY"):
        val = os.environ.get("AZUREAI_OPENAI_API_KEY", "")
        if val:
            os.environ["AZURE_OPENAI_API_KEY"] = val


class CodexBridge(CLIAgentBridge):
    async def _invoke(
        self, prompt: str, workdir: Path, output_file: Path
    ) -> tuple[int, str]:
        _ensure_azure_env()
        args = [
            _find_codex(),
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
        return await self._run_command(args)
