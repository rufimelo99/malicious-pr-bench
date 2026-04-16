"""Claude Code CLI bridge."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

from benchmark.agents.cli_bridge.base import CLIAgentBridge


class ClaudeCodeBridge(CLIAgentBridge):
    async def _invoke_locally(
        self, prompt: str, workdir: Path, output_file: Path
    ) -> tuple[int, str]:
        schema = json.loads(self.schema_text)
        args = [
            "claude",
            "-p",
            prompt,
            "--output-format",
            "json",
            "--dangerously-skip-permissions",
            "--add-dir",
            str(workdir),
            "--json-schema",
            json.dumps(schema),
        ]
        if self.model:
            args.extend(["--model", self.model])

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
                return 124, f"claude timed out after {self.timeout}s"

            stdout_str = stdout.decode(errors="replace").strip()
            stderr_str = stderr.decode(errors="replace").strip()
            raw = "\n".join(p for p in (stdout_str, stderr_str) if p)

            if proc.returncode == 0:
                try:
                    envelope = json.loads(stdout_str)
                    payload = (
                        json.dumps(envelope["result"])
                        if isinstance(envelope, dict) and "result" in envelope
                        else stdout_str
                    )
                except json.JSONDecodeError:
                    payload = stdout_str
                output_file.write_text(payload, encoding="utf-8")

            return proc.returncode or 0, raw

        except FileNotFoundError:
            return 1, "claude: command not found. Is Claude Code installed and on PATH?"
