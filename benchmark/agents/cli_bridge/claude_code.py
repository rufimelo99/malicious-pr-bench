"""Claude Code CLI bridge."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

from benchmark.agents.cli_bridge.base import CLIAgentBridge

if TYPE_CHECKING:
    from inspect_ai.util._sandbox.environment import SandboxEnvironment


class ClaudeCodeBridge(CLIAgentBridge):
    async def _invoke_in_sandbox(
        self, prompt: str, workdir: str, output_file: str, sb: "SandboxEnvironment"
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
            workdir,
            "--json-schema",
            json.dumps(schema),
        ]
        if self.model:
            args.extend(["--model", self.model])

        try:
            res = await sb.exec(cmd=args, cwd=workdir, timeout=self.timeout)
            raw = "\n".join(p for p in (res.stdout, res.stderr) if p).strip()
            if res.returncode == 0:
                try:
                    envelope = json.loads(res.stdout)
                    if isinstance(envelope, dict):
                        if "structured_output" in envelope:
                            payload = json.dumps(envelope["structured_output"])
                        elif "result" in envelope:
                            payload = json.dumps(envelope["result"])
                        else:
                            payload = res.stdout
                    else:
                        payload = res.stdout
                except json.JSONDecodeError:
                    payload = res.stdout
                await sb.write_file(output_file, payload)
            return res.returncode, raw
        except TimeoutError:
            return 124, f"claude timed out after {self.timeout}s"
