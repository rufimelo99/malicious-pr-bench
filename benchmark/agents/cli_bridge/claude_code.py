"""Claude Code CLI bridge."""

from __future__ import annotations

import json
import os
from typing import TYPE_CHECKING

from benchmark.agents.cli_bridge.base import CLIAgentBridge
from benchmark.config import FORWARDED_ENV_VARS

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
            "stream-json",
            "--verbose",
            "--dangerously-skip-permissions",
            "--add-dir",
            workdir,
            "--json-schema",
            json.dumps(schema),
        ]
        if self.model:
            args.extend(["--model", self.model])

        env = {k: v for k in FORWARDED_ENV_VARS if (v := os.environ.get(k))}

        try:
            res = await sb.exec(cmd=args, cwd=workdir, timeout=self.timeout, env=env)
            raw = "\n".join(p for p in (res.stdout, res.stderr) if p).strip()
            if res.returncode == 0:
                payload = self._extract_structured_output(res.stdout)
                await sb.write_file(output_file, payload)
            return res.returncode, raw
        except TimeoutError:
            return 124, f"claude timed out after {self.timeout}s"

    @staticmethod
    def _extract_structured_output(stream_json: str) -> str:
        """Extract structured_output (or result) from the final result event in stream-json output."""
        result_event = None
        for line in stream_json.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                event = json.loads(line)
                if isinstance(event, dict) and event.get("type") == "result":
                    result_event = event
            except json.JSONDecodeError:
                continue
        if result_event is None:
            return stream_json
        structured = result_event.get("structured_output")
        if structured is not None:
            return json.dumps(structured)
        result = result_event.get("result")
        if isinstance(result, dict):
            return json.dumps(result)
        if isinstance(result, str) and result.strip().startswith("{"):
            return result
        return stream_json
