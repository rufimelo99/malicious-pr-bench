"""Claude Code CLI bridge."""

from __future__ import annotations

import json
import os
from typing import TYPE_CHECKING

from benchmark.agents.cli_bridge.base import CLIAgentBridge

if TYPE_CHECKING:
    from inspect_ai.util._sandbox.environment import SandboxEnvironment

_FORWARDED_ENV_VARS = [
    # Anthropic direct
    "ANTHROPIC_API_KEY",
    # AWS Bedrock
    "CLAUDE_CODE_USE_BEDROCK",
    "AWS_REGION",
    "AWS_DEFAULT_REGION",
    "AWS_ACCESS_KEY_ID",
    "AWS_SECRET_ACCESS_KEY",
    "AWS_SESSION_TOKEN",
    "AWS_PROFILE",
    "AWS_BEARER_TOKEN_BEDROCK",
    # Claude Pro OAuth
    "CLAUDE_CODE_OAUTH_TOKEN",
]


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

        env = {k: v for k in _FORWARDED_ENV_VARS if (v := os.environ.get(k))}

        try:
            res = await sb.exec(cmd=args, cwd=workdir, timeout=self.timeout, env=env)
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
