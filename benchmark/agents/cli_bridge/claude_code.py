"""Claude Code CLI bridge."""

from __future__ import annotations

import json
import shutil
from pathlib import Path

from benchmark.agents.cli_bridge.base import CLIAgentBridge


def _find_claude() -> str:
    return shutil.which("claude") or "claude"


class ClaudeCodeBridge(CLIAgentBridge):
    async def _invoke(
        self, prompt: str, workdir: Path, output_file: Path
    ) -> tuple[int, str]:
        schema = json.loads(self.schema_text)
        args = [
            _find_claude(),
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

        exit_code, stdout, stderr = await self._run_command_split(args, cwd=workdir)
        raw_output = "\n".join(part for part in (stdout, stderr) if part).strip()
        if exit_code == 0:
            # Claude --output-format json wraps the result; extract the
            # structured content from the last assistant message.
            try:
                envelope = json.loads(stdout)
                # The envelope is a single JSON object with a "result" key
                # or the schema output directly depending on version.
                if isinstance(envelope, dict) and "result" in envelope:
                    output_file.write_text(
                        json.dumps(envelope["result"]), encoding="utf-8"
                    )
                else:
                    output_file.write_text(stdout, encoding="utf-8")
            except json.JSONDecodeError:
                output_file.write_text(stdout, encoding="utf-8")
        return exit_code, raw_output
