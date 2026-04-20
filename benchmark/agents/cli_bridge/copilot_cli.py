"""Copilot CLI bridge — runs copilot inside the sandbox container."""

from __future__ import annotations

import json
import os
import re
from typing import TYPE_CHECKING

from benchmark.agents.cli_bridge.base import CLIAgentBridge
from benchmark.config import FORWARDED_ENV_VARS

if TYPE_CHECKING:
    from inspect_ai.util._sandbox.environment import SandboxEnvironment


def _extract_json_from_text(text: str) -> str | None:
    """Extract a JSON object from text that may contain markdown fences or prose.

    Looks for JSON with a "decision" key (matching the review schema).
    """
    text = text.strip()
    try:
        obj = json.loads(text)
        if isinstance(obj, dict) and "decision" in obj:
            return json.dumps(obj)
    except json.JSONDecodeError:
        pass

    # Try markdown fence
    fenced = re.search(r"```(?:json)?\s*\n?(.*?)\n?```", text, re.DOTALL)
    if fenced:
        try:
            obj = json.loads(fenced.group(1).strip())
            if isinstance(obj, dict) and "decision" in obj:
                return json.dumps(obj)
        except json.JSONDecodeError:
            pass

    # Try JSON object with "decision" key
    brace_match = re.search(r"\{[^{}]*\"decision\"[^{}]*\}", text, re.DOTALL)
    if brace_match:
        try:
            obj = json.loads(brace_match.group(0))
            if isinstance(obj, dict):
                return json.dumps(obj)
        except json.JSONDecodeError:
            pass

    return None


class CopilotCLIBridge(CLIAgentBridge):
    """Bridge that runs the copilot CLI binary inside the sandbox container.

    The copilot process runs fully inside the sandbox, communicating with
    GitHub Copilot's service directly. Bash commands and file operations
    happen inside the sandbox via copilot's built-in tools.

    Requires: copilot binary in container PATH (install via: pip install github-copilot-sdk)
    """

    async def _invoke_in_sandbox(
        self, prompt: str, workdir: str, output_file: str, sb: "SandboxEnvironment"
    ) -> tuple[int, str]:
        # Forward host environment variables
        env = {k: v for k in FORWARDED_ENV_VARS if (v := os.environ.get(k))}

        # Use COPILOT_GITHUB_TOKEN (not GITHUB_TOKEN) to avoid conflict with Gitea token
        if self.github_token:
            env["COPILOT_GITHUB_TOKEN"] = self.github_token

        # Isolate copilot state and config per container
        env["COPILOT_HOME"] = "/tmp/.copilot"
        # Auto-approve all tools (equivalent to --yolo / --allow-all)
        env["COPILOT_ALLOW_ALL"] = "true"

        args = [
            "copilot",
            "-p",
            prompt,
            "--add-dir",
            workdir,
            "--allow-all",
        ]
        if self.model:
            args.extend(["--model", self.model])

        try:
            res = await sb.exec(cmd=args, cwd=workdir, timeout=self.timeout, env=env)
            raw = "\n".join(p for p in (res.stdout, res.stderr) if p).strip()
            if res.returncode == 0:
                payload = self._extract_from_jsonl(res.stdout)
                await sb.write_file(output_file, payload or res.stdout)
            return res.returncode, raw
        except TimeoutError:
            return 124, f"copilot timed out after {self.timeout}s"

    @staticmethod
    def _extract_from_jsonl(text: str) -> str | None:
        """Extract JSON decision from copilot output.

        Copilot outputs plain text with JSON at the end. Scans for JSON
        objects with a "decision" key, trying multiple extraction methods.
        """
        # Method 1: Look for JSON objects directly in the output
        extracted = _extract_json_from_text(text)
        if extracted:
            return extracted

        # Method 2: Scan lines in reverse (JSON often at end)
        for line in reversed(text.splitlines()):
            line = line.strip()
            if not line or not line.startswith("{"):
                continue
            try:
                obj = json.loads(line)
                if isinstance(obj, dict) and "decision" in obj:
                    return json.dumps(obj)
            except json.JSONDecodeError:
                continue

        # Method 3: Try to parse as JSONL (one JSON per line)
        for line in reversed(text.splitlines()):
            line = line.strip()
            if not line:
                continue
            try:
                event = json.loads(line)
                if not isinstance(event, dict):
                    continue

                # Extract content from various JSONL event formats
                content = event.get("content") or event.get("text") or ""
                if not isinstance(content, str) or not content:
                    continue

                # Try to extract JSON object from the content
                extracted = _extract_json_from_text(content)
                if extracted:
                    return extracted
            except json.JSONDecodeError:
                continue

        return None
