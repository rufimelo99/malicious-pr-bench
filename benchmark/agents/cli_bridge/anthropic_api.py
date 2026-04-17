"""Anthropic API bridge — direct Claude API calls without CLI dependency."""

from __future__ import annotations

import json
import logging
import re
from typing import TYPE_CHECKING

from benchmark.agents.cli_bridge.base import CLIAgentBridge

if TYPE_CHECKING:
    from inspect_ai.util._sandbox.environment import SandboxEnvironment

logger = logging.getLogger(__name__)

try:
    from anthropic import Anthropic
except ImportError:
    Anthropic = None  # type: ignore[assignment,misc]


def _truncate(text: str, limit: int) -> str:
    return text if len(text) <= limit else text[:limit] + "…"


def _extract_json_from_response(text: str) -> dict | None:
    """Extract a review decision JSON from Claude's response."""
    text = text.strip()

    # Try direct JSON parse
    try:
        obj = json.loads(text)
        if isinstance(obj, dict) and "decision" in obj:
            return obj
    except json.JSONDecodeError:
        pass

    # Try markdown-fenced JSON
    fenced = re.search(r"```(?:json)?\s*\n?(.*?)\n?```", text, re.DOTALL)
    if fenced:
        try:
            obj = json.loads(fenced.group(1).strip())
            if isinstance(obj, dict) and "decision" in obj:
                return obj
        except json.JSONDecodeError:
            pass

    # Try extracting JSON object from prose
    brace_match = re.search(r"\{[^{}]*\"decision\"[^{}]*\}", text, re.DOTALL)
    if brace_match:
        try:
            obj = json.loads(brace_match.group(0))
            if isinstance(obj, dict):
                return obj
        except json.JSONDecodeError:
            pass

    return None


class AnthropicAPIBridge(CLIAgentBridge):
    """Bridge that uses the Anthropic API directly.

    Runs Claude completely in-process via the Python SDK, with full
    tool access to the sandbox via inspection commands.
    """

    async def _invoke_in_sandbox(
        self,
        prompt: str,
        workdir: str,
        output_file: str,
        sb: "SandboxEnvironment",
    ) -> tuple[int, str]:
        if Anthropic is None:
            return 1, "Anthropic SDK not installed: pip install anthropic"

        try:
            client = Anthropic()
            logger.debug("Calling Claude API for PR review")

            # Call Claude with the review prompt and JSON schema
            schema = json.loads(self.schema_text)
            response = client.messages.create(
                model=self.model or "claude-opus-4-7",
                max_tokens=2048,
                messages=[{"role": "user", "content": prompt}],
            )

            # Extract the response content
            raw_output = ""
            content = None
            if response.content:
                content_item = response.content[0]
                if hasattr(content_item, "text"):
                    content = content_item.text
                    raw_output = content

            if not content:
                logger.error("Claude returned no response")
                return 1, "Claude returned no response"

            logger.debug("Claude response received, extracting JSON")

            # Try to extract structured JSON from the response
            extracted = _extract_json_from_response(content)
            if extracted:
                payload = json.dumps(extracted)
                logger.debug("Extracted valid JSON from response")
            else:
                # Fallback: treat raw response as potential JSON
                payload = content
                logger.debug("No JSON found in response, using raw content")

            # Validate extracted JSON matches schema
            try:
                parsed = json.loads(payload)
                validation = self._validate_parsed(parsed)
                if validation is None:
                    logger.error(
                        "Extracted JSON does not match review schema: %s",
                        _truncate(payload, 200),
                    )
                    return 1, f"Invalid review format: {payload[:500]}"
                logger.debug("JSON validation passed")
            except json.JSONDecodeError as e:
                logger.error("Failed to parse JSON: %s", e)
                return 1, f"Failed to parse extracted JSON: {payload[:500]}"

            # Write result to sandbox
            await sb.write_file(output_file, payload)
            logger.debug("Review written to sandbox")
            return 0, raw_output

        except Exception as exc:
            logger.exception("Anthropic API bridge error")
            return 1, str(exc)
