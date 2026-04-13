"""Copilot SDK bridge — programmatic control via the copilot Python SDK."""

from __future__ import annotations

import asyncio
import json
import logging
import re
from pathlib import Path

from benchmark.agents.cli_bridge.base import CLIAgentBridge

logger = logging.getLogger(__name__)

_TIMEOUT_EXIT_CODE = 124


def _truncate(text: str, limit: int) -> str:
    return text if len(text) <= limit else text[:limit] + "…"


def _extract_json(text: str) -> str | None:
    """Extract a JSON object from text that may contain markdown fences or prose."""
    # Try the raw text first.
    text = text.strip()
    try:
        obj = json.loads(text)
        if isinstance(obj, dict) and "decision" in obj:
            return json.dumps(obj)
    except json.JSONDecodeError:
        pass

    # Strip markdown code fences and retry.
    fenced = re.search(r"```(?:json)?\s*\n?(.*?)\n?```", text, re.DOTALL)
    if fenced:
        try:
            obj = json.loads(fenced.group(1).strip())
            if isinstance(obj, dict) and "decision" in obj:
                return json.dumps(obj)
        except json.JSONDecodeError:
            pass

    # Last resort: find the first `{...}` block containing "decision".
    brace_match = re.search(r"\{[^{}]*\"decision\"[^{}]*\}", text, re.DOTALL)
    if brace_match:
        try:
            obj = json.loads(brace_match.group(0))
            if isinstance(obj, dict):
                return json.dumps(obj)
        except json.JSONDecodeError:
            pass

    return None


class CopilotSDKBridge(CLIAgentBridge):
    """Bridge that uses the copilot Python SDK instead of shelling out."""

    async def _invoke(
        self, prompt: str, workdir: Path, output_file: Path
    ) -> tuple[int, str]:
        try:
            from copilot import CopilotClient  # noqa: F811
            from copilot.session import PermissionHandler
        except ImportError as exc:
            return 1, (
                f"The copilot Python SDK is not installed: {exc}\n"
                "Install it with: pip install github-copilot-sdk"
            )

        client: CopilotClient | None = None
        session = None
        try:
            client = CopilotClient()
            await client.start()

            session = await client.create_session(
                model=self.model or "gpt-5.4",
                on_permission_request=PermissionHandler.approve_all,
                working_directory=str(workdir),
            )

            # Collect the full event trace for the viewer.
            trace_lines: list[str] = []
            # Map tool_call_id → tool_name for pairing start/complete events.
            _pending_tools: dict[str, str] = {}

            def _trace_handler(event) -> None:
                etype = event.type.value if hasattr(event.type, "value") else str(event.type)
                data = event.data if hasattr(event, "data") else None
                if data is None:
                    return

                if etype == "tool.execution_start":
                    name = getattr(data, "tool_name", None) or "?"
                    call_id = getattr(data, "tool_call_id", None) or ""
                    raw_args = getattr(data, "arguments", None)
                    if call_id and name:
                        _pending_tools[call_id] = name
                    # For bash, extract the command string.
                    if name == "bash" and isinstance(raw_args, dict):
                        cmd = raw_args.get("command", "")
                        trace_lines.append(f"[bash] {_truncate(cmd, 500)}")
                    elif name not in ("report_intent",):
                        arg_str = json.dumps(raw_args) if isinstance(raw_args, dict) else str(raw_args or "")
                        trace_lines.append(f"[tool] {name}: {_truncate(arg_str, 300)}")

                elif etype == "tool.execution_complete":
                    call_id = getattr(data, "tool_call_id", None) or ""
                    name = _pending_tools.pop(call_id, None) or getattr(data, "tool_name", None) or "?"
                    result_obj = getattr(data, "result", None)
                    # Extract content from Result object.
                    if result_obj is not None:
                        content = getattr(result_obj, "content", None) or str(result_obj)
                    else:
                        content = ""
                    if name == "bash":
                        trace_lines.append(f"[bash.output] {_truncate(str(content), 1500)}")
                    elif name not in ("report_intent",):
                        trace_lines.append(f"[tool.output] {name}: {_truncate(str(content), 1000)}")

                elif etype == "assistant.message":
                    content = getattr(data, "content", "")
                    if content:
                        trace_lines.append(f"[assistant] {_truncate(str(content), 2000)}")

                elif etype == "assistant.reasoning":
                    content = getattr(data, "content", "")
                    if content:
                        trace_lines.append(f"[reasoning] {_truncate(str(content), 1000)}")

                elif etype == "session.error":
                    msg = getattr(data, "message", str(data))
                    trace_lines.append(f"[error] {msg}")

            session.on(_trace_handler)

            response = await session.send_and_wait(
                prompt, timeout=float(self.timeout)
            )

            raw_output = "\n".join(trace_lines) if trace_lines else ""

            # Extract the structured review from the last assistant message.
            content: str | None = None
            if response and hasattr(response, "data") and hasattr(response.data, "content"):
                content = response.data.content

            if not content:
                # Fallback: scan trace for last assistant message.
                for line in reversed(trace_lines):
                    if line.startswith("[assistant]"):
                        content = line[len("[assistant] "):]
                        break

            if not content:
                return 1, raw_output or "No response received from Copilot SDK session."

            extracted = _extract_json(content)
            if extracted:
                output_file.write_text(extracted, encoding="utf-8")
            else:
                output_file.write_text(content, encoding="utf-8")

            return 0, raw_output or content

        except TimeoutError:
            return _TIMEOUT_EXIT_CODE, f"Copilot SDK session timed out after {self.timeout}s."
        except Exception as exc:
            logger.exception("Copilot SDK bridge error")
            return 1, str(exc)
        finally:
            if session is not None:
                try:
                    await session.disconnect()
                except Exception:
                    pass
            if client is not None:
                try:
                    await client.stop()
                except Exception:
                    pass
