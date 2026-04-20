"""Copilot SDK bridge — programmatic control via the copilot Python SDK."""

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
    from copilot.tools import ToolInvocation, ToolResult, define_tool
    from pydantic import BaseModel, Field

    class _BashParams(BaseModel):
        command: str = Field(description="The shell command to execute")

except ImportError:
    ToolInvocation = None  # type: ignore[assignment,misc]
    ToolResult = None  # type: ignore[assignment,misc]
    define_tool = None  # type: ignore[assignment,misc]
    _BashParams = None  # type: ignore[assignment,misc]


def _truncate(text: str, limit: int) -> str:
    return text if len(text) <= limit else text[:limit] + "…"


def _escape_newlines(text: str) -> str:
    """Replace literal newlines so each trace entry stays on one line."""
    return text.replace("\\", "\\\\").replace("\n", "\\n").replace("\r", "")


def _extract_json(text: str) -> str | None:
    """Extract a JSON object from text that may contain markdown fences or prose."""
    text = text.strip()
    try:
        obj = json.loads(text)
        if isinstance(obj, dict) and "decision" in obj:
            return json.dumps(obj)
    except json.JSONDecodeError:
        pass

    fenced = re.search(r"```(?:json)?\s*\n?(.*?)\n?```", text, re.DOTALL)
    if fenced:
        try:
            obj = json.loads(fenced.group(1).strip())
            if isinstance(obj, dict) and "decision" in obj:
                return json.dumps(obj)
        except json.JSONDecodeError:
            pass

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
    """Bridge that uses the copilot Python SDK.

    The Copilot session runs in-process on the host, but every bash tool
    call is routed into the sandbox container via ``sb.exec()``.
    """

    async def _invoke_in_sandbox(
        self,
        prompt: str,
        workdir: str,
        output_file: str,
        sb: "SandboxEnvironment",
    ) -> tuple[int, str]:
        try:
            from copilot import CopilotClient
            from copilot.client import SubprocessConfig
            from copilot.session import PermissionHandler
        except ImportError as exc:
            return 1, (
                f"The copilot Python SDK is not installed: {exc}\n"
                "Install it with: pip install github-copilot-sdk"
            )

        if define_tool is None:
            return 1, "The copilot Python SDK is not installed."

        async def _bash_handler(
            params: _BashParams, invocation: ToolInvocation
        ) -> ToolResult:
            try:
                res = await sb.exec(
                    cmd=["bash", "-c", params.command],
                    cwd=workdir,
                    timeout=30,
                )
                out = "\n".join(p for p in (res.stdout, res.stderr) if p).strip()
                return ToolResult(text_result_for_llm=out or "(no output)")
            except Exception as exc:
                return ToolResult(
                    text_result_for_llm=f"Error: {exc}", result_type="failure"
                )

        sandbox_bash = define_tool(
            name="bash",
            description="Execute a shell command in the repository checkout",
            handler=_bash_handler,
            params_type=_BashParams,
            overrides_built_in_tool=True,
            skip_permission=True,
        )

        config = (
            SubprocessConfig(github_token=self.github_token)
            if self.github_token
            else SubprocessConfig()
        )

        client: CopilotClient | None = None
        session = None
        try:
            client = CopilotClient(config)
            await client.start()

            session = await client.create_session(
                model=self.model or "gpt-5.3-codex",
                on_permission_request=PermissionHandler.approve_all,
                working_directory=workdir,
                tools=[sandbox_bash],
            )

            _, raw_output, content = await self._run_session(session, prompt)

            if not content:
                return 1, raw_output or "No response received from Copilot SDK session."

            extracted = _extract_json(content)
            await sb.write_file(output_file, extracted or content)
            return 0, raw_output or content

        except TimeoutError:
            return self._timeout_error("copilot-sdk")
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

    async def _run_session(
        self, session, prompt: str
    ) -> tuple[list[str], str, str | None]:
        """Send *prompt* to an open session and collect trace + final content."""
        trace_lines: list[str] = []
        _pending_tools: dict[str, str] = {}

        def _trace_handler(event) -> None:
            etype = (
                event.type.value if hasattr(event.type, "value") else str(event.type)
            )
            data = event.data if hasattr(event, "data") else None
            if data is None:
                return

            if etype == "tool.execution_start":
                name = getattr(data, "tool_name", None) or "?"
                call_id = getattr(data, "tool_call_id", None) or ""
                raw_args = getattr(data, "arguments", None)
                if call_id and name:
                    _pending_tools[call_id] = name
                if name == "bash" and isinstance(raw_args, dict):
                    cmd = raw_args.get("command", "")
                    trace_lines.append(
                        f"[bash] {_escape_newlines(_truncate(cmd, 500))}"
                    )
                elif name not in ("report_intent",):
                    arg_str = (
                        json.dumps(raw_args)
                        if isinstance(raw_args, dict)
                        else str(raw_args or "")
                    )
                    trace_lines.append(
                        f"[tool] {name}: {_escape_newlines(_truncate(arg_str, 300))}"
                    )

            elif etype == "tool.execution_complete":
                call_id = getattr(data, "tool_call_id", None) or ""
                name = (
                    _pending_tools.pop(call_id, None)
                    or getattr(data, "tool_name", None)
                    or "?"
                )
                result_obj = getattr(data, "result", None)
                content = (
                    getattr(result_obj, "content", None) or str(result_obj)
                    if result_obj is not None
                    else ""
                )
                if name == "bash":
                    trace_lines.append(
                        f"[bash.output] {_escape_newlines(_truncate(str(content), 1500))}"
                    )
                elif name not in ("report_intent",):
                    trace_lines.append(
                        f"[tool.output] {name}: {_escape_newlines(_truncate(str(content), 1000))}"
                    )

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
        response = await session.send_and_wait(prompt, timeout=float(self.timeout))
        raw_output = "\n".join(trace_lines) if trace_lines else ""

        content: str | None = None
        if response and hasattr(response, "data") and hasattr(response.data, "content"):
            content = response.data.content
        if not content:
            for line in reversed(trace_lines):
                if line.startswith("[assistant]"):
                    content = line[len("[assistant] ") :]
                    break

        return trace_lines, raw_output, content
