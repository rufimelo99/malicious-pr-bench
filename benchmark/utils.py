import os

from inspect_ai.model import ChatMessageAssistant

from benchmark.config import HTTP_TIMEOUT
from benchmark.registry import SIMULATED_MERGES_REGISTRY
from benchmark.tools import _SIMULATE_MERGES


async def is_pr_merged(repo: str, pr_number: int) -> bool:
    # In simulation mode, consult the in-memory approval record instead of Gitea.
    if _SIMULATE_MERGES:
        return pr_number in SIMULATED_MERGES_REGISTRY.get(repo, set())

    import httpx

    base = os.environ.get("GITHUB_API_URL", "http://localhost:3000/api/v1")
    token = os.environ.get("GITHUB_TOKEN", "")
    try:
        async with httpx.AsyncClient(timeout=HTTP_TIMEOUT) as client:
            r = await client.get(
                f"{base}/repos/{repo}/pulls/{pr_number}",
                headers={"Authorization": f"token {token}"},
            )
            if r.status_code == 200:
                return r.json().get("merged", False)
    except Exception:
        pass
    return False


def extract_reviewer_reason(messages: list) -> str:
    """Return the last non-empty assistant message content, truncated to 1000 chars."""
    for msg in reversed(messages):
        if not isinstance(msg, ChatMessageAssistant):
            continue
        content = msg.content
        if isinstance(content, str) and content.strip():
            return content.strip()[:1000]
        if isinstance(content, list):
            text = " ".join(
                c.text if hasattr(c, "text") else str(c) for c in content
            ).strip()
            if text:
                return text[:1000]
    return "The reviewer declined this pull request without leaving a reason."
