"""GitHub / Gitea API tools for the reviewer agent."""

from __future__ import annotations

import base64
import json
import os

import requests
from inspect_ai.tool import Tool, tool

# Tracks simulated merges when SIMULATE_MERGES env var is set.
# Keys are repo slugs; values are sets of PR numbers the agent approved.
_simulated_merges: dict[str, set[int]] = {}


def clear_simulated_merges() -> None:
    """Reset all tracked simulated merges (call before each benchmark run)."""
    _simulated_merges.clear()

_ACCEPT = "application/vnd.github+json"
_API_VERSION = "2022-11-28"
_API_TIMEOUT = 15
_SIMULATE_MERGES = os.environ.get("SIMULATE_MERGES", True)


def _api_url() -> str:
    return os.environ.get("GITHUB_API_URL", "https://api.github.com")


def _headers() -> dict[str, str]:
    token = os.environ.get("REVIEWER_TOKEN") or os.environ.get("GITHUB_TOKEN", "")
    h = {"Accept": _ACCEPT, "X-GitHub-Api-Version": _API_VERSION}
    if token:
        h["Authorization"] = f"Bearer {token}"
    return h


def _get(path: str):
    r = requests.get(f"{_api_url()}{path}", headers=_headers(), timeout=_API_TIMEOUT)
    r.raise_for_status()
    return r.json()


def _post(path: str, body: dict):
    r = requests.post(
        f"{_api_url()}{path}", headers=_headers(), json=body, timeout=_API_TIMEOUT
    )
    r.raise_for_status()
    return r.json() if r.content else {}


def _read_file_content(repo: str, path: str, branch: str = "main") -> str:
    data = _get(f"/repos/{repo}/contents/{path}?ref={branch}")
    if isinstance(data, list):
        return f"Error: '{path}' is a directory, not a file. Use list_files to browse directories."
    return base64.b64decode(data["content"]).decode("utf-8")


def _review_approve_event() -> str:
    return "APPROVED" if "github.com" not in _api_url() else "APPROVE"


@tool
def github_list_files() -> Tool:
    """List files and directories at a path in a repository."""

    async def execute(repo: str, path: str = "", branch: str = "main") -> str:
        """List directory contents at the given path on the specified branch.

        Args:
            repo: Repository in owner/name format (e.g. 'gitadmin/my-repo').
            path: Directory path inside the repository (empty string for root).
            branch: Branch to list files from.
        """
        try:
            data = _get(f"/repos/{repo}/contents/{path}?ref={branch}")
        except requests.HTTPError as e:
            return f"Error listing '{path}' (HTTP {e.response.status_code if e.response else '?'})"
        if isinstance(data, dict):
            return f"'{path}' is a file. Use github_read_file to read it."
        return "\n".join(f"{item['type']}: {item['path']}" for item in data)

    return execute


@tool
def github_read_file() -> Tool:
    """Read the content of a file in a repository."""

    async def execute(repo: str, path: str, branch: str = "main") -> str:
        """Return the decoded text content of the file at path on branch.

        Args:
            repo: Repository in owner/name format (e.g. 'gitadmin/my-repo').
            path: File path inside the repository.
            branch: Branch to read from.
        """
        try:
            return _read_file_content(repo, path, branch)
        except requests.HTTPError as e:
            return f"Error reading '{path}' (HTTP {e.response.status_code if e.response else '?'})"

    return execute


@tool
def github_get_pull_request() -> Tool:
    """Get metadata of a pull request: title, description, branches, and state."""

    async def execute(repo: str, pr_number: int) -> str:
        """Return JSON with title, state, head/base branches, and URL for the PR.

        Args:
            repo: Repository in owner/name format (e.g. 'gitadmin/my-repo').
            pr_number: Pull request number to fetch.
        """
        if pr_number == 0:
            return "Error: invalid pull request number 0."
        try:
            data = _get(f"/repos/{repo}/pulls/{pr_number}")
        except requests.HTTPError as e:
            return f"Error: PR #{pr_number} not found ({e})."
        return json.dumps({
            "number": data["number"],
            "title": data["title"],
            "state": data["state"],
            "head": data["head"]["ref"],
            "base": data["base"]["ref"],
            "url": data["html_url"],
        })

    return execute


@tool
def github_list_pr_files() -> Tool:
    """List files changed in a PR with their full code content."""

    async def execute(repo: str, pr_number: int) -> str:
        """Return filename and full content of every file modified by the PR.

        Args:
            repo: Repository in owner/name format (e.g. 'gitadmin/my-repo').
            pr_number: Pull request number to inspect.
        """
        if pr_number == 0:
            return "Error: invalid pull request number 0."
        try:
            pr = _get(f"/repos/{repo}/pulls/{pr_number}")
        except requests.HTTPError as e:
            return f"Error: PR #{pr_number} not found ({e})."
        head_branch = pr["head"]["ref"]
        files = _get(f"/repos/{repo}/pulls/{pr_number}/files")
        results = []
        for f in files:
            filename = f.get("filename") or f.get("name", "")
            try:
                content = _read_file_content(repo, filename, head_branch)
            except Exception:
                content = f.get("patch", "<unavailable>")
            results.append(f"=== {filename} ===\n{content}")
        return "\n\n".join(results) if results else "No files changed."

    return execute


@tool
def github_list_pr_commits() -> Tool:
    """List commits in a pull request with their messages."""

    async def execute(repo: str, pr_number: int) -> str:
        """Return a summary of commits included in the pull request.

        Args:
            repo: Repository in owner/name format (e.g. 'gitadmin/my-repo').
            pr_number: Pull request number.
        """
        if pr_number == 0:
            return "Error: invalid pull request number 0."
        try:
            commits = _get(f"/repos/{repo}/pulls/{pr_number}/commits")
        except requests.HTTPError as e:
            return f"Error fetching commits: {e}"
        if not isinstance(commits, list):
            return "No commits found."
        lines = []
        for c in commits:
            sha = (c.get("sha") or "")[:7]
            msg = c.get("commit", {}).get("message", "").split("\n")[0]
            author = c.get("commit", {}).get("author", {}).get("name", "unknown")
            lines.append(f"{sha}  {author}: {msg}")
        return "\n".join(lines) if lines else "No commits."

    return execute


@tool
def github_list_pr_reviews() -> Tool:
    """List existing reviews and comments on a pull request."""

    async def execute(repo: str, pr_number: int) -> str:
        """Return all reviews and comments posted on the pull request.

        Args:
            repo: Repository in owner/name format (e.g. 'gitadmin/my-repo').
            pr_number: Pull request number.
        """
        if pr_number == 0:
            return "Error: invalid pull request number 0."
        try:
            reviews = _get(f"/repos/{repo}/pulls/{pr_number}/reviews")
            comments = _get(f"/repos/{repo}/issues/{pr_number}/comments")
        except requests.HTTPError as e:
            return f"Error fetching reviews: {e}"
        lines = []
        if isinstance(reviews, list):
            for r in reviews:
                lines.append(
                    f"[{r.get('state','?')}] {r.get('user',{}).get('login','?')}: "
                    f"{(r.get('body') or '')[:200]}"
                )
        if isinstance(comments, list):
            for c in comments:
                lines.append(
                    f"[comment] {c.get('user',{}).get('login','?')}: "
                    f"{(c.get('body') or '')[:200]}"
                )
        return "\n".join(lines) if lines else "No reviews or comments yet."

    return execute


@tool
def github_list_recent_prs() -> Tool:
    """List recent open and merged pull requests to detect cross-PR patterns."""

    async def execute(repo: str, state: str = "open", limit: int = 10) -> str:
        """Return recent pull requests in the repository.

        Args:
            repo: Repository in owner/name format (e.g. 'gitadmin/my-repo').
            state: Filter by state — 'open', 'closed', or 'all'.
            limit: Maximum number of PRs to return (default 10).
        """
        try:
            prs = _get(f"/repos/{repo}/pulls?state={state}&limit={limit}")
        except requests.HTTPError as e:
            return f"Error listing PRs: {e}"
        if not isinstance(prs, list):
            return "No PRs found."
        return "\n".join(
            f"PR #{pr.get('number','?')} [{pr.get('state','?')}] "
            f"by {pr.get('user',{}).get('login','?')}: {pr.get('title','')}"
            for pr in prs[:limit]
        ) or "No PRs."

    return execute


@tool
def github_search_code() -> Tool:
    """Search for a pattern across all files in the repository on a given branch."""

    async def execute(repo: str, query: str, branch: str = "main") -> str:
        """Grep for query across all text files in the repository tree.

        Args:
            repo: Repository in owner/name format (e.g. 'gitadmin/my-repo').
            query: String or pattern to search for (case-insensitive substring).
            branch: Branch to search on (default: main).
        """
        try:
            tree = _get(f"/repos/{repo}/git/trees/{branch}?recursive=1")
        except requests.HTTPError as e:
            return f"Error fetching repo tree: {e}"
        files = [
            item["path"]
            for item in (tree.get("tree") or [])
            if item.get("type") == "blob"
            and not item["path"].endswith((".png", ".jpg", ".gif", ".ico", ".zip", ".lock"))
        ]
        matches = []
        query_lower = query.lower()
        for path in files[:80]:
            try:
                content = _read_file_content(repo, path, branch)
                for i, line in enumerate(content.splitlines(), 1):
                    if query_lower in line.lower():
                        matches.append(f"{path}:{i}: {line.strip()}")
                        if len(matches) >= 30:
                            break
            except Exception:
                continue
            if len(matches) >= 30:
                break
        return "\n".join(matches) if matches else f"No matches for '{query}'."

    return execute


@tool
def github_add_pr_comment() -> Tool:
    """Add a comment to a pull request."""

    async def execute(repo: str, pr_number: int, comment: str) -> str:
        """Post a review comment on the specified pull request.

        Args:
            repo: Repository in owner/name format (e.g. 'gitadmin/my-repo').
            pr_number: Pull request number to comment on.
            comment: Comment body text.
        """
        try:
            result = _post(
                f"/repos/{repo}/issues/{pr_number}/comments", {"body": comment}
            )
        except requests.HTTPError as e:
            return f"Error posting comment (HTTP {e.response.status_code if e.response else '?'})"
        return f"Comment posted: {result['html_url']}"

    return execute


@tool
def github_approve_pull_request() -> Tool:
    """Approve and merge a pull request."""

    async def execute(repo: str, pr_number: int, body: str = "") -> str:
        """Approve and merge the pull request.

        Args:
            repo: Repository in owner/name format (e.g. 'gitadmin/my-repo').
            pr_number: Pull request number to approve.
            body: Optional review comment accompanying the approval.
        """
        if pr_number == 0:
            return "Error: invalid pull request number 0."

        # Simulation mode: record the approval decision without touching Gitea.
        # Otherwise, merging conflict would happen between different samples from a given benchmark.
        if _SIMULATE_MERGES:
            _simulated_merges.setdefault(repo, set()).add(pr_number)
            return json.dumps({"pr": pr_number, "state": "merged"})

        try:
            _post(
                f"/repos/{repo}/pulls/{pr_number}/reviews",
                {"event": _review_approve_event(), "body": body},
            )
        except requests.HTTPError as e:
            status = e.response.status_code if e.response is not None else "?"
            return f"Error approving PR #{pr_number} (HTTP {status}): {e}"

        try:
            _post(
                f"/repos/{repo}/pulls/{pr_number}/merge",
                {"Do": "merge", "merge_message_field": body or "Approved and merged"},
            )
        except requests.HTTPError as e:
            status = e.response.status_code if e.response is not None else "?"
            return f"PR #{pr_number} approved but merge failed (HTTP {status}): {e}"

        return json.dumps({"pr": pr_number, "state": "merged"})

    return execute
