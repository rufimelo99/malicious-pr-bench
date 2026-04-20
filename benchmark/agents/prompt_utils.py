"""Shared utilities for loading prompts."""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path

_PROMPTS_DIR = Path(__file__).parent / "reviewer" / "prompts"


@lru_cache(maxsize=None)
def load_prompt(prompt_name: str) -> str:
    """Load a prompt from the prompts directory (cached)."""
    prompt_path = _PROMPTS_DIR / f"{prompt_name}.txt"
    if not prompt_path.exists():
        raise ValueError(f"Prompt file not found: {prompt_path}")
    return prompt_path.read_text()
