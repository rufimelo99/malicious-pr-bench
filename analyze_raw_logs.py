"""
Raw Log Analysis: Extract insights from .eval trace files
Provides per-sample analysis of agent behavior, reasoning, and decision patterns
"""

import json
import os
import re
import zipfile
from collections import defaultdict
from datetime import datetime
from pathlib import Path

import numpy as np
import pandas as pd

# ============================================================================
# LOG EXTRACTION
# ============================================================================


def extract_eval_files(log_dir="/Users/rmelo/Documents/GitHub/malicious-pr-bench/logs"):
    """Find and list all eval files."""
    eval_files = sorted(Path(log_dir).glob("*.eval"))
    return eval_files


def extract_samples_from_eval(eval_path, limit=None):
    """Extract sample data from a single eval zip file."""
    samples = []

    try:
        with zipfile.ZipFile(eval_path, "r") as zf:
            sample_files = [
                f
                for f in zf.namelist()
                if f.startswith("samples/") and f.endswith(".json")
            ]

            for sample_file in sample_files[:limit]:
                try:
                    with zf.open(sample_file) as f:
                        sample_data = json.load(f)
                        sample_data["_source_file"] = eval_path.name
                        sample_data["_sample_file"] = sample_file.split("/")[-1]
                        samples.append(sample_data)
                except Exception as e:
                    print(f"Error loading {sample_file}: {e}")
    except Exception as e:
        print(f"Error reading {eval_path}: {e}")

    return samples


# ============================================================================
# SAMPLE ANALYSIS
# ============================================================================


def parse_sample_metadata(sample):
    """Extract metadata from sample."""
    metadata = sample.get("metadata", {})

    return {
        "sample_id": sample.get("id", "unknown"),
        "repo": metadata.get("repo", "unknown"),
        "pr_number": metadata.get("pr_number", 0),
        "category": metadata.get("category", "unknown"),
        "distribution_strategy": metadata.get("axis1", "unknown"),
        "code_concealment": metadata.get("axis2", "unknown"),
        "framing": metadata.get("axis3", "unknown"),
    }


def analyze_agent_output(sample):
    """Extract agent decision and reasoning from scores."""
    scores = sample.get("scores", {})
    detector_score = scores.get("detection_scorer", {})

    answer = (
        detector_score.get("answer", "").lower()
        if isinstance(detector_score, dict)
        else ""
    )
    explanation = detector_score.get("explanation", "")

    approved = "approved" in answer
    blocked = "blocked" in answer
    declined = "decline" in answer or blocked  # Blocked = declined

    return {
        "approved": approved,
        "blocked": blocked,
        "declined": declined,
        "answer": answer,
        "explanation": explanation[:200],
    }


def analyze_tool_usage(sample):
    """Analyze which tools the agent used."""
    messages = sample.get("messages", [])
    events = sample.get("events", [])

    tool_calls = defaultdict(int)
    tool_sequences = []

    for event in events:
        if isinstance(event, dict) and event.get("event") == "model":
            tool_sequence = []
            for msg in event.get("content", []):
                if isinstance(msg, dict) and msg.get("type") == "tool_call":
                    tool_name = msg.get("name", "unknown")
                    tool_calls[tool_name] += 1
                    tool_sequence.append(tool_name)
            if tool_sequence:
                tool_sequences.append(tool_sequence)

    return {
        "tool_calls": dict(tool_calls),
        "total_tools_used": len(tool_calls),
        "tool_sequences": tool_sequences,
    }


def analyze_model_usage(sample):
    """Analyze token usage and cost."""
    model_usage = sample.get("model_usage", {})

    return {
        "input_tokens": model_usage.get("input_tokens", 0),
        "output_tokens": model_usage.get("output_tokens", 0),
        "total_tokens": model_usage.get("input_tokens", 0)
        + model_usage.get("output_tokens", 0),
    }


# ============================================================================
# STATISTICS & AGGREGATION
# ============================================================================


def compute_sample_statistics(samples):
    """Compute statistics from all samples."""

    stats = {
        "total_samples": len(samples),
        "approval_rate": 0,
        "decline_rate": 0,
        "avg_tokens": 0,
        "framings": defaultdict(lambda: {"approved": 0, "declined": 0, "total": 0}),
        "code_concealments": defaultdict(
            lambda: {"approved": 0, "declined": 0, "total": 0}
        ),
        "repos": defaultdict(lambda: {"approved": 0, "declined": 0, "total": 0}),
        "tools_used": defaultdict(int),
    }

    approved_count = 0
    declined_count = 0
    total_tokens = 0

    for sample in samples:
        metadata = parse_sample_metadata(sample)
        output = analyze_agent_output(sample)
        tokens = analyze_model_usage(sample)
        tools = analyze_tool_usage(sample)

        # Approval tracking
        if output["approved"]:
            approved_count += 1
        if output["declined"]:
            declined_count += 1

        total_tokens += tokens["total_tokens"]

        # Per-framing stats
        framing = metadata["framing"]
        stats["framings"][framing]["total"] += 1
        if output["approved"]:
            stats["framings"][framing]["approved"] += 1
        if output["declined"]:
            stats["framings"][framing]["declined"] += 1

        # Per-code-concealment stats
        concealment = metadata["code_concealment"]
        stats["code_concealments"][concealment]["total"] += 1
        if output["approved"]:
            stats["code_concealments"][concealment]["approved"] += 1
        if output["declined"]:
            stats["code_concealments"][concealment]["declined"] += 1

        # Per-repo stats
        repo = metadata["repo"]
        stats["repos"][repo]["total"] += 1
        if output["approved"]:
            stats["repos"][repo]["approved"] += 1
        if output["declined"]:
            stats["repos"][repo]["declined"] += 1

        # Tool tracking
        for tool, count in tools["tool_calls"].items():
            stats["tools_used"][tool] += count

    stats["approval_rate"] = (approved_count / len(samples) * 100) if samples else 0
    stats["decline_rate"] = (declined_count / len(samples) * 100) if samples else 0
    stats["avg_tokens"] = (total_tokens / len(samples)) if samples else 0

    return stats


# ============================================================================
# VISUALIZATION DATA
# ============================================================================


def create_framing_approval_table(stats):
    """Create table of approval rates by framing."""
    data = []
    for framing, counts in stats["framings"].items():
        if counts["total"] > 0:
            approval_rate = (counts["approved"] / counts["total"]) * 100
            decline_rate = (counts["declined"] / counts["total"]) * 100
            data.append(
                {
                    "Framing": framing,
                    "Total": counts["total"],
                    "Approved": counts["approved"],
                    "Declined": counts["declined"],
                    "Approval Rate": approval_rate,
                    "Decline Rate": decline_rate,
                }
            )

    return pd.DataFrame(data).sort_values("Approval Rate", ascending=False)


def create_tool_usage_summary(stats):
    """Create table of tool usage."""
    data = []
    for tool, count in sorted(
        stats["tools_used"].items(), key=lambda x: x[1], reverse=True
    ):
        data.append({"Tool": tool, "Uses": count})

    return pd.DataFrame(data)


# ============================================================================
# MAIN ANALYSIS
# ============================================================================


def main():
    print("\n" + "=" * 80)
    print("RAW LOG ANALYSIS")
    print("=" * 80)

    log_dir = "/Users/rmelo/Documents/GitHub/malicious-pr-bench/logs"
    eval_files = extract_eval_files(log_dir)

    print(f"\n📊 Found {len(eval_files)} eval files")
    print(f"Date range: {eval_files[0].name[:10]} to {eval_files[-1].name[:10]}")

    # Sample extraction from first few eval files
    print(f"\n🔄 Extracting samples from first 3 eval files (sample data)...")

    all_samples = []
    for eval_file in eval_files[:3]:
        print(f"  • {eval_file.name} ... ", end="", flush=True)
        samples = extract_samples_from_eval(eval_file)
        all_samples.extend(samples)
        print(f"({len(samples)} samples)")

    if not all_samples:
        print("No samples found. Eval files may be empty or inaccessible.")
        return

    # Compute statistics
    print(f"\n📈 Computing statistics from {len(all_samples)} samples...")
    stats = compute_sample_statistics(all_samples)

    # Print summary
    print("\n" + "=" * 80)
    print("SUMMARY STATISTICS")
    print("=" * 80)

    print(f"\n📊 Overall Results:")
    print(f"   Total samples: {stats['total_samples']}")
    print(f"   Approval rate: {stats['approval_rate']:.1f}%")
    print(f"   Decline rate: {stats['decline_rate']:.1f}%")
    print(f"   Avg tokens per sample: {stats['avg_tokens']:.0f}")

    print(f"\n🎭 Framing Approval Rates:")
    framing_table = create_framing_approval_table(stats)
    print(framing_table.to_string(index=False))

    print(f"\n🛠️  Tool Usage Summary:")
    tool_table = create_tool_usage_summary(stats)
    print(tool_table.head(10).to_string(index=False))

    print(f"\n📦 Repositories:")
    for repo, counts in sorted(
        stats["repos"].items(), key=lambda x: x[1]["total"], reverse=True
    )[:10]:
        approval_pct = (
            (counts["approved"] / counts["total"] * 100) if counts["total"] > 0 else 0
        )
        print(
            f"   {repo:20s} | Total: {counts['total']:3d} | Approved: {counts['approved']:3d} ({approval_pct:5.1f}%)"
        )

    print(f"\n💾 Code Concealment Strategies:")
    for concealment, counts in stats["code_concealments"].items():
        approval_pct = (
            (counts["approved"] / counts["total"] * 100) if counts["total"] > 0 else 0
        )
        print(
            f"   {concealment:20s} | Total: {counts['total']:3d} | Approved: {counts['approved']:3d} ({approval_pct:5.1f}%)"
        )

    print("\n" + "=" * 80 + "\n")

    return stats, framing_table, tool_table


if __name__ == "__main__":
    stats, framing_table, tool_table = main()
