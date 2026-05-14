#!/usr/bin/env python3
"""
Extract message counts and tool call information from evaluation logs.
Analyzes reasoning depth: how many back-and-forth messages each model needed.

Usage:
  python3 extract_message_counts.py          # Extract all samples
  python3 extract_message_counts.py --retained  # Filter to retained challenge split
"""
import glob
import json
import sys
import zipfile
from collections import defaultdict
from pathlib import Path


def extract_tool_calls(model_usage):
    """Count and categorize tool calls from model_usage data."""
    if not model_usage:
        return {"total": 0, "by_type": {}}

    total_calls = 0
    by_type = defaultdict(int)

    # model_usage is typically: {"input_tokens": N, "output_tokens": N, ...}
    # Tool calls are typically in a tools_used or similar field
    # For now, we'll just count total calls if available

    return {"total": total_calls, "by_type": dict(by_type) if by_type else {}}


# Check for --retained flag
use_retained_split = "--retained" in sys.argv

# Load retained sample IDs if requested
retained_ids_by_cwe = None
if use_retained_split:
    retained_path = Path("../../retained_sample_ids.json")
    with open(retained_path) as f:
        retained_ids_by_cwe = json.load(f)
    total_entries = sum(len(ids) for ids in retained_ids_by_cwe.values())
    print(
        f"Using retained challenge split: {total_entries} total samples across CWEs\n"
    )

# Results structure: model -> prompt -> cwe -> framing -> [samples with message_count]
results = defaultdict(
    lambda: defaultdict(lambda: defaultdict(lambda: defaultdict(list)))
)

# Scan both results_nips and filtering_releases directories
results_dirs = [
    Path("../../logs/results_nips"),
    Path("../../logs/filtering_releases"),
]

sample_count = 0
for results_dir in results_dirs:
    for dir_path in sorted(results_dir.glob("*_gitea_*")):
        if not dir_path.is_dir():
            continue

        # Parse directory name
        parts = dir_path.name.split("_gitea_")
        if len(parts) < 2:
            continue

        # Handle different naming conventions
        rest = "_gitea_".join(parts[1:])

        # Try to extract prompt and cwe
        if "_cwe" in rest:
            prompt_cwe = (
                rest.split("_cwe")[0] + "_cwe" + rest.split("_cwe")[1].split("_")[0]
            )
        else:
            continue

        model_name = parts[0]
        prompt_parts = prompt_cwe.split("_cwe")
        if len(prompt_parts) != 2:
            continue

        prompt = prompt_parts[0]
        cwe = f"cwe{prompt_parts[1]}"

        # Find eval files
        eval_files = list(dir_path.glob("*.eval"))
        if not eval_files:
            continue

        # Deduplicate by sample ID: process files oldest-to-newest so retries overwrite prior results
        samples_by_id = {}
        for eval_file in sorted(eval_files):
            try:
                with zipfile.ZipFile(eval_file) as z:
                    summary_files = sorted(
                        [
                            n
                            for n in z.namelist()
                            if "_journal/summaries" in n and n.endswith(".json")
                        ]
                    )
                    for summary_file in summary_files:
                        with z.open(summary_file) as f:
                            samples = json.loads(f.read().decode())
                            for sample in samples:
                                sample_id = sample.get("id", sample.get("uuid"))
                                if sample_id:
                                    samples_by_id[sample_id] = sample
            except Exception as e:
                continue

        # Process deduplicated samples
        for sample in samples_by_id.values():
            if "scores" not in sample:
                continue

            # Filter to retained split if requested (check per-CWE)
            sample_id = sample.get("id", "")
            if retained_ids_by_cwe is not None:
                if sample_id not in retained_ids_by_cwe.get(cwe, []):
                    continue

            # Extract framing from sample ID
            parts = sample_id.split("-")
            if len(parts) < 3:
                continue

            framing = parts[-1]  # Last part is framing

            # Skip partial_test_coverage (not in paper's 15 framings)
            if framing == "partial_test_coverage":
                continue

            # Extract message count
            message_count = sample.get("message_count", 0)

            # Extract detection decision
            detection_score = (
                sample["scores"].get("detection_scorer", {}).get("value", None)
            )

            # Extract security reason score
            security_reason_score = (
                sample["scores"].get("security_reason_scorer", {}).get("value", None)
            )

            # Extract model usage info
            model_usage = sample.get("model_usage", {})
            input_tokens = model_usage.get("input_tokens", 0) if model_usage else 0
            output_tokens = model_usage.get("output_tokens", 0) if model_usage else 0

            sample_data = {
                "sample_id": sample_id,
                "message_count": message_count,
                "detection_score": detection_score,
                "security_reason_score": security_reason_score,
                "input_tokens": input_tokens,
                "output_tokens": output_tokens,
                "total_tokens": input_tokens + output_tokens,
            }

            results[model_name][prompt][cwe][framing].append(sample_data)
            sample_count += 1

print(f"Extracted {sample_count} samples\n")

# ============================================================================
# AGGREGATE STATISTICS
# ============================================================================

# Per-model statistics
model_stats = {}
for model_name, prompts in results.items():
    model_samples = []
    for prompt, cwes in prompts.items():
        for cwe, framings in cwes.items():
            for framing, samples in framings.items():
                model_samples.extend(samples)

    if model_samples:
        message_counts = [s["message_count"] for s in model_samples]
        detection_scores = [
            s["detection_score"]
            for s in model_samples
            if s["detection_score"] is not None
        ]
        token_counts = [s["total_tokens"] for s in model_samples]

        model_stats[model_name] = {
            "n_samples": len(model_samples),
            "message_count": {
                "mean": (
                    round(sum(message_counts) / len(message_counts), 2)
                    if message_counts
                    else None
                ),
                "min": min(message_counts) if message_counts else None,
                "max": max(message_counts) if message_counts else None,
            },
            "detection_accuracy": {
                "accuracy": (
                    round(
                        sum([1 for s in detection_scores if s == 1.0])
                        / len(detection_scores)
                        * 100,
                        1,
                    )
                    if detection_scores
                    else None
                ),
                "n_samples": len(detection_scores),
            },
            "tokens": {
                "mean": (
                    round(sum(token_counts) / len(token_counts), 0)
                    if token_counts
                    else None
                ),
                "min": min(token_counts) if token_counts else None,
                "max": max(token_counts) if token_counts else None,
            },
        }

# Per-CWE statistics
cwe_stats = {}
for model_name, prompts in results.items():
    for prompt, cwes in prompts.items():
        for cwe, framings in cwes.items():
            cwe_samples = []
            for framing, samples in framings.items():
                cwe_samples.extend(samples)

            if cwe_samples:
                if cwe not in cwe_stats:
                    cwe_stats[cwe] = {}

                message_counts = [s["message_count"] for s in cwe_samples]
                detection_scores = [
                    s["detection_score"]
                    for s in cwe_samples
                    if s["detection_score"] is not None
                ]

                cwe_stats[cwe][model_name] = {
                    "n_samples": len(cwe_samples),
                    "message_count": {
                        "mean": (
                            round(sum(message_counts) / len(message_counts), 2)
                            if message_counts
                            else None
                        ),
                        "min": min(message_counts) if message_counts else None,
                        "max": max(message_counts) if message_counts else None,
                    },
                    "detection_accuracy": {
                        "accuracy": (
                            round(
                                sum([1 for s in detection_scores if s == 1.0])
                                / len(detection_scores)
                                * 100,
                                1,
                            )
                            if detection_scores
                            else None
                        ),
                    },
                }

# Build output structure
output_data = {
    "metadata": {
        "total_samples": sample_count,
        "filtered": use_retained_split,
    },
    "per_model": model_stats,
    "per_cwe": cwe_stats,
    "raw_samples": {},
}

# Include raw sample data for detailed analysis
for model_name, prompts in results.items():
    output_data["raw_samples"][model_name] = {}
    for prompt, cwes in prompts.items():
        output_data["raw_samples"][model_name][prompt] = {}
        for cwe, framings in cwes.items():
            output_data["raw_samples"][model_name][prompt][cwe] = {}
            for framing, samples in framings.items():
                output_data["raw_samples"][model_name][prompt][cwe][framing] = samples

# Save results as JSON
if use_retained_split:
    output_path = Path("../../message_counts_retained_split.json")
else:
    output_path = Path("../../message_counts.json")

with open(output_path, "w") as f:
    json.dump(output_data, f, indent=2)

mode = "RETAINED SPLIT" if use_retained_split else "ALL DATA"
print(f"✓ Saved message count analysis ({mode}) to {output_path}")
print(f"\nPer-model summary:")
for model, stats in sorted(model_stats.items()):
    print(f"  {model}:")
    print(f"    Samples: {stats['n_samples']}")
    print(f"    Avg messages: {stats['message_count']['mean']}")
    print(f"    Detection accuracy: {stats['detection_accuracy']['accuracy']}%")
    print(f"    Avg tokens: {stats['tokens']['mean']}")
