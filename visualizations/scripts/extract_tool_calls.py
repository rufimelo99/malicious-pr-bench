#!/usr/bin/env python3
"""
Extract tool call information from evaluation logs.
Analyzes which tools models invoke and how frequently during PR reviews.

Usage:
  python3 extract_tool_calls.py          # Extract all samples
  python3 extract_tool_calls.py --retained  # Filter to retained challenge split
"""
import glob
import json
import sys
import zipfile
from collections import defaultdict
from pathlib import Path

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

# Results structure: model -> cwe -> framing -> [tool call counts and types]
results = defaultdict(lambda: defaultdict(lambda: defaultdict(list)))

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
                    # Try to find sample files first (newer format)
                    sample_files = sorted(
                        [
                            n
                            for n in z.namelist()
                            if n.startswith("samples/") and n.endswith(".json")
                        ]
                    )

                    for sample_file in sample_files:
                        with z.open(sample_file) as f:
                            sample = json.loads(f.read().decode())
                            sample_id = sample.get("id", sample.get("uuid"))
                            if sample_id:
                                samples_by_id[sample_id] = sample

                    # Fallback to summary files
                    if not sample_files:
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

            # Extract tool calls from messages
            messages = sample.get("messages", [])
            tool_calls_made = defaultdict(int)

            for msg in messages:
                if msg.get("role") == "assistant":
                    calls = msg.get("tool_calls", [])
                    for call in calls:
                        tool_name = call.get("function", "unknown")
                        tool_calls_made[tool_name] += 1

            # Extract detection score
            detection_score = (
                sample.get("scores", {}).get("detection_scorer", {}).get("value", None)
            )

            sample_data = {
                "sample_id": sample_id,
                "tool_calls": dict(tool_calls_made),
                "total_tool_calls": sum(tool_calls_made.values()),
                "detection_score": detection_score,
            }

            results[model_name][cwe][framing].append(sample_data)
            sample_count += 1

print(f"Extracted {sample_count} samples\n")

# ============================================================================
# AGGREGATE STATISTICS
# ============================================================================

# Per-model statistics
model_stats = {}
for model_name, cwes in results.items():
    model_samples = []
    for cwe, framings in cwes.items():
        for framing, samples in framings.items():
            model_samples.extend(samples)

    if model_samples:
        tool_call_counts = [s["total_tool_calls"] for s in model_samples]
        detection_scores = [
            s["detection_score"]
            for s in model_samples
            if s["detection_score"] is not None
        ]

        # Aggregate tool call types
        all_tool_types = defaultdict(int)
        for sample in model_samples:
            for tool, count in sample["tool_calls"].items():
                all_tool_types[tool] += count

        model_stats[model_name] = {
            "n_samples": len(model_samples),
            "tool_calls": {
                "mean": (
                    round(sum(tool_call_counts) / len(tool_call_counts), 2)
                    if tool_call_counts
                    else None
                ),
                "min": min(tool_call_counts) if tool_call_counts else None,
                "max": max(tool_call_counts) if tool_call_counts else None,
            },
            "tool_types": dict(all_tool_types),
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
        }

# Per-CWE statistics
cwe_stats = {}
for model_name, cwes in results.items():
    for cwe, framings in cwes.items():
        cwe_samples = []
        for framing, samples in framings.items():
            cwe_samples.extend(samples)

        if cwe_samples:
            if cwe not in cwe_stats:
                cwe_stats[cwe] = {}

            tool_call_counts = [s["total_tool_calls"] for s in cwe_samples]
            detection_scores = [
                s["detection_score"]
                for s in cwe_samples
                if s["detection_score"] is not None
            ]

            cwe_stats[cwe][model_name] = {
                "n_samples": len(cwe_samples),
                "tool_calls": {
                    "mean": (
                        round(sum(tool_call_counts) / len(tool_call_counts), 2)
                        if tool_call_counts
                        else None
                    ),
                    "min": min(tool_call_counts) if tool_call_counts else None,
                    "max": max(tool_call_counts) if tool_call_counts else None,
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
for model_name, cwes in results.items():
    output_data["raw_samples"][model_name] = {}
    for cwe, framings in cwes.items():
        output_data["raw_samples"][model_name][cwe] = {}
        for framing, samples in framings.items():
            output_data["raw_samples"][model_name][cwe][framing] = samples

# Save results as JSON
if use_retained_split:
    output_path = Path("../../tool_calls_retained_split.json")
else:
    output_path = Path("../../tool_calls.json")

with open(output_path, "w") as f:
    json.dump(output_data, f, indent=2)

mode = "RETAINED SPLIT" if use_retained_split else "ALL DATA"
print(f"✓ Saved tool call analysis ({mode}) to {output_path}")
print(f"\nPer-model summary:")
for model, stats in sorted(model_stats.items()):
    print(f"  {model}:")
    print(f"    Samples: {stats['n_samples']}")
    print(f"    Avg tool calls: {stats['tool_calls']['mean']}")
    print(f"    Detection accuracy: {stats['detection_accuracy']['accuracy']}%")
    print(f"    Tool types used: {len(stats['tool_types'])}")
    if stats["tool_types"]:
        most_used = sorted(
            stats["tool_types"].items(), key=lambda x: x[1], reverse=True
        )[:3]
        print(
            f"      Top tools: {', '.join([f'{tool} ({count})' for tool, count in most_used])}"
        )
