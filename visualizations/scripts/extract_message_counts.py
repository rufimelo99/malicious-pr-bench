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


# Optional tokenizer for estimating output tokens when a provider does not
# report usage. The DeepSeek-V4-Flash run logged no model_usage at all, so its
# output-token cost is otherwise unknown. We approximate it from the assistant
# message text (generated content + tool-call arguments; tool results are input
# and excluded). tiktoken's o200k_base is a proxy for the real tokenizer, so the
# value is approximate: for non-reasoning models it tracks real usage closely
# (validated ~1.03x on GLM-5), for reasoning models it undercounts because hidden
# reasoning tokens are not in the message text.
try:
    import tiktoken

    _ENCODER = tiktoken.get_encoding("o200k_base")
except Exception:
    _ENCODER = None


def estimate_output_tokens(messages):
    """Approximate assistant output tokens from message text. Returns None if a
    tokenizer or messages are unavailable."""
    if _ENCODER is None or not messages:
        return None
    total = 0
    for m in messages:
        if not isinstance(m, dict) or m.get("role") != "assistant":
            continue
        content = m.get("content")
        if isinstance(content, str):
            text = content
        elif isinstance(content, list):
            text = "".join(
                b.get("text", "") or "" for b in content if isinstance(b, dict)
            )
        else:
            text = ""
        total += len(_ENCODER.encode(text))
        for tc in m.get("tool_calls") or []:
            args = tc.get("arguments")
            args = args if isinstance(args, str) else json.dumps(args)
            total += len(_ENCODER.encode(str(tc.get("function", "")) + args))
    return total


def estimate_output_tokens_from_zip(z, summary):
    """Read a sample's full message list from the eval zip and estimate output
    tokens. Returns None if the messages are unavailable."""
    name = f"samples/{summary.get('id')}_epoch_{summary.get('epoch')}.json"
    try:
        full = json.loads(z.open(name).read().decode())
    except Exception:
        return None
    return estimate_output_tokens(full.get("messages"))


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
                                    # Fall back to a text-based estimate only when
                                    # the provider reported no usage (DeepSeek).
                                    if not sample.get("model_usage"):
                                        est = estimate_output_tokens_from_zip(z, sample)
                                        if est is not None:
                                            sample["_est_output_tokens"] = est
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

            # Extract model usage info.
            # model_usage is keyed by model name, e.g.
            #   {"bedrock/global.anthropic.claude-opus-4-7":
            #       {"input_tokens": N, "output_tokens": N, "total_tokens": N}}
            # so the token counts live inside the per-model entry, not at the top
            # level. There is normally exactly one entry per sample; summing the
            # values is robust if a scorer model ever adds a second entry.
            model_usage = sample.get("model_usage") or {}
            input_tokens = sum(
                (u or {}).get("input_tokens", 0) or 0 for u in model_usage.values()
            )
            output_tokens = sum(
                (u or {}).get("output_tokens", 0) or 0 for u in model_usage.values()
            )

            # When the provider logged no usage, fall back to the text estimate.
            output_tokens_estimated = False
            if not model_usage and output_tokens == 0:
                est = sample.get("_est_output_tokens")
                if est:
                    output_tokens = est
                    output_tokens_estimated = True

            sample_data = {
                "sample_id": sample_id,
                "message_count": message_count,
                "detection_score": detection_score,
                "security_reason_score": security_reason_score,
                "input_tokens": input_tokens,
                "output_tokens": output_tokens,
                "total_tokens": input_tokens + output_tokens,
                "output_tokens_estimated": output_tokens_estimated,
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
        output_token_counts = [s["output_tokens"] for s in model_samples]
        output_tokens_estimated = any(
            s.get("output_tokens_estimated") for s in model_samples
        )

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
            # Assistant output tokens only (excludes prompt/tool-result input
            # tokens). This is what the NIPS plots use for "token cost".
            "output_tokens_only": {
                "mean": (
                    sum(output_token_counts) / len(output_token_counts)
                    if output_token_counts
                    else None
                ),
                "min": min(output_token_counts) if output_token_counts else None,
                "max": max(output_token_counts) if output_token_counts else None,
            },
            # True when output tokens were estimated from text (no provider usage).
            "output_tokens_estimated": output_tokens_estimated,
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
