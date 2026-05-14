#!/usr/bin/env python3
"""
Extract NIPS results with both Detection Accuracy (DA) and Security Reason Rate (SRR).
Generates per-CWE and per-framing tables for both metrics.
Includes both frontier models (results_nips) and baseline/filtering models (filtering_releases).

Usage:
  python3 extract_nips_results_with_srr.py          # Extract all samples
  python3 extract_nips_results_with_srr.py --retained  # Filter to retained challenge split
"""
import glob
import json
import math
import sys
import zipfile
from collections import defaultdict
from pathlib import Path


def compute_standard_error(accuracy, n):
    """Compute standard error of detection rate: sqrt(p(1-p)/n)"""
    if accuracy is None or n == 0:
        return None
    p = accuracy / 100.0
    se = math.sqrt(p * (1 - p) / n)
    return round(se * 100, 2)


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

# Results structure: model -> prompt -> cwe -> framing -> {detection, security_reason}
results = defaultdict(
    lambda: defaultdict(
        lambda: defaultdict(
            lambda: defaultdict(
                lambda: {
                    "detection": {"caught": 0, "missed": 0, "total": 0},
                    "security_reason": {"caught": 0, "missed": 0, "total": 0},
                }
            )
        )
    )
)

# Scan both results_nips and filtering_releases directories
results_dirs = [
    Path("../../logs/results_nips"),
    Path("../../logs/filtering_releases"),
]

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

            # Detection score
            detection_score = (
                sample["scores"].get("detection_scorer", {}).get("value", None)
            )

            # Security reason score
            security_reason_score = (
                sample["scores"].get("security_reason_scorer", {}).get("value", None)
            )

            # Process detection score
            if detection_score == 1.0:
                results[model_name][prompt][cwe][framing]["detection"]["caught"] += 1
                results[model_name][prompt][cwe][framing]["detection"]["total"] += 1
            elif detection_score == 0.0:
                results[model_name][prompt][cwe][framing]["detection"]["missed"] += 1
                results[model_name][prompt][cwe][framing]["detection"]["total"] += 1

            # Process security reason score
            if security_reason_score == 1.0:
                results[model_name][prompt][cwe][framing]["security_reason"][
                    "caught"
                ] += 1
                results[model_name][prompt][cwe][framing]["security_reason"][
                    "total"
                ] += 1
            elif security_reason_score == 0.0:
                results[model_name][prompt][cwe][framing]["security_reason"][
                    "missed"
                ] += 1
                results[model_name][prompt][cwe][framing]["security_reason"][
                    "total"
                ] += 1

# ============================================================================
# AGGREGATE AND GENERATE TABLES
# ============================================================================

# Per-CWE results
cwe_results = defaultdict(
    lambda: defaultdict(
        lambda: defaultdict(
            lambda: {
                "detection": {"caught": 0, "missed": 0, "total": 0},
                "security_reason": {"caught": 0, "missed": 0, "total": 0},
            }
        )
    )
)

for model_name, prompts in results.items():
    for prompt, cwes in prompts.items():
        for cwe, framings in cwes.items():
            for framing, counts in framings.items():
                cwe_results[model_name][prompt][cwe]["detection"]["caught"] += counts[
                    "detection"
                ]["caught"]
                cwe_results[model_name][prompt][cwe]["detection"]["missed"] += counts[
                    "detection"
                ]["missed"]
                cwe_results[model_name][prompt][cwe]["detection"]["total"] += counts[
                    "detection"
                ]["total"]

                cwe_results[model_name][prompt][cwe]["security_reason"][
                    "caught"
                ] += counts["security_reason"]["caught"]
                cwe_results[model_name][prompt][cwe]["security_reason"][
                    "missed"
                ] += counts["security_reason"]["missed"]
                cwe_results[model_name][prompt][cwe]["security_reason"][
                    "total"
                ] += counts["security_reason"]["total"]

# Per-framing results
framing_results = defaultdict(
    lambda: defaultdict(
        lambda: {
            "detection": {"caught": 0, "missed": 0, "total": 0},
            "security_reason": {"caught": 0, "missed": 0, "total": 0},
        }
    )
)

for model_name, prompts in results.items():
    for prompt, cwes in prompts.items():
        for cwe, framings in cwes.items():
            for framing, counts in framings.items():
                framing_results[model_name][framing]["detection"]["caught"] += counts[
                    "detection"
                ]["caught"]
                framing_results[model_name][framing]["detection"]["missed"] += counts[
                    "detection"
                ]["missed"]
                framing_results[model_name][framing]["detection"]["total"] += counts[
                    "detection"
                ]["total"]

                framing_results[model_name][framing]["security_reason"][
                    "caught"
                ] += counts["security_reason"]["caught"]
                framing_results[model_name][framing]["security_reason"][
                    "missed"
                ] += counts["security_reason"]["missed"]
                framing_results[model_name][framing]["security_reason"][
                    "total"
                ] += counts["security_reason"]["total"]

# Save results as JSON
if use_retained_split:
    output_path = Path("../../nips_results_with_srr_retained_split.json")
else:
    output_path = Path("../../nips_results_with_srr.json")
output_data = {"per_cwe": {}, "per_framing": {}}

# Per-CWE
for model, prompts in cwe_results.items():
    output_data["per_cwe"][model] = {}
    for prompt, cwes in prompts.items():
        output_data["per_cwe"][model][prompt] = {}
        for cwe, metrics in cwes.items():
            output_data["per_cwe"][model][prompt][cwe] = {}

            # Detection
            da_caught = metrics["detection"]["caught"]
            da_missed = metrics["detection"]["missed"]
            da_total = da_caught + da_missed
            da_acc = (da_caught / da_total * 100) if da_total > 0 else None
            da_se = compute_standard_error(da_acc, da_total) if da_total > 0 else None

            # Security Reason
            srr_caught = metrics["security_reason"]["caught"]
            srr_missed = metrics["security_reason"]["missed"]
            srr_total = srr_caught + srr_missed
            srr_acc = (srr_caught / srr_total * 100) if srr_total > 0 else None
            srr_se = (
                compute_standard_error(srr_acc, srr_total) if srr_total > 0 else None
            )

            output_data["per_cwe"][model][prompt][cwe]["detection_accuracy"] = {
                "accuracy": round(da_acc, 1) if da_acc else None,
                "standard_error": da_se,
                "n_samples": da_total,
            }
            output_data["per_cwe"][model][prompt][cwe]["security_reason_rate"] = {
                "accuracy": round(srr_acc, 1) if srr_acc else None,
                "standard_error": srr_se,
                "n_samples": srr_total,
            }

# Per-framing
for model, framings in framing_results.items():
    output_data["per_framing"][model] = {}
    for framing, metrics in framings.items():
        # Detection
        da_caught = metrics["detection"]["caught"]
        da_missed = metrics["detection"]["missed"]
        da_total = da_caught + da_missed
        da_acc = (da_caught / da_total * 100) if da_total > 0 else None
        da_se = compute_standard_error(da_acc, da_total) if da_total > 0 else None

        # Security Reason
        srr_caught = metrics["security_reason"]["caught"]
        srr_missed = metrics["security_reason"]["missed"]
        srr_total = srr_caught + srr_missed
        srr_acc = (srr_caught / srr_total * 100) if srr_total > 0 else None
        srr_se = compute_standard_error(srr_acc, srr_total) if srr_total > 0 else None

        output_data["per_framing"][model][framing] = {
            "detection_accuracy": {
                "accuracy": round(da_acc, 1) if da_acc else None,
                "standard_error": da_se,
                "n_samples": da_total,
            },
            "security_reason_rate": {
                "accuracy": round(srr_acc, 1) if srr_acc else None,
                "standard_error": srr_se,
                "n_samples": srr_total,
            },
        }

with open(output_path, "w") as f:
    json.dump(output_data, f, indent=2)

mode = "RETAINED SPLIT" if use_retained_split else "ALL DATA"
print(f"✓ Saved per-CWE and per-framing results ({mode}) to {output_path}")
