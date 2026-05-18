"""
Generate scatter plots for retained challenge split analysis
Plain prompt only, with rejection rate metric
"""

import json
import zipfile
from collections import defaultdict
from pathlib import Path

import matplotlib.pyplot as plt
import numpy as np

# Load JSON data
with open("nips_results_with_srr_retained_split.json") as f:
    data = json.load(f)

# Load retained sample IDs
with open("retained_sample_ids.json") as f:
    retained_ids_by_cwe = json.load(f)

cwes = [
    "cwe79",
    "cwe89",
    "cwe352",
    "cwe862",
    "cwe787",
    "cwe22",
    "cwe416",
    "cwe125",
    "cwe78",
    "cwe94",
]

print("=" * 80)
print("GENERATING SCATTER PLOTS (PLAIN PROMPT ONLY)")
print("=" * 80)

# ============================================================================
# 1. CWE SCATTER: Rejection Rate vs Security Reason Rate
# ============================================================================

print("\n[1/3] Generating CWE Scatter (Rejection Rate vs Security Reason Rate)...")

cwe_metrics = {}
for cwe in cwes:
    cwe_metrics[cwe] = {
        "da_caught": 0,
        "da_missed": 0,
        "da_total": 0,
        "srr_caught": 0,
        "srr_missed": 0,
        "srr_total": 0,
    }

for model, prompts in data["per_cwe"].items():
    if "plain" not in prompts:
        continue

    for cwe, metrics in prompts["plain"].items():
        if cwe not in cwe_metrics:
            continue

        da = metrics["detection_accuracy"]
        if da["accuracy"] is not None:
            cwe_metrics[cwe]["da_caught"] += da["accuracy"] * da["n_samples"] / 100
            cwe_metrics[cwe]["da_missed"] += (
                (100 - da["accuracy"]) * da["n_samples"] / 100
            )
            cwe_metrics[cwe]["da_total"] += da["n_samples"]

        srr = metrics["security_reason_rate"]
        if srr["accuracy"] is not None:
            cwe_metrics[cwe]["srr_caught"] += srr["accuracy"] * srr["n_samples"] / 100
            cwe_metrics[cwe]["srr_missed"] += (
                (100 - srr["accuracy"]) * srr["n_samples"] / 100
            )
            cwe_metrics[cwe]["srr_total"] += srr["n_samples"]

cwe_results = {}
for cwe in cwes:
    counts = cwe_metrics[cwe]
    da_acc = (
        (counts["da_caught"] / counts["da_total"] * 100)
        if counts["da_total"] > 0
        else 0
    )
    srr_acc = (
        (counts["srr_caught"] / counts["srr_total"] * 100)
        if counts["srr_total"] > 0
        else 0
    )

    cwe_results[cwe] = {
        "rejection_rate": 100 - da_acc,
        "security_reason_rate": srr_acc,
        "n_samples": counts["da_total"],
    }

fig, ax = plt.subplots(figsize=(12, 8))

rr_values = [cwe_results[c]["rejection_rate"] for c in cwes]
srr_values = [cwe_results[c]["security_reason_rate"] for c in cwes]

scatter = ax.scatter(
    rr_values,
    srr_values,
    s=300,
    alpha=0.7,
    c=rr_values,
    cmap="RdYlGn_r",
    edgecolors="black",
    linewidth=1.5,
)

for i, cwe in enumerate(cwes):
    ax.annotate(
        cwe.upper(),
        (rr_values[i], srr_values[i]),
        ha="center",
        va="center",
        fontsize=11,
        fontweight="bold",
        color="black",
    )

ax.set_xlabel("Rejection Rate (%)", fontsize=12, fontweight="bold")
ax.set_ylabel("Security Reason Rate (%)", fontsize=12, fontweight="bold")
ax.set_title(
    "CWE Scatter: Rejection Rate vs Security Reason Rate\n(Plain Prompt, Retained Challenge Split)",
    fontsize=14,
    fontweight="bold",
)
ax.grid(True, alpha=0.3)
ax.set_xlim([20, 50])
ax.set_ylim([0, 65])

cbar = plt.colorbar(scatter, ax=ax)
cbar.set_label("Rejection Rate (%)", fontsize=11, fontweight="bold")

# Add quadrant lines
ax.axhline(y=np.mean(srr_values), color="gray", linestyle="--", alpha=0.5, linewidth=1)
ax.axvline(x=np.mean(rr_values), color="gray", linestyle="--", alpha=0.5, linewidth=1)

plt.tight_layout()
plt.savefig("1_cwe_scatter_rr_vs_srr.png", dpi=150, bbox_inches="tight")
print("✓ Saved: 1_cwe_scatter_rr_vs_srr.png")
plt.close()

# ============================================================================
# 2. MODEL SCATTER: Average Rejection Rate vs Consistency
# ============================================================================

print("[2/3] Generating Model Scatter (Robustness vs Consistency)...")

models_data = {}
for model, prompts in data["per_cwe"].items():
    if "plain" not in prompts:
        continue

    # Skip Sonnet and GPT-OSS
    if any(exc in model.lower() for exc in ["sonnet", "gpt-oss"]):
        continue

    cwe_rejection_rates = []
    for cwe in cwes:
        if cwe in prompts["plain"]:
            da_acc = prompts["plain"][cwe]["detection_accuracy"]["accuracy"]
            rr = 100 - da_acc if da_acc is not None else 50
            cwe_rejection_rates.append(rr)
        else:
            cwe_rejection_rates.append(50)

    models_data[model] = cwe_rejection_rates

model_names = sorted(models_data.keys())
model_results = {}

for model in model_names:
    rr_values = models_data[model]
    avg_rr = np.mean(rr_values)
    std_rr = np.std(rr_values)

    # Get display name
    if "claude-opus" in model:
        display_name = "Opus 4.7"
        tier = "Frontier"
    elif "gpt-5.5" in model:
        display_name = "GPT-5.5"
        tier = "Frontier"
    elif "haiku" in model:
        display_name = "Haiku 4.5"
        tier = "Baseline"
    elif "gpt-5.4" in model:
        display_name = "GPT-5.4-nano"
        tier = "Baseline"
    elif "grok" in model:
        display_name = "Grok"
        tier = "Baseline"
    elif "glm-5" in model:
        display_name = "GLM-5"
        tier = "Frontier"
    elif "DeepSeek" in model:
        display_name = "DeepSeek"
        tier = "Baseline"
    elif "kimi" in model:
        display_name = "Kimi K2.5"
        tier = "Baseline"
    else:
        display_name = model[:15]
        tier = "Baseline"

    model_results[model] = {
        "display_name": display_name,
        "avg_rr": avg_rr,
        "std_rr": std_rr,
        "tier": tier,
    }

fig, ax = plt.subplots(figsize=(12, 8))

frontier_models = [m for m in model_names if model_results[m]["tier"] == "Frontier"]
baseline_models = [m for m in model_names if model_results[m]["tier"] == "Baseline"]

# Plot Frontier models (red)
for model in frontier_models:
    r = model_results[model]
    ax.scatter(
        r["avg_rr"],
        r["std_rr"],
        s=300,
        alpha=0.8,
        color="#FF6B6B",
        edgecolors="black",
        linewidth=1.5,
        label="Frontier" if model == frontier_models[0] else "",
    )

# Plot Baseline models (blue)
for model in baseline_models:
    r = model_results[model]
    ax.scatter(
        r["avg_rr"],
        r["std_rr"],
        s=300,
        alpha=0.8,
        color="#4ECDC4",
        edgecolors="black",
        linewidth=1.5,
        label="Baseline" if model == baseline_models[0] else "",
    )

# Annotate all models
for model in model_names:
    r = model_results[model]
    ax.annotate(
        r["display_name"],
        (r["avg_rr"], r["std_rr"]),
        ha="center",
        va="center",
        fontsize=9,
        fontweight="bold",
    )

ax.set_xlabel("Average Rejection Rate (%)", fontsize=12, fontweight="bold")
ax.set_ylabel("Consistency (Std Dev of RR across CWEs)", fontsize=12, fontweight="bold")
ax.set_title(
    "Model Robustness: Detection Accuracy vs Consistency\n(Plain Prompt, Retained Challenge Split)",
    fontsize=14,
    fontweight="bold",
)
ax.grid(True, alpha=0.3)
ax.legend(fontsize=11, loc="upper right")

plt.tight_layout()
plt.savefig("3_model_scatter.png", dpi=150, bbox_inches="tight")
print("✓ Saved: 3_model_scatter.png")
plt.close()

# ============================================================================
# 3. CWE × FRAMING SCATTER
# ============================================================================

print("[3/3] Generating CWE × Framing Scatter...")

cwe_framing_data = defaultdict(lambda: defaultdict(lambda: {"caught": 0, "total": 0}))

results_dirs = [
    Path("logs/results_nips"),
    Path("logs/filtering_releases"),
]

for results_dir in results_dirs:
    if not results_dir.exists():
        continue

    for dir_path in sorted(results_dir.glob("*_gitea_plain_cwe*")):
        if not dir_path.is_dir():
            continue

        parts = dir_path.name.split("_gitea_")
        if len(parts) < 2:
            continue

        rest = "_gitea_".join(parts[1:])
        if "_cwe" not in rest:
            continue

        prompt_parts = rest.split("_cwe")
        cwe = f"cwe{prompt_parts[1].split('_')[0]}"

        if cwe not in cwes:
            continue

        eval_files = list(dir_path.glob("*.eval"))
        if not eval_files:
            continue

        samples_by_id = {}
        for eval_file in sorted(eval_files):
            try:
                with zipfile.ZipFile(eval_file) as z:
                    for name in z.namelist():
                        if "_journal/summaries" in name and name.endswith(".json"):
                            with z.open(name) as f:
                                samples = json.loads(f.read().decode())
                                for sample in samples:
                                    sid = sample.get("id", "")
                                    if sid:
                                        samples_by_id[sid] = sample
            except:
                continue

        for sample in samples_by_id.values():
            if "scores" not in sample:
                continue

            sample_id = sample.get("id")
            if sample_id not in retained_ids_by_cwe.get(cwe, []):
                continue

            parts = sample_id.split("-")
            if len(parts) < 3:
                continue

            framing = parts[-1]
            if framing == "partial_test_coverage":
                continue

            detection_score = (
                sample["scores"].get("detection_scorer", {}).get("value", None)
            )

            if detection_score is not None:
                cwe_framing_data[cwe][framing]["total"] += 1
                if detection_score == 0.0:
                    cwe_framing_data[cwe][framing]["caught"] += 1

# Create scatter plot
fig, ax = plt.subplots(figsize=(14, 8))

for cwe in cwes:
    cwe_rr = cwe_results[cwe]["rejection_rate"]

    for framing, counts in cwe_framing_data[cwe].items():
        total = counts["total"]
        if total >= 5:  # Minimum sample threshold
            combination_rr = (counts["caught"] / total) * 100 if total > 0 else 0

            color = "#FF6B6B" if combination_rr > 50 else "#4ECDC4"
            ax.scatter(
                cwe_rr,
                combination_rr,
                s=total * 3,
                alpha=0.6,
                color=color,
                edgecolors="black",
                linewidth=0.5,
            )

# Add CWE labels on x-axis regions
for cwe in cwes:
    cwe_rr = cwe_results[cwe]["rejection_rate"]
    ax.axvline(x=cwe_rr, color="gray", linestyle=":", alpha=0.2, linewidth=0.8)

ax.set_xlabel("CWE Difficulty (Rejection Rate, %)", fontsize=12, fontweight="bold")
ax.set_ylabel(
    "CWE-Framing Combination Rejection Rate (%)", fontsize=12, fontweight="bold"
)
ax.set_title(
    "CWE × Framing Interactions: Rejection Rate by Difficulty\n(Plain Prompt, Retained Challenge Split, bubble size=sample count)",
    fontsize=14,
    fontweight="bold",
)
ax.grid(True, alpha=0.3)
ax.set_xlim([20, 50])
ax.set_ylim([0, 105])

plt.tight_layout()
plt.savefig("5_cwe_framing_scatter.png", dpi=150, bbox_inches="tight")
print("✓ Saved: 5_cwe_framing_scatter.png")
plt.close()

print("\n" + "=" * 80)
print("✓ ALL SCATTER PLOTS GENERATED")
print("=" * 80)
print("\nGenerated plots:")
print("  1_cwe_scatter_rr_vs_srr.png     - CWE difficulty vs reasoning quality")
print("  3_model_scatter.png              - Model robustness vs consistency")
print("  5_cwe_framing_scatter.png        - CWE-framing interactions by difficulty")
print("=" * 80)
