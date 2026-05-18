"""
Publication-quality scatter plots for NIPS paper (v3 - cleaner, more interpretable)
Retained challenge split analysis, plain prompt only
"""

import json
import zipfile
from collections import defaultdict
from pathlib import Path

import matplotlib.pyplot as plt
import numpy as np

# Publication-ready style
plt.style.use("seaborn-v0_8-whitegrid")
plt.rcParams["font.family"] = "sans-serif"
plt.rcParams["font.size"] = 10
plt.rcParams["axes.labelsize"] = 11
plt.rcParams["axes.titlesize"] = 12
plt.rcParams["xtick.labelsize"] = 10
plt.rcParams["ytick.labelsize"] = 10
plt.rcParams["legend.fontsize"] = 10
plt.rcParams["axes.linewidth"] = 1
plt.rcParams["grid.alpha"] = 0.4

# Load data
with open("nips_results_with_srr_retained_split.json") as f:
    data = json.load(f)

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
print("GENERATING NIPS-QUALITY SCATTER PLOTS (V3)")
print("=" * 80)

# ============================================================================
# 1. CWE SCATTER: Rejection Rate vs Security Reason Rate
# ============================================================================

print("\n[1/3] CWE Rejection Rate vs Security Reasoning Quality...")

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
    }

fig, ax = plt.subplots(figsize=(9, 7))
ax.set_facecolor("white")

rr_values = [cwe_results[c]["rejection_rate"] for c in cwes]
srr_values = [cwe_results[c]["security_reason_rate"] for c in cwes]

# Create gradient colors (no colorbar)
colors_val = np.array(rr_values)
colors_norm = (colors_val - colors_val.min()) / (colors_val.max() - colors_val.min())
colors = plt.cm.RdYlGn_r(colors_norm)

scatter = ax.scatter(
    rr_values,
    srr_values,
    s=280,
    alpha=0.75,
    c=colors,
    edgecolors="black",
    linewidth=1.2,
)

# Add labels with offsets
for i, cwe in enumerate(cwes):
    ax.annotate(
        cwe.upper(),
        (rr_values[i], srr_values[i]),
        xytext=(8, 8),
        textcoords="offset points",
        ha="left",
        va="bottom",
        fontsize=10,
        fontweight="bold",
        bbox=dict(
            boxstyle="round,pad=0.3", facecolor="white", alpha=0.7, edgecolor="none"
        ),
    )

ax.set_xlabel("Rejection Rate (%)", fontweight="bold")
ax.set_ylabel("Security Reasoning Rate (%)", fontweight="bold")
ax.set_title(
    "(a) CWE Vulnerability Characteristics", fontweight="bold", loc="left", pad=12
)
ax.set_xlim([20, 50])
ax.set_ylim([0, 65])
ax.grid(True, alpha=0.3, linestyle="-", linewidth=0.5)

plt.tight_layout()
plt.savefig("1_cwe_scatter.png", dpi=300, bbox_inches="tight", facecolor="white")
print("✓ Saved: 1_cwe_scatter.png")
plt.close()

# ============================================================================
# 2. MODEL SCATTER: Average Rejection Rate vs Consistency
# ============================================================================

print("[2/3] Model Robustness vs Consistency...")

models_data = {}
for model, prompts in data["per_cwe"].items():
    if "plain" not in prompts:
        continue
    if any(exc in model.lower() for exc in ["sonnet", "gpt-oss", "haiku"]):
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

    if "claude-opus" in model:
        display_name = "Opus 4.7"
        tier = "Frontier"
    elif "gpt-5.5" in model:
        display_name = "GPT-5.5"
        tier = "Frontier"
    elif "glm-5" in model:
        display_name = "GLM-5"
        tier = "Frontier"
    elif "haiku" in model:
        display_name = "Haiku"
        tier = "Baseline"
    elif "gpt-5.4" in model:
        display_name = "GPT-5.4-nano"
        tier = "Baseline"
    elif "grok" in model:
        display_name = "Grok"
        tier = "Baseline"
    elif "DeepSeek" in model:
        display_name = "DeepSeek"
        tier = "Baseline"
    elif "kimi" in model:
        display_name = "Kimi"
        tier = "Baseline"
    else:
        display_name = model[:12]
        tier = "Baseline"

    model_results[model] = {
        "display_name": display_name,
        "avg_da": 100 - avg_rr,
        "std_rr": std_rr,
        "tier": tier,
    }

fig, ax = plt.subplots(figsize=(9, 7))
ax.set_facecolor("white")

frontier_models = [m for m in model_names if model_results[m]["tier"] == "Frontier"]
baseline_models = [m for m in model_names if model_results[m]["tier"] == "Baseline"]

# Plot without legend - just color by tier
for model in frontier_models:
    r = model_results[model]
    ax.scatter(
        r["avg_da"],
        r["std_rr"],
        s=280,
        alpha=0.8,
        color="#E74C3C",
        edgecolors="black",
        linewidth=1.2,
    )

for model in baseline_models:
    r = model_results[model]
    ax.scatter(
        r["avg_da"],
        r["std_rr"],
        s=280,
        alpha=0.8,
        color="#3498DB",
        edgecolors="black",
        linewidth=1.2,
    )

# Add labels with offsets
for model in model_names:
    r = model_results[model]
    ax.annotate(
        r["display_name"],
        (r["avg_da"], r["std_rr"]),
        xytext=(6, 6),
        textcoords="offset points",
        ha="left",
        va="bottom",
        fontsize=9,
        fontweight="bold",
        bbox=dict(
            boxstyle="round,pad=0.3", facecolor="white", alpha=0.7, edgecolor="none"
        ),
    )

ax.set_xlabel("Average Detection Accuracy (%)", fontweight="bold")
ax.set_ylabel("Consistency (Std Dev, %)", fontweight="bold")
ax.set_title("(b) Model Robustness Analysis", fontweight="bold", loc="left", pad=12)
ax.grid(True, alpha=0.3, linestyle="-", linewidth=0.5)
ax.set_xlim([30, 105])

plt.tight_layout()
plt.savefig("2_model_scatter.png", dpi=300, bbox_inches="tight", facecolor="white")
print("✓ Saved: 2_model_scatter.png")
plt.close()

# ============================================================================
# 3. CWE × FRAMING SCATTER (WITH CWE LABELS)
# ============================================================================

print("[3/3] CWE-Framing Interaction Analysis...")

cwe_framing_data = defaultdict(
    lambda: defaultdict(lambda: {"caught": 0, "total": 0, "framing": ""})
)

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
                cwe_framing_data[cwe][framing]["framing"] = framing
                if detection_score == 0.0:
                    cwe_framing_data[cwe][framing]["caught"] += 1

fig, ax = plt.subplots(figsize=(12, 7))
ax.set_facecolor("white")

for cwe in cwes:
    cwe_rr = cwe_results[cwe]["rejection_rate"]

    for framing, counts in cwe_framing_data[cwe].items():
        total = counts["total"]
        if total >= 5:
            combination_rr = (counts["caught"] / total) * 100 if total > 0 else 0
            color = "#E74C3C" if combination_rr > 50 else "#3498DB"
            ax.scatter(
                cwe_rr,
                combination_rr,
                s=total * 2.5,
                alpha=0.65,
                color=color,
                edgecolors="black",
                linewidth=0.5,
            )

# Add CWE labels at the top of the plot (alternating up and down)
cwes_sorted = sorted(cwes, key=lambda c: cwe_results[c]["rejection_rate"])
for i, cwe in enumerate(cwes_sorted):
    cwe_rr = cwe_results[cwe]["rejection_rate"]
    # Alternate between high and low positions: even indices up, odd indices down
    y_pos = 110 if i % 2 == 0 else 95
    ax.annotate(
        cwe.upper(),
        xy=(cwe_rr, y_pos),
        fontsize=8,
        ha="center",
        fontweight="bold",
        bbox=dict(
            boxstyle="round,pad=0.3",
            facecolor="lightyellow",
            alpha=0.7,
            edgecolor="none",
        ),
    )
    # Add faint vertical line
    ax.axvline(x=cwe_rr, color="gray", linestyle=":", alpha=0.2, linewidth=0.8)

ax.set_xlabel("CWE Difficulty (Baseline Rejection Rate, %)", fontweight="bold")
ax.set_ylabel("CWE-Framing Attack Success Rate (%)", fontweight="bold")
ax.set_title(
    "(c) Social Engineering Effectiveness Varies by Vulnerability",
    fontweight="bold",
    loc="left",
    pad=12,
)
ax.grid(True, alpha=0.3, linestyle="-", linewidth=0.5)
ax.set_xlim([20, 50])
ax.set_ylim([0, 120])

# Add reference lines
ax.axhline(y=50, color="gray", linestyle="--", alpha=0.4, linewidth=1)

# Add legend
from matplotlib.patches import Patch

legend_elements = [
    Patch(
        facecolor="#E74C3C",
        edgecolor="black",
        alpha=0.65,
        label="High effectiveness (>50%)",
    ),
    Patch(
        facecolor="#3498DB",
        edgecolor="black",
        alpha=0.65,
        label="Low effectiveness (≤50%)",
    ),
]
ax.legend(handles=legend_elements, loc="lower left", framealpha=0.95, fontsize=9)

# Add interpretation text
textstr = "Interpretation: CWE labels at top indicate where that vulnerability's\nattacks are plotted. Points at same x-position are different framings\nof the same CWE. Harder CWEs (right) show more red (higher success rates),\nindicating social engineering is more effective on difficult vulnerabilities."
props = dict(boxstyle="round", facecolor="wheat", alpha=0.8)
ax.text(
    0.98,
    0.35,
    textstr,
    transform=ax.transAxes,
    fontsize=8.5,
    verticalalignment="top",
    horizontalalignment="right",
    bbox=props,
)

plt.tight_layout()
plt.savefig(
    "3_cwe_framing_scatter.png", dpi=300, bbox_inches="tight", facecolor="white"
)
print("✓ Saved: 3_cwe_framing_scatter.png")
plt.close()

print("\n" + "=" * 80)
print("✓ NIPS PUBLICATION PLOTS (V3) COMPLETE")
print("=" * 80)
print("\nChanges in V3:")
print("  • Plot 1: Removed colorbar, white background (cleaner look)")
print("  • Plot 2: Removed Frontier/Baseline legend (colors speak for themselves)")
print("  • Plot 3: Added CWE labels at top to identify each vulnerability's region")
print("           Added vertical lines and improved interpretation text")
print("=" * 80)
