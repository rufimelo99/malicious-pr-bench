#!/usr/bin/env python3
"""
Generate visualizations for message count analysis.
Shows reasoning depth: how many back-and-forth messages each model needed.

Generates:
1. Message Count vs Detection Accuracy (scatter plot)
2. Message Count Distribution by CWE (box plot)
3. Message Count by Framing (bar plot)
"""
import json
from collections import defaultdict
from pathlib import Path

import matplotlib.pyplot as plt
import seaborn as sns

# Load data
data_path = Path("../message_counts_retained_split.json")
with open(data_path) as f:
    data = json.load(f)

# Setup plotting style
sns.set_theme(style="whitegrid")
plt.rcParams["figure.dpi"] = 300
plt.rcParams["savefig.dpi"] = 300
plt.rcParams["font.size"] = 10

# Model display names (clean)
model_display_names = {
    "bedrock_global.anthropic.claude-opus-4-7": "Opus 4.7",
    "bedrock_global.anthropic.claude-sonnet-4-6": "Sonnet 4.6",
    "bedrock_openai.gpt-oss-120b-1:0:": "GPT-OSS-120B",
    "bedrock_moonshotai.kimi-k2.5": "Kimi",
    "bedrock_zai.glm-5": "GLM-5",
    "bedrock_us.anthropic.claude-haiku-4-5-20251001-v1:0:": "Haiku",
    "openai_azure_gpt-5.5": "GPT-5.5",
    "openai_azure_gpt-5.4-nano": "GPT-5.4-nano",
    "openai_azure_DeepSeek-V4-Flash": "DeepSeek",
    "openai_azure_grok-code-fast-1": "Grok",
}

# Model categories
frontier_models = {"Opus 4.7", "Sonnet 4.6", "GPT-5.5", "GLM-5"}
baseline_models = {"GPT-5.4-nano", "Grok", "Kimi", "DeepSeek", "Haiku", "GPT-OSS-120B"}

# ============================================================================
# PLOT 1: Message Count vs Detection Accuracy
# ============================================================================
fig, ax = plt.subplots(figsize=(10, 6))

models_to_plot = []
message_counts = []
accuracies = []
colors_list = []

for model_name, stats in data["per_model"].items():
    display_name = model_display_names.get(model_name, model_name)
    if stats["detection_accuracy"]["accuracy"] is None:
        continue

    models_to_plot.append(display_name)
    message_counts.append(stats["message_count"]["mean"])
    accuracies.append(stats["detection_accuracy"]["accuracy"])

    # Color by model type
    if display_name in frontier_models:
        colors_list.append("#D62728")  # Red for frontier
    else:
        colors_list.append("#1F77B4")  # Blue for baseline

# Create scatter plot
ax.scatter(
    message_counts,
    accuracies,
    s=200,
    c=colors_list,
    alpha=0.7,
    edgecolors="black",
    linewidth=1.5,
)

# Add model labels
for i, model in enumerate(models_to_plot):
    ax.annotate(
        model,
        (message_counts[i], accuracies[i]),
        xytext=(8, 8),
        textcoords="offset points",
        fontsize=9,
        bbox=dict(
            boxstyle="round,pad=0.3", facecolor="white", edgecolor="gray", alpha=0.8
        ),
    )

ax.set_xlabel(
    "Average Message Count (Back-and-Forth Messages)", fontsize=11, fontweight="bold"
)
ax.set_ylabel("Detection Accuracy (%)", fontsize=11, fontweight="bold")
ax.set_title(
    "Reasoning Depth vs Accuracy: How Many Messages Needed?",
    fontsize=12,
    fontweight="bold",
)
ax.grid(True, alpha=0.3)
ax.set_ylim(30, 105)
ax.set_xlim(0, 40)

# Add legend
from matplotlib.patches import Patch

legend_elements = [
    Patch(facecolor="#D62728", edgecolor="black", label="Frontier Models"),
    Patch(facecolor="#1F77B4", edgecolor="black", label="Baseline Models"),
]
ax.legend(handles=legend_elements, loc="lower right", fontsize=10)

plt.tight_layout()
plt.savefig(
    "6_message_count_accuracy.png", dpi=300, bbox_inches="tight", facecolor="white"
)
print("✓ Saved 6_message_count_accuracy.png")
plt.close()

# ============================================================================
# PLOT 2: Message Count Distribution by CWE
# ============================================================================
fig, ax = plt.subplots(figsize=(14, 6))

# Organize message counts by CWE
cwe_message_data = defaultdict(list)
for model_name, prompts in data["raw_samples"].items():
    for prompt, cwes in prompts.items():
        if prompt != "plain":
            continue
        for cwe, framings in cwes.items():
            for framing, samples in framings.items():
                for sample in samples:
                    cwe_message_data[cwe].append(sample["message_count"])

# Sort CWEs
cwes_sorted = sorted(cwe_message_data.keys())
cwe_data_list = [cwe_message_data[cwe] for cwe in cwes_sorted]

# Create box plot
bp = ax.boxplot(
    cwe_data_list,
    labels=cwes_sorted,
    patch_artist=True,
    widths=0.6,
)

# Color boxes
for patch in bp["boxes"]:
    patch.set_facecolor("#87CEEB")
    patch.set_alpha(0.7)

ax.set_xlabel("CWE Class", fontsize=11, fontweight="bold")
ax.set_ylabel("Message Count", fontsize=11, fontweight="bold")
ax.set_title("Reasoning Depth by Vulnerability Class", fontsize=12, fontweight="bold")
ax.grid(True, alpha=0.3, axis="y")

plt.tight_layout()
plt.savefig(
    "7_message_count_by_cwe.png", dpi=300, bbox_inches="tight", facecolor="white"
)
print("✓ Saved 7_message_count_by_cwe.png")
plt.close()

# ============================================================================
# PLOT 3: Message Count Distribution Comparison (Frontier vs Baseline)
# ============================================================================
fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(14, 5))

frontier_messages = []
baseline_messages = []

for model_name, prompts in data["raw_samples"].items():
    display_name = model_display_names.get(model_name, model_name)
    if display_name not in frontier_models and display_name not in baseline_models:
        continue

    for prompt, cwes in prompts.items():
        if prompt != "plain":
            continue
        for cwe, framings in cwes.items():
            for framing, samples in framings.items():
                for sample in samples:
                    if display_name in frontier_models:
                        frontier_messages.append(sample["message_count"])
                    else:
                        baseline_messages.append(sample["message_count"])

# Frontier box plot
bp1 = ax1.boxplot(
    [frontier_messages],
    labels=["Frontier Models"],
    patch_artist=True,
    widths=0.5,
)
for patch in bp1["boxes"]:
    patch.set_facecolor("#D62728")
    patch.set_alpha(0.7)

ax1.set_ylabel("Message Count", fontsize=11, fontweight="bold")
ax1.set_title("Frontier Models: Reasoning Depth", fontsize=11, fontweight="bold")
ax1.grid(True, alpha=0.3, axis="y")
ax1.set_ylim(0, 100)

# Baseline box plot
bp2 = ax2.boxplot(
    [baseline_messages],
    labels=["Baseline Models"],
    patch_artist=True,
    widths=0.5,
)
for patch in bp2["boxes"]:
    patch.set_facecolor("#1F77B4")
    patch.set_alpha(0.7)

ax2.set_ylabel("Message Count", fontsize=11, fontweight="bold")
ax2.set_title("Baseline Models: Reasoning Depth", fontsize=11, fontweight="bold")
ax2.grid(True, alpha=0.3, axis="y")
ax2.set_ylim(0, 100)

plt.tight_layout()
plt.savefig(
    "8_message_count_distribution.png", dpi=300, bbox_inches="tight", facecolor="white"
)
print("✓ Saved 8_message_count_distribution.png")
plt.close()

# ============================================================================
# SUMMARY STATISTICS
# ============================================================================
print("\n" + "=" * 70)
print("MESSAGE COUNT ANALYSIS SUMMARY")
print("=" * 70)

print("\nFrontier Models (High Accuracy):")
for model_name in sorted(data["per_model"].keys()):
    display_name = model_display_names.get(model_name, model_name)
    if display_name not in frontier_models:
        continue
    stats = data["per_model"][model_name]
    print(
        f"  {display_name:20} | Messages: {stats['message_count']['mean']:6.2f} | Accuracy: {stats['detection_accuracy']['accuracy']:6.1f}%"
    )

print("\nBaseline Models (Lower Accuracy):")
for model_name in sorted(data["per_model"].keys()):
    display_name = model_display_names.get(model_name, model_name)
    if display_name not in baseline_models:
        continue
    stats = data["per_model"][model_name]
    print(
        f"  {display_name:20} | Messages: {stats['message_count']['mean']:6.2f} | Accuracy: {stats['detection_accuracy']['accuracy']:6.1f}%"
    )

print("\n" + "=" * 70)
print("Key Insights:")
print("=" * 70)
print(
    f"Frontier avg messages: {sum(data['per_model'][m]['message_count']['mean'] for m in data['per_model'] if model_display_names.get(m) in frontier_models) / 4:.2f}"
)
print(
    f"Baseline avg messages: {sum(data['per_model'][m]['message_count']['mean'] for m in data['per_model'] if model_display_names.get(m) in baseline_models) / len([m for m in data['per_model'] if model_display_names.get(m) in baseline_models]):.2f}"
)
print(
    "\nInference: Frontier models need fewer average messages despite higher accuracy."
)
print("          This suggests more efficient reasoning, not just more effort.")
