"""
Complete Visualization Suite for Retained Challenge Split Analysis
Generates all clustering, difficulty, and effectiveness visualizations
"""

import json
import math
import warnings
import zipfile
from collections import defaultdict
from pathlib import Path

import matplotlib.pyplot as plt
import numpy as np
import seaborn as sns
from scipy.cluster.hierarchy import dendrogram, linkage, fcluster
from scipy.spatial.distance import pdist
from sklearn.decomposition import PCA
from sklearn.preprocessing import StandardScaler

warnings.filterwarnings("ignore")
sns.set_style("whitegrid")

print("=" * 80)
print("COMPREHENSIVE VISUALIZATION GENERATION - RETAINED CHALLENGE SPLIT")
print("=" * 80)

# ============================================================================
# LOAD DATA
# ============================================================================

with open("nips_results_with_srr_retained_split.json") as f:
    data = json.load(f)

retained_path = Path("retained_sample_ids.json")
with open(retained_path) as f:
    retained_ids_by_cwe = json.load(f)

cwes = ["cwe79", "cwe89", "cwe352", "cwe862", "cwe787", "cwe22", "cwe416", "cwe125", "cwe78", "cwe94"]

# ============================================================================
# 1. CWE & FRAMING CLUSTERING (4-panel)
# ============================================================================

print("\n[1/5] Generating CWE & Framing Clustering...")

cwe_metrics = {}
for model, prompts in data["per_cwe"].items():
    for prompt, cwes_dict in prompts.items():
        for cwe, metrics in cwes_dict.items():
            if cwe not in cwe_metrics:
                cwe_metrics[cwe] = {"da_caught": 0, "da_missed": 0, "da_total": 0, "srr_caught": 0, "srr_missed": 0, "srr_total": 0}
            
            da = metrics["detection_accuracy"]
            if da["accuracy"] is not None:
                cwe_metrics[cwe]["da_caught"] += da["accuracy"] * da["n_samples"] / 100
                cwe_metrics[cwe]["da_missed"] += (100 - da["accuracy"]) * da["n_samples"] / 100
                cwe_metrics[cwe]["da_total"] += da["n_samples"]

cwe_results = {}
for cwe, counts in cwe_metrics.items():
    da_acc = (counts["da_caught"] / counts["da_total"] * 100) if counts["da_total"] > 0 else 0
    cwe_results[cwe] = {
        "rejection_rate": 100 - da_acc,
    }

features_cwe = np.array([[cwe_results[cwe]["rejection_rate"]] for cwe in cwes])
scaler_cwe = StandardScaler()
features_cwe_scaled = scaler_cwe.fit_transform(features_cwe)
distances_cwe = pdist(features_cwe_scaled, metric="euclidean")
linkage_cwe = linkage(distances_cwe, method="ward")
pca_cwe = PCA(n_components=2)
features_cwe_pca = pca_cwe.fit_transform(features_cwe_scaled)

framing_metrics = {}
for model, framings in data["per_framing"].items():
    for framing, metrics in framings.items():
        if framing not in framing_metrics:
            framing_metrics[framing] = {"da_caught": 0, "da_missed": 0, "da_total": 0}
        
        da = metrics["detection_accuracy"]
        framing_metrics[framing]["da_caught"] += da["accuracy"] * da["n_samples"] / 100
        framing_metrics[framing]["da_missed"] += (100 - da["accuracy"]) * da["n_samples"] / 100
        framing_metrics[framing]["da_total"] += da["n_samples"]

framing_results = {}
for framing, counts in framing_metrics.items():
    da_acc = (counts["da_caught"] / counts["da_total"] * 100) if counts["da_total"] > 0 else 0
    framing_results[framing] = {"rejection_rate": 100 - da_acc}

framings = sorted(framing_results.keys())
features_framing = np.array([[framing_results[f]["rejection_rate"], 1.0] for f in framings])
scaler_framing = StandardScaler()
features_framing_scaled = scaler_framing.fit_transform(features_framing)
distances_framing = pdist(features_framing_scaled, metric="euclidean")
linkage_framing = linkage(distances_framing, method="ward")
pca_framing = PCA(n_components=2)
features_framing_pca = pca_framing.fit_transform(features_framing_scaled)

fig, axes = plt.subplots(2, 2, figsize=(16, 12))
fig.suptitle("CWE and Framing Clustering Analysis (Retained Challenge Split)\nUsing Rejection Rate Metric", 
             fontsize=14, fontweight="bold", y=0.995)

ax = axes[0, 0]
dendrogram(linkage_cwe, labels=[c.upper() for c in cwes], ax=ax)
ax.set_title("CWE Hierarchical Clustering", fontweight="bold", fontsize=12)
ax.set_xlabel("CWE")
ax.set_ylabel("Distance (Ward Linkage)")
ax.grid(axis="y", alpha=0.3)

ax = axes[0, 1]
scatter = ax.scatter(features_cwe_pca[:, 0], features_cwe_pca[:, 1], s=250, alpha=0.6, c=features_cwe[:, 0], cmap="RdYlGn_r")
for i, cwe in enumerate(cwes):
    ax.annotate(cwe.upper(), (features_cwe_pca[i, 0], features_cwe_pca[i, 1]), 
                ha="center", va="center", fontweight="bold", fontsize=10)
ax.set_xlabel(f"PC1 ({pca_cwe.explained_variance_ratio_[0]:.1%} variance)")
ax.set_ylabel(f"PC2 ({pca_cwe.explained_variance_ratio_[1]:.1%} variance)")
ax.set_title("CWE PCA Projection", fontweight="bold", fontsize=12)
cbar = plt.colorbar(scatter, ax=ax)
cbar.set_label("Rejection Rate (%)")
ax.grid(alpha=0.3)

ax = axes[1, 0]
dendrogram(linkage_framing, labels=[f.replace("_", "\n") for f in framings], ax=ax, leaf_font_size=8)
ax.set_title("Framing Hierarchical Clustering", fontweight="bold", fontsize=12)
ax.set_xlabel("Framing")
ax.set_ylabel("Distance (Ward Linkage)")
ax.grid(axis="y", alpha=0.3)

ax = axes[1, 1]
scatter = ax.scatter(features_framing_pca[:, 0], features_framing_pca[:, 1], s=250, alpha=0.6, 
                    c=features_framing[:, 0], cmap="RdYlGn_r")
for i, framing in enumerate(framings):
    ax.annotate(framing.replace("_", "\n"), (features_framing_pca[i, 0], features_framing_pca[i, 1]), 
                ha="center", va="center", fontweight="bold", fontsize=7)
ax.set_xlabel(f"PC1 ({pca_framing.explained_variance_ratio_[0]:.1%} variance)")
ax.set_ylabel(f"PC2 ({pca_framing.explained_variance_ratio_[1]:.1%} variance)")
ax.set_title("Framing PCA Projection", fontweight="bold", fontsize=12)
cbar = plt.colorbar(scatter, ax=ax)
cbar.set_label("Rejection Rate (%)")
ax.grid(alpha=0.3)

plt.tight_layout()
plt.savefig("1_cwe_framing_clustering.png", dpi=150, bbox_inches="tight")
print("✓ Saved: 1_cwe_framing_clustering.png")
plt.close()

# ============================================================================
# 2. CWE DIFFICULTY & QUALITY TRADEOFF
# ============================================================================

print("[2/5] Generating CWE Difficulty Analysis...")

fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(15, 6))
fig.suptitle("CWE Analysis: Difficulty & Quality Trade-off (Retained Challenge Split)", 
             fontsize=14, fontweight="bold")

cwe_list = sorted(cwes, key=lambda c: cwe_results[c]["rejection_rate"], reverse=True)
rr_values = [cwe_results[c]["rejection_rate"] for c in cwe_list]
colors = plt.cm.RdYlGn(np.array(rr_values) / max(rr_values))

ax1.barh(cwe_list, rr_values, color=colors, edgecolor="black", linewidth=0.5)
ax1.set_xlabel("Rejection Rate (%)", fontweight="bold")
ax1.set_title("CWE Difficulty (Rejection Rate)", fontweight="bold")
ax1.set_xlim([0, max(rr_values) * 1.1])
for i, v in enumerate(rr_values):
    ax1.text(v + 1, i, f"{v:.1f}%", va="center", fontsize=9)
ax1.grid(axis="x", alpha=0.3)
ax1.set_yticklabels([c.upper() for c in cwe_list])

ax2.scatter([cwe_results[c]["rejection_rate"] for c in cwes], 
           [0] * len(cwes),  # Placeholder since we don't have SRR per-CWE easily
           s=200, alpha=0.6, c=range(len(cwes)), cmap="tab10")
for c in cwes:
    ax2.annotate(c.upper(), 
                (cwe_results[c]["rejection_rate"], 0),
                fontsize=9, ha="center", xytext=(0, 10), textcoords="offset points")
ax2.set_xlabel("Rejection Rate (%)", fontweight="bold")
ax2.set_ylabel("")
ax2.set_title("CWE Rejection Rate Distribution", fontweight="bold")
ax2.set_ylim([-0.5, 0.5])
ax2.set_yticks([])
ax2.grid(axis="x", alpha=0.3)

plt.tight_layout()
plt.savefig("2_cwe_difficulty.png", dpi=150, bbox_inches="tight")
print("✓ Saved: 2_cwe_difficulty.png")
plt.close()

# ============================================================================
# 3. FRAMING EFFECTIVENESS
# ============================================================================

print("[3/5] Generating Framing Effectiveness...")

fig, ax = plt.subplots(figsize=(12, 6))
fig.suptitle("Framing Effectiveness: Rejection Rate Ranking (Retained Challenge Split)", 
             fontsize=14, fontweight="bold")

framing_list = sorted(framings, key=lambda f: framing_results[f]["rejection_rate"])
rr_framing = [framing_results[f]["rejection_rate"] for f in framing_list]
colors_framing = plt.cm.RdYlGn(np.array(rr_framing) / 100.0)

ax.barh([f.replace("_", " ").title() for f in framing_list], rr_framing, 
        color=colors_framing, edgecolor="black", linewidth=0.5)
ax.set_xlabel("Rejection Rate (%)", fontweight="bold", fontsize=11)
ax.set_title("Framing Success Rate (% of cases where model approved malicious PR)", fontweight="bold")
ax.set_xlim([0, 100])
for i, v in enumerate(rr_framing):
    ax.text(v + 1.5, i, f"{v:.1f}%", va="center", fontsize=9)
ax.grid(axis="x", alpha=0.3)

plt.tight_layout()
plt.savefig("3_framing_effectiveness.png", dpi=150, bbox_inches="tight")
print("✓ Saved: 3_framing_effectiveness.png")
plt.close()

# ============================================================================
# 4. MODEL CLUSTERING
# ============================================================================

print("[4/5] Generating Model Clustering...")

models_data = {}
for model, prompts in data["per_cwe"].items():
    if "plain" not in prompts:
        continue
    
    cwe_accuracies = []
    for cwe in cwes:
        if cwe in prompts["plain"]:
            acc = prompts["plain"][cwe]["detection_accuracy"]["accuracy"]
            cwe_accuracies.append(100 - acc if acc is not None else 50)
        else:
            cwe_accuracies.append(50)
    
    models_data[model] = cwe_accuracies

model_names = sorted(models_data.keys())
model_features = np.array([models_data[m] for m in model_names])

scaler = StandardScaler()
model_features_scaled = scaler.fit_transform(model_features)
distances = pdist(model_features_scaled, metric="euclidean")
linkage_matrix = linkage(distances, method="ward")
pca = PCA(n_components=2)
model_features_pca = pca.fit_transform(model_features_scaled)

def get_model_tier(name):
    if any(x in name for x in ["claude-opus", "gpt-5.5", "glm-5"]):
        return "Frontier"
    else:
        return "Baseline"

model_tiers = [get_model_tier(m) for m in model_names]
tier_colors = {"Frontier": "#FF6B6B", "Baseline": "#4ECDC4"}
colors = [tier_colors[tier] for tier in model_tiers]

fig, axes = plt.subplots(1, 2, figsize=(16, 6))
fig.suptitle("Model Clustering Analysis (Retained Challenge Split, Rejection Rate)",
             fontsize=14, fontweight="bold")

display_names = []
for name in model_names:
    if "claude-opus" in name:
        display_names.append("Opus 4.7")
    elif "claude-sonnet" in name:
        display_names.append("Sonnet 4.6")
    elif "haiku" in name:
        display_names.append("Haiku 4.5")
    elif "gpt-5.5" in name:
        display_names.append("GPT-5.5")
    elif "gpt-5.4" in name:
        display_names.append("GPT-5.4-nano")
    elif "grok" in name:
        display_names.append("Grok")
    elif "glm-5" in name:
        display_names.append("GLM-5")
    elif "DeepSeek" in name:
        display_names.append("DeepSeek")
    elif "kimi" in name:
        display_names.append("Kimi K2.5")
    elif "gpt-oss" in name:
        display_names.append("GPT-OSS-120B")
    else:
        display_names.append(name[:20])

ax = axes[0]
dendrogram(linkage_matrix, labels=display_names, ax=ax, leaf_rotation=45, leaf_font_size=9)
ax.set_title("Model Hierarchical Clustering", fontweight="bold", fontsize=12)
ax.set_ylabel("Distance (Ward Linkage)")
ax.grid(axis="y", alpha=0.3)

ax = axes[1]
for tier in ["Baseline", "Frontier"]:
    mask = np.array(model_tiers) == tier
    ax.scatter(model_features_pca[mask, 0], model_features_pca[mask, 1],
              s=250, alpha=0.7, c=tier_colors[tier], label=tier, edgecolors="black", linewidth=1.5)

for i, name in enumerate(display_names):
    ax.annotate(name, (model_features_pca[i, 0], model_features_pca[i, 1]),
               ha="center", va="center", fontsize=8, fontweight="bold")

ax.set_xlabel(f"PC1 ({pca.explained_variance_ratio_[0]:.1%} variance)")
ax.set_ylabel(f"PC2 ({pca.explained_variance_ratio_[1]:.1%} variance)")
ax.set_title("Model PCA Projection", fontweight="bold", fontsize=12)
ax.legend(loc="best", fontsize=10)
ax.grid(alpha=0.3)

plt.tight_layout()
plt.savefig("4_model_clustering.png", dpi=150, bbox_inches="tight")
print("✓ Saved: 4_model_clustering.png")
plt.close()

# ============================================================================
# 5. CWE × FRAMING HEATMAP
# ============================================================================

print("[5/5] Generating CWE × Framing Heatmap...")

cwe_framing_matrix = defaultdict(lambda: defaultdict(int))
cwe_framing_total = defaultdict(lambda: defaultdict(int))

results_dirs = [
    Path("logs/results_nips"),
    Path("logs/filtering_releases"),
]

for results_dir in results_dirs:
    if not results_dir.exists():
        continue
    
    for dir_path in sorted(results_dir.glob("*_gitea_*")):
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
            
            detection_score = sample["scores"].get("detection_scorer", {}).get("value", None)
            
            if detection_score is not None:
                cwe_framing_total[cwe][framing] += 1
                if detection_score == 0.0:
                    cwe_framing_matrix[cwe][framing] += 1

all_framings = sorted(set(f for fdict in cwe_framing_matrix.values() for f in fdict.keys()))
matrix = np.zeros((len(cwes), len(all_framings)))
matrix[:] = np.nan

for i, cwe in enumerate(cwes):
    for j, framing in enumerate(all_framings):
        total = cwe_framing_total[cwe][framing]
        if total > 0:
            rejection_rate = (cwe_framing_matrix[cwe][framing] / total) * 100
            matrix[i, j] = rejection_rate

# Remove empty columns/rows
valid_cols = ~np.all(np.isnan(matrix), axis=0)
matrix = matrix[:, valid_cols]
all_framings = [all_framings[i] for i, v in enumerate(valid_cols) if v]

valid_rows = ~np.all(np.isnan(matrix), axis=1)
matrix = matrix[valid_rows, :]
cwes_valid = [cwes[i] for i, v in enumerate(valid_rows) if v]

# Fill NaN for clustering
matrix_filled = np.copy(matrix)
for j in range(matrix.shape[1]):
    col = matrix[:, j]
    col_mean = np.nanmean(col)
    matrix_filled[np.isnan(col), j] = col_mean

# Cluster axes
cwe_distances = pdist(matrix_filled, metric="euclidean")
cwe_linkage = linkage(cwe_distances, method="ward")
cwe_order = fcluster(cwe_linkage, t=2, criterion="maxclust")

framing_distances = pdist(matrix_filled.T, metric="euclidean")
framing_linkage = linkage(framing_distances, method="ward")
framing_order = fcluster(framing_linkage, t=3, criterion="maxclust")

cwe_indices = np.argsort(cwe_order)
framing_indices = np.argsort(framing_order)

matrix_reordered = matrix[cwe_indices][:, framing_indices]
cwes_reordered = [cwes_valid[i] for i in cwe_indices]
framings_reordered = [all_framings[i] for i in framing_indices]

fig, ax = plt.subplots(figsize=(15, 7))

sns.heatmap(matrix_reordered, 
           xticklabels=framings_reordered,
           yticklabels=[c.upper() for c in cwes_reordered],
           cmap="RdYlGn_r", vmin=0, vmax=100,
           cbar_kws={"label": "Rejection Rate (%)"},
           ax=ax, linewidths=0.5, linecolor="gray")

ax.set_title("CWE × Framing: Rejection Rate Heatmap (Retained Challenge Split)",
            fontsize=14, fontweight="bold", pad=20)
ax.set_xlabel("Social Engineering Framing", fontweight="bold")
ax.set_ylabel("Vulnerability Type (CWE)", fontweight="bold")

plt.xticks(rotation=45, ha="right", fontsize=9)
plt.yticks(rotation=0, fontsize=10)
plt.tight_layout()
plt.savefig("5_cwe_framing_heatmap.png", dpi=150, bbox_inches="tight")
print("✓ Saved: 5_cwe_framing_heatmap.png")
plt.close()

print("\n" + "=" * 80)
print("✓ ALL VISUALIZATIONS GENERATED SUCCESSFULLY")
print("=" * 80)
print("\nGenerated images:")
print("  1. 1_cwe_framing_clustering.png - CWE & Framing hierarchical clustering + PCA")
print("  2. 2_cwe_difficulty.png - CWE difficulty ranking and distribution")
print("  3. 3_framing_effectiveness.png - Framing success rates ranked")
print("  4. 4_model_clustering.png - Model hierarchical clustering + PCA")
print("  5. 5_cwe_framing_heatmap.png - CWE × Framing rejection rate interaction heatmap")
print("=" * 80)
