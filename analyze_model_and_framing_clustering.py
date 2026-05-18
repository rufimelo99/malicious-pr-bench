"""
Model Clustering and CWE × Framing Analysis on Retained Challenge Split
Uses rejection rate metric
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

# ============================================================================
# LOAD DATA & EXTRACT MODEL PERFORMANCE VECTORS
# ============================================================================

with open("nips_results_with_srr_retained_split.json") as f:
    data = json.load(f)

# Extract per-model performance across CWEs (for model clustering)
cwes = ["cwe79", "cwe89", "cwe352", "cwe862", "cwe787", "cwe22", "cwe416", "cwe125", "cwe78", "cwe94"]
models_data = {}

for model, prompts in data["per_cwe"].items():
    # Use plain prompt for consistency
    if "plain" not in prompts:
        continue
    
    cwe_accuracies = []
    for cwe in cwes:
        if cwe in prompts["plain"]:
            acc = prompts["plain"][cwe]["detection_accuracy"]["accuracy"]
            cwe_accuracies.append(100 - acc if acc is not None else 50)  # Rejection rate
        else:
            cwe_accuracies.append(50)
    
    models_data[model] = cwe_accuracies

print("=" * 70)
print("MODEL CLUSTERING")
print("=" * 70)

# ============================================================================
# RE-EXTRACT CWE × FRAMING DATA FROM LOGS
# ============================================================================

print("\nRe-extracting CWE × Framing data from evaluation logs...")

# Load retained sample IDs
retained_path = Path("retained_sample_ids.json")
with open(retained_path) as f:
    retained_ids_by_cwe = json.load(f)

# Results structure: cwe -> framing -> {caught, missed, total}
cwe_framing_results = defaultdict(
    lambda: defaultdict(lambda: {"caught": 0, "missed": 0, "total": 0})
)

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
        
        # Find eval files
        eval_files = list(dir_path.glob("*.eval"))
        if not eval_files:
            continue
        
        # Deduplicate samples
        samples_by_id = {}
        for eval_file in sorted(eval_files):
            try:
                with zipfile.ZipFile(eval_file) as z:
                    for name in z.namelist():
                        if "_journal/summaries" in name and name.endswith(".json"):
                            with z.open(name) as f:
                                samples = json.loads(f.read().decode())
                                for sample in samples:
                                    sample_id = sample.get("id", "")
                                    if sample_id:
                                        samples_by_id[sample_id] = sample
            except:
                continue
        
        # Process samples
        for sample in samples_by_id.values():
            if "scores" not in sample:
                continue
            
            # Filter to retained split
            sample_id = sample.get("id")
            if sample_id not in retained_ids_by_cwe.get(cwe, []):
                continue
            
            # Extract framing
            parts = sample_id.split("-")
            if len(parts) < 3:
                continue
            
            framing = parts[-1]
            if framing == "partial_test_coverage":
                continue
            
            # Get detection score
            detection_score = (
                sample["scores"].get("detection_scorer", {}).get("value", None)
            )
            
            if detection_score == 1.0:
                cwe_framing_results[cwe][framing]["caught"] += 1
                cwe_framing_results[cwe][framing]["total"] += 1
            elif detection_score == 0.0:
                cwe_framing_results[cwe][framing]["missed"] += 1
                cwe_framing_results[cwe][framing]["total"] += 1

# Compute rejection rates
cwe_framing_metrics = {}
for cwe in cwes:
    cwe_framing_metrics[cwe] = {}
    for framing in sorted(cwe_framing_results[cwe].keys()):
        counts = cwe_framing_results[cwe][framing]
        total = counts["total"]
        if total > 0:
            rejection_rate = (counts["missed"] / total) * 100
            cwe_framing_metrics[cwe][framing] = {
                "rejection_rate": rejection_rate,
                "n_samples": total,
            }

print(f"✓ Extracted {len(cwe_framing_metrics)} CWEs × framings")

# ============================================================================
# MODEL CLUSTERING VISUALIZATION
# ============================================================================

print("\nGenerating model clustering visualization...")

model_names = sorted(models_data.keys())
model_features = np.array([models_data[m] for m in model_names])

# Standardize
scaler = StandardScaler()
model_features_scaled = scaler.fit_transform(model_features)

# Clustering
distances = pdist(model_features_scaled, metric="euclidean")
linkage_matrix = linkage(distances, method="ward")

# PCA
pca = PCA(n_components=2)
model_features_pca = pca.fit_transform(model_features_scaled)

# Categorize models
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

# Dendrogram
ax = axes[0]
# Shorten model names for display
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

dendrogram(linkage_matrix, labels=display_names, ax=ax, leaf_rotation=45, leaf_font_size=9)
ax.set_title("Model Hierarchical Clustering", fontweight="bold")
ax.set_ylabel("Distance (Ward Linkage)")
ax.grid(axis="y", alpha=0.3)

# PCA
ax = axes[1]
for tier in ["Baseline", "Frontier"]:
    mask = np.array(model_tiers) == tier
    ax.scatter(model_features_pca[mask, 0], model_features_pca[mask, 1],
              s=200, alpha=0.7, c=tier_colors[tier], label=tier, edgecolors="black", linewidth=1.5)

for i, name in enumerate(display_names):
    ax.annotate(name, (model_features_pca[i, 0], model_features_pca[i, 1]),
               ha="center", va="center", fontsize=8, fontweight="bold")

ax.set_xlabel(f"PC1 ({pca.explained_variance_ratio_[0]:.1%} variance)")
ax.set_ylabel(f"PC2 ({pca.explained_variance_ratio_[1]:.1%} variance)")
ax.set_title("Model PCA Projection", fontweight="bold")
ax.legend(loc="best", fontsize=10)
ax.grid(alpha=0.3)

plt.tight_layout()
plt.savefig("model_clustering.png", dpi=150, bbox_inches="tight")
print("✓ Saved model_clustering.png")

# ============================================================================
# CWE × FRAMING HEATMAP
# ============================================================================

print("\nGenerating CWE × Framing heatmap...")

# Get all framings
all_framings = set()
for cwe in cwe_framing_metrics.values():
    all_framings.update(cwe.keys())
all_framings = sorted(all_framings)

# Build matrix
matrix = np.zeros((len(cwes), len(all_framings)))
for i, cwe in enumerate(cwes):
    for j, framing in enumerate(all_framings):
        if framing in cwe_framing_metrics[cwe]:
            matrix[i, j] = cwe_framing_metrics[cwe][framing]["rejection_rate"]
        else:
            matrix[i, j] = np.nan

# Cluster both axes
from scipy.cluster.hierarchy import dendrogram as sp_dendrogram

cwe_distances = pdist(matrix, metric="euclidean")
cwe_linkage = linkage(cwe_distances, method="ward")
cwe_order = fcluster(cwe_linkage, t=3, criterion="maxclust")

framing_distances = pdist(matrix.T, metric="euclidean")
framing_linkage = linkage(framing_distances, method="ward")
framing_order = fcluster(framing_linkage, t=3, criterion="maxclust")

# Reorder matrix
cwe_indices = np.argsort(cwe_order)
framing_indices = np.argsort(framing_order)

matrix_reordered = matrix[cwe_indices][:, framing_indices]
cwes_reordered = [cwes[i] for i in cwe_indices]
framings_reordered = [all_framings[i] for i in framing_indices]

# Plot
fig, ax = plt.subplots(figsize=(14, 7))

sns.heatmap(matrix_reordered, 
           xticklabels=framings_reordered,
           yticklabels=cwes_reordered,
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
plt.savefig("cwe_framing_heatmap.png", dpi=150, bbox_inches="tight")
print("✓ Saved cwe_framing_heatmap.png")

# Save metrics
output_data = {
    "model_performance": {name: values.tolist() for name, values in zip(model_names, model_features)},
    "cwe_framing_rejection_rates": {
        cwe: {f: cwe_framing_metrics[cwe][f]["rejection_rate"] 
              for f in all_framings if f in cwe_framing_metrics[cwe]}
        for cwe in cwes
    },
}

with open("model_and_framing_analysis.json", "w") as f:
    json.dump(output_data, f, indent=2)

print("✓ Saved model_and_framing_analysis.json")
print("\n" + "=" * 70)
print("ANALYSIS COMPLETE")
print("=" * 70)
