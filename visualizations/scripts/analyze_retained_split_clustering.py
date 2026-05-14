"""
CWE and Framing Clustering Analysis on Retained Challenge Split
Uses rejection rate (1 - detection accuracy) instead of detection accuracy
"""

import json
import math
import warnings

import matplotlib.pyplot as plt
import numpy as np
import seaborn as sns
from scipy.cluster.hierarchy import dendrogram, linkage
from scipy.spatial.distance import pdist, squareform
from sklearn.decomposition import PCA
from sklearn.preprocessing import StandardScaler

warnings.filterwarnings("ignore")

# Load retained split data
with open("nips_results_with_srr_retained_split.json") as f:
    data = json.load(f)

# ============================================================================
# AGGREGATE METRICS
# ============================================================================


def aggregate_per_cwe(data):
    """Aggregate metrics per CWE across all models and prompts."""
    cwe_metrics = {}

    for model, prompts in data["per_cwe"].items():
        for prompt, cwes in prompts.items():
            for cwe, metrics in cwes.items():
                if cwe not in cwe_metrics:
                    cwe_metrics[cwe] = {
                        "da_caught": 0,
                        "da_missed": 0,
                        "da_total": 0,
                        "srr_caught": 0,
                        "srr_missed": 0,
                        "srr_total": 0,
                    }

                # Detection accuracy
                da = metrics["detection_accuracy"]
                if da["accuracy"] is not None:
                    cwe_metrics[cwe]["da_caught"] += (
                        da["accuracy"] * da["n_samples"] / 100
                    )
                    cwe_metrics[cwe]["da_missed"] += (
                        (100 - da["accuracy"]) * da["n_samples"] / 100
                    )
                    cwe_metrics[cwe]["da_total"] += da["n_samples"]

                # Security reason rate
                srr = metrics["security_reason_rate"]
                if srr["accuracy"] is not None:
                    cwe_metrics[cwe]["srr_caught"] += (
                        srr["accuracy"] * srr["n_samples"] / 100
                    )
                    cwe_metrics[cwe]["srr_missed"] += (
                        (100 - srr["accuracy"]) * srr["n_samples"] / 100
                    )
                    cwe_metrics[cwe]["srr_total"] += srr["n_samples"]

    # Compute final metrics
    cwe_results = {}
    for cwe, counts in cwe_metrics.items():
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
            "detection_accuracy": da_acc,
            "rejection_rate": 100 - da_acc,
            "security_reason_rate": srr_acc,
            "n_samples": counts["da_total"],
        }

    return cwe_results


def aggregate_per_framing(data):
    """Aggregate metrics per framing across all models."""
    framing_metrics = {}

    for model, framings in data["per_framing"].items():
        for framing, metrics in framings.items():
            if framing not in framing_metrics:
                framing_metrics[framing] = {
                    "da_caught": 0,
                    "da_missed": 0,
                    "da_total": 0,
                }

            da = metrics["detection_accuracy"]
            framing_metrics[framing]["da_caught"] += (
                da["accuracy"] * da["n_samples"] / 100
            )
            framing_metrics[framing]["da_missed"] += (
                (100 - da["accuracy"]) * da["n_samples"] / 100
            )
            framing_metrics[framing]["da_total"] += da["n_samples"]

    # Compute final metrics
    framing_results = {}
    for framing, counts in framing_metrics.items():
        da_acc = (
            (counts["da_caught"] / counts["da_total"] * 100)
            if counts["da_total"] > 0
            else 0
        )
        framing_results[framing] = {
            "detection_accuracy": da_acc,
            "rejection_rate": 100 - da_acc,
            "n_samples": counts["da_total"],
        }

    return framing_results


# Compute aggregates
cwe_results = aggregate_per_cwe(data)
framing_results = aggregate_per_framing(data)

print("CWE Metrics (aggregated across all models, plain prompt):")
for cwe in sorted(cwe_results.keys()):
    m = cwe_results[cwe]
    print(
        f"  {cwe.upper()}: RR={m['rejection_rate']:5.1f}%, DA={m['detection_accuracy']:5.1f}%, SRR={m['security_reason_rate']:5.1f}%"
    )

print("\nFraming Metrics (aggregated across all models):")
for framing in sorted(framing_results.keys()):
    m = framing_results[framing]
    print(
        f"  {framing:30s}: RR={m['rejection_rate']:5.1f}%, DA={m['detection_accuracy']:5.1f}%"
    )

# ============================================================================
# CWE CLUSTERING
# ============================================================================

print("\n" + "=" * 70)
print("CWE CLUSTERING")
print("=" * 70)

cwes = sorted(cwe_results.keys())
features_cwe = []

for cwe in cwes:
    m = cwe_results[cwe]
    features_cwe.append(
        [
            m["rejection_rate"],
            m["security_reason_rate"],
            m["rejection_rate"],  # difficulty = rejection rate
        ]
    )

features_cwe = np.array(features_cwe)
print(f"\nCWE feature matrix shape: {features_cwe.shape}")
print(f"Features: [Rejection Rate, Security Reason Rate, Difficulty]")

# Standardize
scaler_cwe = StandardScaler()
features_cwe_scaled = scaler_cwe.fit_transform(features_cwe)

# Clustering
distances_cwe = pdist(features_cwe_scaled, metric="euclidean")
linkage_cwe = linkage(distances_cwe, method="ward")

# PCA
pca_cwe = PCA(n_components=2)
features_cwe_pca = pca_cwe.fit_transform(features_cwe_scaled)
var_explained_cwe = pca_cwe.explained_variance_ratio_

print(
    f"PCA variance explained: PC1={var_explained_cwe[0]:.1%}, PC2={var_explained_cwe[1]:.1%}"
)

# ============================================================================
# FRAMING CLUSTERING
# ============================================================================

print("\n" + "=" * 70)
print("FRAMING CLUSTERING")
print("=" * 70)

framings = sorted(framing_results.keys())
features_framing = []

for framing in framings:
    m = framing_results[framing]
    features_framing.append(
        [
            m["rejection_rate"],
        ]
    )

features_framing = np.array(features_framing)
print(f"\nFraming feature matrix shape: {features_framing.shape}")
print(f"Features: [Rejection Rate]")

# For framing, we only have 1 dimension, so we'll add sample count as second dimension
features_framing_2d = []
for framing in framings:
    m = framing_results[framing]
    features_framing_2d.append(
        [
            m["rejection_rate"],
            m["n_samples"] / 100,  # Scale sample count for visibility
        ]
    )

features_framing_2d = np.array(features_framing_2d)

# Standardize
scaler_framing = StandardScaler()
features_framing_scaled = scaler_framing.fit_transform(features_framing_2d)

# Clustering
distances_framing = pdist(features_framing_scaled, metric="euclidean")
linkage_framing = linkage(distances_framing, method="ward")

# PCA
pca_framing = PCA(n_components=2)
features_framing_pca = pca_framing.fit_transform(features_framing_scaled)
var_explained_framing = pca_framing.explained_variance_ratio_

print(
    f"PCA variance explained: PC1={var_explained_framing[0]:.1%}, PC2={var_explained_framing[1]:.1%}"
)

# ============================================================================
# VISUALIZATIONS
# ============================================================================

fig, axes = plt.subplots(2, 2, figsize=(16, 12))
fig.suptitle(
    "CWE and Framing Clustering Analysis (Retained Challenge Split)\nUsing Rejection Rate Metric",
    fontsize=14,
    fontweight="bold",
    y=0.995,
)

# CWE Dendrogram
ax = axes[0, 0]
dendrogram(linkage_cwe, labels=[c.upper() for c in cwes], ax=ax)
ax.set_title("CWE Hierarchical Clustering (Dendrogram)", fontweight="bold")
ax.set_xlabel("CWE")
ax.set_ylabel("Distance (Ward Linkage)")
ax.grid(axis="y", alpha=0.3)

# CWE PCA
ax = axes[0, 1]
scatter = ax.scatter(
    features_cwe_pca[:, 0],
    features_cwe_pca[:, 1],
    s=200,
    alpha=0.6,
    c=features_cwe[:, 0],
    cmap="RdYlGn_r",
)
for i, cwe in enumerate(cwes):
    ax.annotate(
        cwe.upper(),
        (features_cwe_pca[i, 0], features_cwe_pca[i, 1]),
        ha="center",
        va="center",
        fontweight="bold",
        fontsize=9,
    )
ax.set_xlabel(f"PC1 ({var_explained_cwe[0]:.1%} variance)")
ax.set_ylabel(f"PC2 ({var_explained_cwe[1]:.1%} variance)")
ax.set_title("CWE PCA Projection", fontweight="bold")
cbar = plt.colorbar(scatter, ax=ax)
cbar.set_label("Rejection Rate (%)")
ax.grid(alpha=0.3)

# Framing Dendrogram
ax = axes[1, 0]
dendrogram(
    linkage_framing,
    labels=[f.replace("_", "\n") for f in framings],
    ax=ax,
    leaf_font_size=8,
)
ax.set_title("Framing Hierarchical Clustering (Dendrogram)", fontweight="bold")
ax.set_xlabel("Framing")
ax.set_ylabel("Distance (Ward Linkage)")
ax.grid(axis="y", alpha=0.3)

# Framing PCA
ax = axes[1, 1]
scatter = ax.scatter(
    features_framing_pca[:, 0],
    features_framing_pca[:, 1],
    s=200,
    alpha=0.6,
    c=features_framing[:, 0],
    cmap="RdYlGn_r",
)
for i, framing in enumerate(framings):
    ax.annotate(
        framing.replace("_", "\n"),
        (features_framing_pca[i, 0], features_framing_pca[i, 1]),
        ha="center",
        va="center",
        fontweight="bold",
        fontsize=7,
    )
ax.set_xlabel(f"PC1 ({var_explained_framing[0]:.1%} variance)")
ax.set_ylabel(f"PC2 ({var_explained_framing[1]:.1%} variance)")
ax.set_title("Framing PCA Projection", fontweight="bold")
cbar = plt.colorbar(scatter, ax=ax)
cbar.set_label("Rejection Rate (%)")
ax.grid(alpha=0.3)

plt.tight_layout()
plt.savefig("retained_split_cwe_framing_clustering.png", dpi=150, bbox_inches="tight")
print("\n✓ Saved retained_split_cwe_framing_clustering.png")

# ============================================================================
# ADDITIONAL VISUALIZATIONS
# ============================================================================

# CWE Difficulty Ranking (using rejection rate)
fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(15, 6))
fig.suptitle(
    "CWE Analysis: Difficulty & Quality Trade-off (Retained Challenge Split)",
    fontsize=14,
    fontweight="bold",
)

# Left: Rejection Rate Bar Chart
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

# Right: Rejection Rate vs Security Reason Rate
ax2.scatter(
    [cwe_results[c]["rejection_rate"] for c in cwes],
    [cwe_results[c]["security_reason_rate"] for c in cwes],
    s=150,
    alpha=0.6,
    c=range(len(cwes)),
    cmap="tab10",
)
for c in cwes:
    ax2.annotate(
        c.upper(),
        (cwe_results[c]["rejection_rate"], cwe_results[c]["security_reason_rate"]),
        fontsize=8,
        ha="center",
    )
ax2.set_xlabel("Rejection Rate (%)", fontweight="bold")
ax2.set_ylabel("Security Reason Rate (%)", fontweight="bold")
ax2.set_title("Rejection Rate vs Security Reason Rate", fontweight="bold")
ax2.grid(alpha=0.3)

plt.tight_layout()
plt.savefig("retained_split_cwe_difficulty.png", dpi=150, bbox_inches="tight")
print("✓ Saved retained_split_cwe_difficulty.png")

# Framing Effectiveness Ranking
fig, ax = plt.subplots(figsize=(12, 6))
fig.suptitle(
    "Framing Effectiveness: Rejection Rate Ranking (Retained Challenge Split)",
    fontsize=14,
    fontweight="bold",
)

framing_list = sorted(framings, key=lambda f: framing_results[f]["rejection_rate"])
rr_framing = [framing_results[f]["rejection_rate"] for f in framing_list]
colors_framing = plt.cm.RdYlGn(np.array(rr_framing) / 100.0)

ax.barh(
    [f.replace("_", " ").title() for f in framing_list],
    rr_framing,
    color=colors_framing,
    edgecolor="black",
    linewidth=0.5,
)
ax.set_xlabel("Rejection Rate (%)", fontweight="bold")
ax.set_title(
    "Framing Success Rate (% of cases where model approved malicious PR)",
    fontweight="bold",
)
ax.set_xlim([0, 100])
for i, v in enumerate(rr_framing):
    ax.text(v + 1.5, i, f"{v:.1f}%", va="center", fontsize=9)
ax.grid(axis="x", alpha=0.3)

plt.tight_layout()
plt.savefig("retained_split_framing_effectiveness.png", dpi=150, bbox_inches="tight")
print("✓ Saved retained_split_framing_effectiveness.png")

# Save metrics to JSON
output_data = {
    "cwe_metrics": cwe_results,
    "framing_metrics": framing_results,
    "cwe_clustering": {
        "method": "Ward hierarchical clustering",
        "features": ["Rejection Rate", "Security Reason Rate", "Difficulty"],
        "pca_variance_explained": [float(v) for v in var_explained_cwe],
    },
    "framing_clustering": {
        "method": "Ward hierarchical clustering",
        "features": ["Rejection Rate", "Sample Count (scaled)"],
        "pca_variance_explained": [float(v) for v in var_explained_framing],
    },
}

with open("retained_split_clustering_results.json", "w") as f:
    json.dump(output_data, f, indent=2)

print("✓ Saved retained_split_clustering_results.json")
print("\n" + "=" * 70)
print("ANALYSIS COMPLETE")
print("=" * 70)
