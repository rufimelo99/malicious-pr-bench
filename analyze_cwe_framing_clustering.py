"""
CWE Clustering and Framing Effectiveness Analysis
Analyzes how CWE classes cluster by detection difficulty and which framings are most effective.
"""

import json
import warnings
from collections import defaultdict

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import seaborn as sns
from scipy.cluster.hierarchy import dendrogram, fcluster, linkage
from scipy.spatial.distance import pdist, squareform
from sklearn.decomposition import PCA
from sklearn.preprocessing import StandardScaler

warnings.filterwarnings("ignore")

# ============================================================================
# LOAD DATA
# ============================================================================


def load_data():
    """Load benchmark results."""
    with open("nips_frontier_results_by_framing.json") as f:
        framing_data = json.load(f)

    with open("nips_results_with_srr.json") as f:
        srr_data = json.load(f)

    return framing_data, srr_data


# ============================================================================
# CWE DIFFICULTY ANALYSIS
# ============================================================================


def analyze_cwe_difficulty(srr_data):
    """Analyze detection difficulty per CWE across all models."""

    model_cwe_results = defaultdict(lambda: defaultdict(dict))

    for model, prompt_variants in srr_data["per_cwe"].items():
        for prompt_variant, cwes in prompt_variants.items():
            for cwe, metrics in cwes.items():
                da = metrics["detection_accuracy"]["accuracy"]
                srr = metrics["security_reason_rate"]["accuracy"]
                n_samples = metrics["detection_accuracy"]["n_samples"]

                if cwe not in model_cwe_results[model]:
                    model_cwe_results[model][cwe] = {
                        "detection_accuracy": [],
                        "security_reason_rate": [],
                        "n_samples": n_samples,
                    }

                model_cwe_results[model][cwe]["detection_accuracy"].append(da)
                model_cwe_results[model][cwe]["security_reason_rate"].append(srr)

    # Create summary: average per CWE across models and prompts
    cwe_summary = {}
    for cwe_id in [
        "cwe22",
        "cwe78",
        "cwe79",
        "cwe89",
        "cwe94",
        "cwe125",
        "cwe352",
        "cwe416",
        "cwe787",
        "cwe862",
    ]:
        das = []
        srrs = []

        for model in model_cwe_results:
            if cwe_id in model_cwe_results[model]:
                das.extend(model_cwe_results[model][cwe_id]["detection_accuracy"])
                srrs.extend(model_cwe_results[model][cwe_id]["security_reason_rate"])

        if das:
            srrs_filtered = [s for s in srrs if s is not None]
            cwe_summary[cwe_id] = {
                "mean_da": np.mean(das),
                "std_da": np.std(das),
                "mean_srr": np.mean(srrs_filtered) if srrs_filtered else 0,
                "std_srr": np.std(srrs_filtered) if srrs_filtered else 0,
                "difficulty": 100 - np.mean(das),  # Lower DA = higher difficulty
            }

    return cwe_summary, model_cwe_results


# ============================================================================
# FRAMING EFFECTIVENESS ANALYSIS
# ============================================================================


def analyze_framing_effectiveness(framing_data):
    """Analyze which framings are most/least effective per CWE."""

    framing_summary = defaultdict(lambda: defaultdict(dict))

    for model, framings in framing_data.items():
        for framing, stats in framings.items():
            # Extract CWE from the data if available, otherwise aggregate
            accuracy = stats["accuracy"]
            caught = stats["caught"]
            missed = stats["missed"]
            total = stats["total"]

            framing_summary[framing][model] = {
                "accuracy": accuracy,
                "caught": caught,
                "missed": missed,
                "total": total,
            }

    # Compute aggregate framing effectiveness
    framing_agg = {}
    for framing, models in framing_summary.items():
        accuracies = [v["accuracy"] for v in models.values()]
        framing_agg[framing] = {
            "mean_accuracy": np.mean(accuracies),
            "std_accuracy": np.std(accuracies),
            "effectiveness_score": 100
            - np.mean(accuracies),  # Lower accuracy = more effective attack
        }

    return framing_summary, framing_agg


# ============================================================================
# CLUSTERING ANALYSIS
# ============================================================================


def cluster_cwes(cwe_summary):
    """Cluster CWEs based on detection difficulty patterns."""

    cwe_ids = list(cwe_summary.keys())
    features = []

    for cwe_id in cwe_ids:
        features.append(
            [
                cwe_summary[cwe_id]["mean_da"],
                cwe_summary[cwe_id]["mean_srr"],
                cwe_summary[cwe_id]["difficulty"],
            ]
        )

    features = np.array(features)

    # Standardize features
    scaler = StandardScaler()
    features_scaled = scaler.fit_transform(features)

    # Hierarchical clustering
    Z = linkage(features_scaled, method="ward")
    clusters = fcluster(Z, t=3, criterion="maxclust")

    # PCA for visualization
    pca = PCA(n_components=2)
    features_pca = pca.fit_transform(features_scaled)

    return {
        "cwe_ids": cwe_ids,
        "features": features,
        "features_scaled": features_scaled,
        "features_pca": features_pca,
        "linkage": Z,
        "clusters": clusters,
        "pca": pca,
    }


# ============================================================================
# VISUALIZATION FUNCTIONS
# ============================================================================


def plot_cwe_heatmap(cwe_summary, framing_summary, framing_data):
    """Create heatmap of CWE difficulty vs framing effectiveness."""

    # Get one model for reference (Claude Opus)
    model_key = [k for k in framing_data.keys() if "opus-4-7" in k][0]

    cwe_ids = sorted(list(cwe_summary.keys()))
    framing_names = sorted(list(framing_data[model_key].keys()))

    # Build matrix: CWE x Framing (accuracy - lower is better for attacker)
    matrix = np.zeros((len(cwe_ids), len(framing_names)))

    for i, framing in enumerate(framing_names):
        accuracy = framing_data[model_key][framing]["accuracy"]
        for j, cwe in enumerate(cwe_ids):
            # Use difficulty metric (100 - accuracy)
            matrix[j, i] = 100 - accuracy

    fig, ax = plt.subplots(figsize=(14, 8))
    sns.heatmap(
        matrix,
        xticklabels=framing_names,
        yticklabels=cwe_ids,
        cmap="RdYlGn_r",
        annot=True,
        fmt=".1f",
        cbar_kws={"label": "Attack Success Rate (%)"},
        ax=ax,
    )
    ax.set_title(
        "CWE Vulnerability to Social Engineering Framings\n(Claude Opus 4.7)",
        fontsize=14,
        fontweight="bold",
    )
    ax.set_xlabel("Framing Strategy", fontsize=12, fontweight="bold")
    ax.set_ylabel("CWE Class", fontsize=12, fontweight="bold")
    plt.xticks(rotation=45, ha="right")
    plt.tight_layout()
    plt.savefig(
        "/Users/rmelo/Documents/GitHub/malicious-pr-bench/analysis_cwe_framing_heatmap.png",
        dpi=300,
        bbox_inches="tight",
    )
    print("✓ Saved: analysis_cwe_framing_heatmap.png")
    plt.close()


def plot_cwe_clustering(clustering_result, cwe_summary):
    """Plot CWE clustering dendrogram and PCA."""

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(16, 6))

    # Dendrogram
    dendrogram(
        clustering_result["linkage"], labels=clustering_result["cwe_ids"], ax=ax1
    )
    ax1.set_title(
        "Hierarchical Clustering of CWEs by Detection Difficulty",
        fontsize=12,
        fontweight="bold",
    )
    ax1.set_ylabel("Distance")
    ax1.set_xlabel("CWE Class")
    plt.setp(ax1.xaxis.get_majorticklabels(), rotation=45, ha="right")

    # PCA scatter
    clusters = clustering_result["clusters"]
    colors = ["#FF6B6B", "#4ECDC4", "#45B7D1"]

    for cluster_id in np.unique(clusters):
        mask = clusters == cluster_id
        ax2.scatter(
            clustering_result["features_pca"][mask, 0],
            clustering_result["features_pca"][mask, 1],
            c=colors[cluster_id - 1],
            label=f"Cluster {cluster_id}",
            s=200,
            alpha=0.7,
            edgecolors="black",
            linewidth=2,
        )

    # Annotate points
    for idx, cwe in enumerate(clustering_result["cwe_ids"]):
        ax2.annotate(
            cwe.upper(),
            (
                clustering_result["features_pca"][idx, 0],
                clustering_result["features_pca"][idx, 1],
            ),
            fontsize=10,
            fontweight="bold",
            ha="center",
            va="center",
        )

    ax2.set_xlabel(
        f'PC1 ({clustering_result["pca"].explained_variance_ratio_[0]:.1%})',
        fontsize=11,
    )
    ax2.set_ylabel(
        f'PC2 ({clustering_result["pca"].explained_variance_ratio_[1]:.1%})',
        fontsize=11,
    )
    ax2.set_title("PCA Projection: CWE Clustering", fontsize=12, fontweight="bold")
    ax2.legend()
    ax2.grid(True, alpha=0.3)

    plt.tight_layout()
    plt.savefig(
        "/Users/rmelo/Documents/GitHub/malicious-pr-bench/analysis_cwe_clustering.png",
        dpi=300,
        bbox_inches="tight",
    )
    print("✓ Saved: analysis_cwe_clustering.png")
    plt.close()


def plot_framing_effectiveness(framing_agg, framing_data):
    """Bar plot of framing effectiveness."""

    framings = sorted(framing_agg.keys())
    effectiveness = [framing_agg[f]["effectiveness_score"] for f in framings]

    fig, ax = plt.subplots(figsize=(12, 6))

    colors = [
        "#FF6B6B" if e > 30 else "#FFA07A" if e > 15 else "#90EE90"
        for e in effectiveness
    ]
    bars = ax.barh(
        framings, effectiveness, color=colors, edgecolor="black", linewidth=1.5
    )

    # Add value labels
    for i, (framing, eff) in enumerate(zip(framings, effectiveness)):
        ax.text(eff + 1, i, f"{eff:.1f}%", va="center", fontweight="bold")

    ax.set_xlabel("Attack Success Rate (%)", fontsize=12, fontweight="bold")
    ax.set_title(
        "Social Engineering Framing Effectiveness\n(Aggregate across models)",
        fontsize=13,
        fontweight="bold",
    )
    ax.set_xlim(0, max(effectiveness) + 10)
    ax.grid(axis="x", alpha=0.3)

    plt.tight_layout()
    plt.savefig(
        "/Users/rmelo/Documents/GitHub/malicious-pr-bench/analysis_framing_effectiveness.png",
        dpi=300,
        bbox_inches="tight",
    )
    print("✓ Saved: analysis_framing_effectiveness.png")
    plt.close()


def plot_cwe_difficulty_distribution(cwe_summary):
    """Box plot and scatter of CWE difficulty."""

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(14, 5))

    cwe_ids = sorted(list(cwe_summary.keys()))
    difficulties = [cwe_summary[cwe]["difficulty"] for cwe in cwe_ids]
    das = [cwe_summary[cwe]["mean_da"] for cwe in cwe_ids]
    srrs = [cwe_summary[cwe]["mean_srr"] for cwe in cwe_ids]

    # Bar plot: difficulty by CWE
    colors_difficulty = [
        "#FF6B6B" if d > 25 else "#FFA07A" if d > 10 else "#90EE90"
        for d in difficulties
    ]
    ax1.bar(
        range(len(cwe_ids)),
        difficulties,
        color=colors_difficulty,
        edgecolor="black",
        linewidth=1.5,
    )
    ax1.set_xticks(range(len(cwe_ids)))
    ax1.set_xticklabels([cwe.upper() for cwe in cwe_ids], rotation=45, ha="right")
    ax1.set_ylabel("Difficulty Score (1 - DA)", fontsize=11, fontweight="bold")
    ax1.set_title("Detection Difficulty by CWE Class", fontsize=12, fontweight="bold")
    ax1.grid(axis="y", alpha=0.3)

    # Scatter: DA vs SRR
    ax2.scatter(
        das,
        srrs,
        s=300,
        c=difficulties,
        cmap="RdYlGn_r",
        edgecolors="black",
        linewidth=2,
        alpha=0.7,
    )
    for i, cwe in enumerate(cwe_ids):
        ax2.annotate(
            cwe.upper(),
            (das[i], srrs[i]),
            fontsize=9,
            fontweight="bold",
            ha="center",
            va="center",
        )

    ax2.set_xlabel("Detection Accuracy (%)", fontsize=11, fontweight="bold")
    ax2.set_ylabel("Security Reason Rate (%)", fontsize=11, fontweight="bold")
    ax2.set_title(
        "DA vs SRR: Vulnerability Characteristics", fontsize=12, fontweight="bold"
    )
    ax2.grid(True, alpha=0.3)

    cbar = plt.cm.ScalarMappable(
        cmap="RdYlGn_r",
        norm=plt.Normalize(vmin=min(difficulties), vmax=max(difficulties)),
    )
    cbar.set_array(difficulties)
    cbar_ax = fig.add_axes([0.92, 0.15, 0.02, 0.7])
    fig.colorbar(cbar, cax=cbar_ax, label="Difficulty")

    plt.tight_layout(rect=[0, 0, 0.9, 1])
    plt.savefig(
        "/Users/rmelo/Documents/GitHub/malicious-pr-bench/analysis_cwe_difficulty.png",
        dpi=300,
        bbox_inches="tight",
    )
    print("✓ Saved: analysis_cwe_difficulty.png")
    plt.close()


# ============================================================================
# SUMMARY STATISTICS
# ============================================================================


def print_summary_statistics(cwe_summary, framing_agg, clustering_result):
    """Print comprehensive summary statistics."""

    print("\n" + "=" * 80)
    print("CWE CLUSTERING & FRAMING ANALYSIS SUMMARY")
    print("=" * 80)

    print("\n📊 CWE DIFFICULTY RANKING (by detection difficulty):")
    print("-" * 80)
    cwe_sorted = sorted(
        cwe_summary.items(), key=lambda x: x[1]["difficulty"], reverse=True
    )
    for rank, (cwe, metrics) in enumerate(cwe_sorted, 1):
        print(
            f"{rank:2d}. {cwe.upper():8s} | Difficulty: {metrics['difficulty']:5.1f}% | "
            f"DA: {metrics['mean_da']:5.1f}% | SRR: {metrics['mean_srr']:5.1f}%"
        )

    print("\n\n🎯 FRAMING EFFECTIVENESS RANKING (by attack success rate):")
    print("-" * 80)
    framing_sorted = sorted(
        framing_agg.items(), key=lambda x: x[1]["effectiveness_score"], reverse=True
    )
    for rank, (framing, metrics) in enumerate(framing_sorted, 1):
        print(
            f"{rank:2d}. {framing.replace('_', ' ').title():35s} | "
            f"Success Rate: {metrics['effectiveness_score']:5.1f}% | "
            f"Std Dev: {metrics['std_accuracy']:5.1f}%"
        )

    print("\n\n🔍 CWE CLUSTERING INSIGHTS:")
    print("-" * 80)
    for cluster_id in np.unique(clustering_result["clusters"]):
        mask = clustering_result["clusters"] == cluster_id
        cwes_in_cluster = [clustering_result["cwe_ids"][i] for i in np.where(mask)[0]]
        difficulties = [cwe_summary[cwe]["difficulty"] for cwe in cwes_in_cluster]
        print(f"Cluster {cluster_id}: {[c.upper() for c in cwes_in_cluster]}")
        print(f"  - Avg Difficulty: {np.mean(difficulties):.1f}%")
        print(
            f"  - Interpretation: {['Easy to detect', 'Moderate difficulty', 'Hard to detect'][cluster_id - 1]}"
        )

    print("\n\n💡 KEY INSIGHTS:")
    print("-" * 80)
    most_difficult_cwe = cwe_sorted[0][0]
    least_difficult_cwe = cwe_sorted[-1][0]
    most_effective_framing = framing_sorted[0][0]
    least_effective_framing = framing_sorted[-1][0]

    print(
        f"• Hardest CWE to detect: {most_difficult_cwe.upper()} "
        f"(Difficulty: {cwe_summary[most_difficult_cwe]['difficulty']:.1f}%)"
    )
    print(
        f"• Easiest CWE to detect: {least_difficult_cwe.upper()} "
        f"(Difficulty: {cwe_summary[least_difficult_cwe]['difficulty']:.1f}%)"
    )
    print(
        f"• Most effective framing: {most_effective_framing.replace('_', ' ').title()} "
        f"(Success: {framing_agg[most_effective_framing]['effectiveness_score']:.1f}%)"
    )
    print(
        f"• Least effective framing: {least_effective_framing.replace('_', ' ').title()} "
        f"(Success: {framing_agg[least_effective_framing]['effectiveness_score']:.1f}%)"
    )

    print("\n" + "=" * 80 + "\n")


# ============================================================================
# EXPORT DATA FOR PAPER
# ============================================================================


def export_analysis_data(cwe_summary, framing_agg, clustering_result):
    """Export analysis data as JSON for use in paper."""

    export_data = {
        "cwe_summary": {
            cwe: {
                "mean_detection_accuracy": round(metrics["mean_da"], 2),
                "std_detection_accuracy": round(metrics["std_da"], 2),
                "mean_security_reason_rate": round(metrics["mean_srr"], 2),
                "difficulty_score": round(metrics["difficulty"], 2),
            }
            for cwe, metrics in cwe_summary.items()
        },
        "framing_effectiveness": {
            framing: {
                "mean_attack_success_rate": round(metrics["effectiveness_score"], 2),
                "std_attack_success_rate": round(metrics["std_accuracy"], 2),
            }
            for framing, metrics in framing_agg.items()
        },
        "clustering": {
            "cwe_clusters": {
                int(cluster_id): [
                    clustering_result["cwe_ids"][i].upper()
                    for i in np.where(clustering_result["clusters"] == cluster_id)[0]
                ]
                for cluster_id in np.unique(clustering_result["clusters"])
            }
        },
    }

    with open(
        "/Users/rmelo/Documents/GitHub/malicious-pr-bench/analysis_cwe_framing.json",
        "w",
    ) as f:
        json.dump(export_data, f, indent=2)

    print("✓ Exported: analysis_cwe_framing.json")


# ============================================================================
# MAIN
# ============================================================================


def main():
    print("\n🔄 Loading data...")
    framing_data, srr_data = load_data()

    print("📈 Analyzing CWE difficulty...")
    cwe_summary, model_cwe_results = analyze_cwe_difficulty(srr_data)

    print("🎭 Analyzing framing effectiveness...")
    framing_summary, framing_agg = analyze_framing_effectiveness(framing_data)

    print("🔍 Clustering CWEs...")
    clustering_result = cluster_cwes(cwe_summary)

    print("\n📊 Creating visualizations...")
    plot_cwe_heatmap(cwe_summary, framing_summary, framing_data)
    plot_cwe_clustering(clustering_result, cwe_summary)
    plot_framing_effectiveness(framing_agg, framing_data)
    plot_cwe_difficulty_distribution(cwe_summary)

    print("\n📋 Exporting analysis data...")
    export_analysis_data(cwe_summary, framing_agg, clustering_result)

    print_summary_statistics(cwe_summary, framing_agg, clustering_result)

    return cwe_summary, framing_agg, clustering_result


if __name__ == "__main__":
    cwe_summary, framing_agg, clustering_result = main()
