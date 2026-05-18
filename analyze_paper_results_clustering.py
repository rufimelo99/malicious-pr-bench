"""
CWE Clustering & Framing Analysis for Paper Results
Analyzes /logs/results_nips/ and /logs/filtering_releases/ (same as paper)
Reports rejection rate metric (1 - detection accuracy)
"""

import json
import math
import warnings
import zipfile
from collections import defaultdict
from pathlib import Path

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import seaborn as sns
from scipy.cluster.hierarchy import dendrogram, linkage
from scipy.spatial.distance import pdist, squareform
from sklearn.decomposition import PCA
from sklearn.preprocessing import StandardScaler

warnings.filterwarnings("ignore")

# ============================================================================
# DATA EXTRACTION
# ============================================================================


def extract_paper_data(
    results_dirs=[
        "/Users/rmelo/Documents/GitHub/malicious-pr-bench/logs/results_nips",
        "/Users/rmelo/Documents/GitHub/malicious-pr-bench/logs/filtering_releases",
    ],
    use_retained_split=True,
):
    """Extract all data from paper's evaluation sources.

    If use_retained_split=True, only includes samples in the retained challenge split
    (1,062 samples where weak models failed). This matches Table 1 in the paper.
    """

    # Load retained sample IDs if needed (keep per-CWE structure)
    retained_ids_by_cwe = None
    if use_retained_split:
        retained_path = Path(
            "/Users/rmelo/Documents/GitHub/malicious-pr-bench/retained_sample_ids.json"
        )
        with open(retained_path) as f:
            retained_ids_by_cwe = json.load(f)
        total_entries = sum(len(ids) for ids in retained_ids_by_cwe.values())
        print(
            f"Loaded retained challenge split: {total_entries} total samples across CWEs"
        )

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

    total_dirs_found = 0

    for results_dir in results_dirs:
        results_path = Path(results_dir)
        if not results_path.exists():
            print(f"  Warning: {results_dir} not found")
            continue

        dir_paths = sorted([d for d in results_path.glob("*_gitea_*") if d.is_dir()])
        print(f"Found {len(dir_paths)} directories in {results_path.name}")
        total_dirs_found += len(dir_paths)

        for dir_path in dir_paths:
            # Parse directory name: {model}_gitea_{prompt_variant}_cwe{number}
            parts = dir_path.name.split("_gitea_")
            if len(parts) < 2:
                continue

            model_name = parts[0]
            rest = "_gitea_".join(parts[1:])

            # Extract prompt and CWE
            if "_cwe" not in rest:
                continue

            prompt_parts = rest.split("_cwe")
            prompt = prompt_parts[0]
            cwe_num = (
                prompt_parts[1].split("_")[0]
                if "_" in prompt_parts[1]
                else prompt_parts[1]
            )
            cwe = f"cwe{cwe_num}"

            # Find and process eval files
            eval_files = list(dir_path.glob("*.eval"))
            if not eval_files:
                continue

            # Deduplicate samples
            samples_by_id = {}
            for eval_file in sorted(eval_files):
                try:
                    with zipfile.ZipFile(eval_file) as z:
                        summary_files = sorted(
                            [
                                f
                                for f in z.namelist()
                                if "_journal/summaries" in f and f.endswith(".json")
                            ]
                        )
                        for summary_file in summary_files:
                            with z.open(summary_file) as f:
                                samples = json.load(f)
                                for sample in samples:
                                    sample_id = sample.get("id", sample.get("uuid"))
                                    if sample_id:
                                        samples_by_id[sample_id] = sample
                except Exception as e:
                    continue

            # Process samples
            for sample in samples_by_id.values():
                if "scores" not in sample:
                    continue

                # Filter to retained challenge split if requested (check per-CWE)
                if retained_ids_by_cwe is not None:
                    sample_id = sample.get("id")
                    # Check if this sample is in the retained set for this CWE
                    if sample_id not in retained_ids_by_cwe.get(cwe, []):
                        continue

                # Extract framing from sample metadata
                metadata = sample.get("metadata", {})
                framing = metadata.get("axis3", "unknown")

                # Filter out partial_test_coverage (not in paper's 15 framings)
                if framing == "partial_test_coverage":
                    continue

                # Get scores
                detection_score = (
                    sample["scores"].get("detection_scorer", {}).get("value", None)
                )
                security_reason_score = (
                    sample["scores"]
                    .get("security_reason_scorer", {})
                    .get("value", None)
                )

                # Record results
                if detection_score == 1.0:
                    results[model_name][prompt][cwe][framing]["detection"][
                        "caught"
                    ] += 1
                    results[model_name][prompt][cwe][framing]["detection"]["total"] += 1
                elif detection_score == 0.0:
                    results[model_name][prompt][cwe][framing]["detection"][
                        "missed"
                    ] += 1
                    results[model_name][prompt][cwe][framing]["detection"]["total"] += 1

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

    print(f"Total directories scanned: {total_dirs_found}\n")
    return results


def aggregate_by_cwe_and_framing(results):
    """Aggregate results by CWE and by Framing, combining across prompt variants."""

    # Aggregate by CWE (combine prompt variants, combine framings)
    cwe_summary = defaultdict(
        lambda: {
            "detection": {"caught": 0, "missed": 0, "total": 0},
            "security_reason": {"caught": 0, "missed": 0, "total": 0},
        }
    )

    # Aggregate by CWE x Framing
    cwe_framing_summary = defaultdict(
        lambda: defaultdict(
            lambda: {
                "detection": {"caught": 0, "missed": 0, "total": 0},
                "security_reason": {"caught": 0, "missed": 0, "total": 0},
            }
        )
    )

    # Aggregate by Framing (combine CWEs)
    framing_summary = defaultdict(
        lambda: {
            "detection": {"caught": 0, "missed": 0, "total": 0},
            "security_reason": {"caught": 0, "missed": 0, "total": 0},
        }
    )

    # Aggregate by Model (for context)
    model_summary = defaultdict(
        lambda: {
            "detection": {"caught": 0, "missed": 0, "total": 0},
            "security_reason": {"caught": 0, "missed": 0, "total": 0},
        }
    )

    for model_name, prompts in results.items():
        for prompt, cwes in prompts.items():
            for cwe, framings in cwes.items():
                for framing, counts in framings.items():
                    # CWE summary
                    cwe_summary[cwe]["detection"]["caught"] += counts["detection"][
                        "caught"
                    ]
                    cwe_summary[cwe]["detection"]["missed"] += counts["detection"][
                        "missed"
                    ]
                    cwe_summary[cwe]["detection"]["total"] += counts["detection"][
                        "total"
                    ]
                    cwe_summary[cwe]["security_reason"]["caught"] += counts[
                        "security_reason"
                    ]["caught"]
                    cwe_summary[cwe]["security_reason"]["missed"] += counts[
                        "security_reason"
                    ]["missed"]
                    cwe_summary[cwe]["security_reason"]["total"] += counts[
                        "security_reason"
                    ]["total"]

                    # CWE x Framing
                    cwe_framing_summary[cwe][framing]["detection"]["caught"] += counts[
                        "detection"
                    ]["caught"]
                    cwe_framing_summary[cwe][framing]["detection"]["missed"] += counts[
                        "detection"
                    ]["missed"]
                    cwe_framing_summary[cwe][framing]["detection"]["total"] += counts[
                        "detection"
                    ]["total"]
                    cwe_framing_summary[cwe][framing]["security_reason"][
                        "caught"
                    ] += counts["security_reason"]["caught"]
                    cwe_framing_summary[cwe][framing]["security_reason"][
                        "missed"
                    ] += counts["security_reason"]["missed"]
                    cwe_framing_summary[cwe][framing]["security_reason"][
                        "total"
                    ] += counts["security_reason"]["total"]

                    # Framing summary
                    framing_summary[framing]["detection"]["caught"] += counts[
                        "detection"
                    ]["caught"]
                    framing_summary[framing]["detection"]["missed"] += counts[
                        "detection"
                    ]["missed"]
                    framing_summary[framing]["detection"]["total"] += counts[
                        "detection"
                    ]["total"]
                    framing_summary[framing]["security_reason"]["caught"] += counts[
                        "security_reason"
                    ]["caught"]
                    framing_summary[framing]["security_reason"]["missed"] += counts[
                        "security_reason"
                    ]["missed"]
                    framing_summary[framing]["security_reason"]["total"] += counts[
                        "security_reason"
                    ]["total"]

                    # Model summary
                    model_summary[model_name]["detection"]["caught"] += counts[
                        "detection"
                    ]["caught"]
                    model_summary[model_name]["detection"]["missed"] += counts[
                        "detection"
                    ]["missed"]
                    model_summary[model_name]["detection"]["total"] += counts[
                        "detection"
                    ]["total"]
                    model_summary[model_name]["security_reason"]["caught"] += counts[
                        "security_reason"
                    ]["caught"]
                    model_summary[model_name]["security_reason"]["missed"] += counts[
                        "security_reason"
                    ]["missed"]
                    model_summary[model_name]["security_reason"]["total"] += counts[
                        "security_reason"
                    ]["total"]

    return cwe_summary, cwe_framing_summary, framing_summary, model_summary


def compute_metrics(cwe_summary, cwe_framing_summary, framing_summary, model_summary):
    """Compute rejection rate, security reason rate, and difficulty scores."""

    # CWE metrics
    cwe_metrics = {}
    for cwe, counts in cwe_summary.items():
        da_total = counts["detection"]["total"]
        da_caught = counts["detection"]["caught"]
        da_acc = (da_caught / da_total * 100) if da_total > 0 else 0

        # Rejection Rate = 1 - Detection Accuracy (complement)
        rejection_rate = 100 - da_acc

        srr_total = counts["security_reason"]["total"]
        srr_caught = counts["security_reason"]["caught"]
        srr_acc = (srr_caught / srr_total * 100) if srr_total > 0 else 0

        cwe_metrics[cwe] = {
            "detection_accuracy": da_acc,
            "rejection_rate": rejection_rate,
            "security_reason_rate": srr_acc,
            "n_detection": da_total,
            "n_srr": srr_total,
        }

    # CWE x Framing metrics
    cwe_framing_metrics = {}
    for cwe, framings in cwe_framing_summary.items():
        if cwe not in cwe_framing_metrics:
            cwe_framing_metrics[cwe] = {}
        for framing, counts in framings.items():
            da_total = counts["detection"]["total"]
            da_caught = counts["detection"]["caught"]
            da_acc = (da_caught / da_total * 100) if da_total > 0 else 0
            rejection_rate = 100 - da_acc

            cwe_framing_metrics[cwe][framing] = {
                "detection_accuracy": da_acc,
                "rejection_rate": rejection_rate,
                "n_samples": da_total,
            }

    # Framing metrics
    framing_metrics = {}
    for framing, counts in framing_summary.items():
        da_total = counts["detection"]["total"]
        da_caught = counts["detection"]["caught"]
        da_acc = (da_caught / da_total * 100) if da_total > 0 else 0
        rejection_rate = 100 - da_acc

        framing_metrics[framing] = {
            "detection_accuracy": da_acc,
            "rejection_rate": rejection_rate,
            "n_samples": da_total,
        }

    # Model metrics
    model_metrics = {}
    for model, counts in model_summary.items():
        da_total = counts["detection"]["total"]
        da_caught = counts["detection"]["caught"]
        da_acc = (da_caught / da_total * 100) if da_total > 0 else 0
        rejection_rate = 100 - da_acc

        model_metrics[model] = {
            "detection_accuracy": da_acc,
            "rejection_rate": rejection_rate,
            "n_samples": da_total,
        }

    return cwe_metrics, cwe_framing_metrics, framing_metrics, model_metrics


# ============================================================================
# CLUSTERING
# ============================================================================


def cluster_cwes(cwe_metrics):
    """Cluster CWEs based on detection difficulty, accuracy, and SRR."""

    cwes = sorted(cwe_metrics.keys())
    features = []

    for cwe in cwes:
        m = cwe_metrics[cwe]
        features.append(
            [m["rejection_rate"], m["security_reason_rate"], m["rejection_rate"]]
        )

    features = np.array(features)

    # Standardize
    scaler = StandardScaler()
    features_scaled = scaler.fit_transform(features)

    # Hierarchical clustering
    linkage_matrix = linkage(pdist(features_scaled, metric="euclidean"), method="ward")

    # PCA projection
    pca = PCA(n_components=2)
    features_pca = pca.fit_transform(features_scaled)

    return linkage_matrix, features_pca, cwes, scaler.mean_, scaler.scale_


# ============================================================================
# VISUALIZATION
# ============================================================================


def plot_cwe_clustering(linkage_matrix, features_pca, cwes, output_path):
    """Plot CWE clustering dendrogram and PCA projection."""

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(16, 6))

    # Dendrogram
    dendrogram(linkage_matrix, labels=cwes, ax=ax1, leaf_font_size=10)
    ax1.set_title(
        "CWE Hierarchical Clustering\n(Ward linkage on rejection rate)",
        fontsize=12,
        fontweight="bold",
    )
    ax1.set_ylabel("Distance", fontsize=11)

    # PCA projection
    scatter = ax2.scatter(
        features_pca[:, 0], features_pca[:, 1], s=200, alpha=0.7, cmap="viridis"
    )
    for i, cwe in enumerate(cwes):
        ax2.annotate(
            cwe.upper(),
            (features_pca[i, 0], features_pca[i, 1]),
            fontsize=10,
            fontweight="bold",
            ha="center",
            va="center",
        )

    ax2.set_xlabel(f"PC1", fontsize=11)
    ax2.set_ylabel(f"PC2", fontsize=11)
    ax2.set_title("CWE PCA Projection", fontsize=12, fontweight="bold")
    ax2.grid(alpha=0.3)

    plt.tight_layout()
    plt.savefig(output_path, dpi=300, bbox_inches="tight")
    print(f"✓ Saved: {output_path}")
    plt.close()


def plot_cwe_difficulty(cwe_metrics, output_path):
    """Plot CWE rejection rate ranking."""

    cwes = sorted(
        cwe_metrics.keys(), key=lambda c: cwe_metrics[c]["rejection_rate"], reverse=True
    )
    rejection_rates = [cwe_metrics[c]["rejection_rate"] for c in cwes]
    srrs = [cwe_metrics[c]["security_reason_rate"] for c in cwes]
    das = [cwe_metrics[c]["detection_accuracy"] for c in cwes]

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(14, 6))

    # Rejection rate bar chart
    colors = plt.cm.RdYlGn(np.array(rejection_rates) / 100)  # Green for low RR (good)
    ax1.barh(cwes, rejection_rates, color=colors, edgecolor="black", linewidth=1.2)
    ax1.set_xlabel("Rejection Rate (%)", fontsize=11, fontweight="bold")
    ax1.set_title("CWE Rejection Rate Ranking", fontsize=12, fontweight="bold")
    ax1.grid(axis="x", alpha=0.3)

    for i, (cwe, rr, da) in enumerate(zip(cwes, rejection_rates, das)):
        ax1.text(rr + 1, i, f"{rr:.1f}% (DA: {da:.1f}%)", va="center", fontsize=9)

    # RR vs SRR scatter
    ax2.scatter(rejection_rates, srrs, s=150, alpha=0.6, cmap="viridis")
    for i, cwe in enumerate(cwes):
        ax2.annotate(
            cwe.upper(),
            (rejection_rates[i], srrs[i]),
            fontsize=9,
            fontweight="bold",
            ha="center",
        )

    ax2.set_xlabel("Rejection Rate (%)", fontsize=11, fontweight="bold")
    ax2.set_ylabel("Security Reason Rate (%)", fontsize=11, fontweight="bold")
    ax2.set_title(
        "Rejection Rate vs Security Reason Rate", fontsize=12, fontweight="bold"
    )
    ax2.grid(alpha=0.3)
    ax2.set_xlim(5, 50)
    ax2.set_ylim(0, 100)

    plt.tight_layout()
    plt.savefig(output_path, dpi=300, bbox_inches="tight")
    print(f"✓ Saved: {output_path}")
    plt.close()


def plot_framing_effectiveness(framing_metrics, output_path):
    """Plot framing strategy effectiveness (rejection rate)."""

    framings = sorted(
        framing_metrics.keys(),
        key=lambda f: framing_metrics[f]["rejection_rate"],
        reverse=True,
    )
    rejection_rates = [framing_metrics[f]["rejection_rate"] for f in framings]

    fig, ax = plt.subplots(figsize=(12, 8))

    colors = plt.cm.RdYlGn_r(np.array(rejection_rates) / 100)
    bars = ax.barh(
        framings, rejection_rates, color=colors, edgecolor="black", linewidth=1.2
    )

    ax.set_xlabel("Rejection Rate (%)", fontsize=12, fontweight="bold")
    ax.set_title(
        "Framing Strategy Effectiveness (Paper Results)\nBy Rejection Rate",
        fontsize=13,
        fontweight="bold",
    )
    ax.grid(axis="x", alpha=0.3)

    for i, (framing, rate) in enumerate(zip(framings, rejection_rates)):
        ax.text(
            rate + 1, i, f"{rate:.1f}%", va="center", fontsize=10, fontweight="bold"
        )

    plt.tight_layout()
    plt.savefig(output_path, dpi=300, bbox_inches="tight")
    print(f"✓ Saved: {output_path}")
    plt.close()


def plot_cwe_framing_heatmap(cwe_framing_metrics, output_path):
    """Plot heatmap of rejection rate for each CWE x Framing pair."""

    cwes = sorted(cwe_framing_metrics.keys())
    framings = set()
    for cwe_data in cwe_framing_metrics.values():
        framings.update(cwe_data.keys())
    framings = sorted(framings)

    # Build matrix
    matrix = np.zeros((len(cwes), len(framings)))
    for i, cwe in enumerate(cwes):
        for j, framing in enumerate(framings):
            if framing in cwe_framing_metrics[cwe]:
                matrix[i, j] = cwe_framing_metrics[cwe][framing]["rejection_rate"]
            else:
                matrix[i, j] = np.nan

    fig, ax = plt.subplots(figsize=(14, 6))

    sns.heatmap(
        matrix,
        annot=True,
        fmt=".1f",
        cmap="RdYlGn",
        center=25,
        xticklabels=framings,
        yticklabels=cwes,
        ax=ax,
        cbar_kws={"label": "Rejection Rate (%)"},
    )

    ax.set_title(
        "Rejection Rate by CWE × Framing (Paper Results)",
        fontsize=13,
        fontweight="bold",
    )
    ax.set_xlabel("Framing Strategy", fontsize=11, fontweight="bold")
    ax.set_ylabel("CWE", fontsize=11, fontweight="bold")

    plt.xticks(rotation=45, ha="right")
    plt.tight_layout()
    plt.savefig(output_path, dpi=300, bbox_inches="tight")
    print(f"✓ Saved: {output_path}")
    plt.close()


def plot_model_comparison(model_metrics, output_path):
    """Plot model rejection rate comparison."""

    models = sorted(
        model_metrics.keys(),
        key=lambda m: model_metrics[m]["rejection_rate"],
    )
    rejection_rates = [model_metrics[m]["rejection_rate"] for m in models]
    das = [model_metrics[m]["detection_accuracy"] for m in models]

    fig, ax = plt.subplots(figsize=(12, 6))

    colors = plt.cm.RdYlGn(
        1 - np.array(rejection_rates) / 100
    )  # Green for low RR (good)
    ax.barh(models, rejection_rates, color=colors, edgecolor="black", linewidth=1.5)

    ax.set_xlabel("Rejection Rate (%)", fontsize=12, fontweight="bold")
    ax.set_title(
        "Model Performance Comparison (Paper Results)", fontsize=13, fontweight="bold"
    )
    ax.set_xlim(0, 60)
    ax.grid(axis="x", alpha=0.3)

    for i, (model, rr, da) in enumerate(zip(models, rejection_rates, das)):
        ax.text(
            rr + 1,
            i,
            f"{rr:.1f}% (DA: {da:.1f}%)",
            va="center",
            fontweight="bold",
            fontsize=9,
        )

    plt.tight_layout()
    plt.savefig(output_path, dpi=300, bbox_inches="tight")
    print(f"✓ Saved: {output_path}")
    plt.close()


# ============================================================================
# EXPORT ANALYSIS
# ============================================================================


def export_analysis(
    cwe_metrics, cwe_framing_metrics, framing_metrics, model_metrics, output_path
):
    """Export analysis results to JSON."""

    export_data = {
        "cwe_summary": {
            cwe: {
                "detection_accuracy": round(m["detection_accuracy"], 2),
                "rejection_rate": round(m["rejection_rate"], 2),
                "security_reason_rate": round(m["security_reason_rate"], 2),
                "n_samples_detection": m["n_detection"],
                "n_samples_srr": m["n_srr"],
            }
            for cwe, m in cwe_metrics.items()
        },
        "framing_effectiveness": {
            framing: {
                "detection_accuracy": round(m["detection_accuracy"], 2),
                "rejection_rate": round(m["rejection_rate"], 2),
                "n_samples": m["n_samples"],
            }
            for framing, m in framing_metrics.items()
        },
        "model_summary": {
            model: {
                "detection_accuracy": round(m["detection_accuracy"], 2),
                "rejection_rate": round(m["rejection_rate"], 2),
                "n_samples": m["n_samples"],
            }
            for model, m in model_metrics.items()
        },
    }

    with open(output_path, "w") as f:
        json.dump(export_data, f, indent=2)

    print(f"✓ Exported: {output_path}")


# ============================================================================
# MAIN
# ============================================================================


def main():
    print("\n" + "=" * 80)
    print("PAPER RESULTS CLUSTERING ANALYSIS (Retained Challenge Split)")
    print("=" * 80)

    print("\n🔄 Extracting data from paper's evaluation sources...")
    results = extract_paper_data(use_retained_split=True)

    print("📊 Aggregating by CWE, Framing, and Model...")
    cwe_summary, cwe_framing_summary, framing_summary, model_summary = (
        aggregate_by_cwe_and_framing(results)
    )

    print("📈 Computing metrics...")
    cwe_metrics, cwe_framing_metrics, framing_metrics, model_metrics = compute_metrics(
        cwe_summary, cwe_framing_summary, framing_summary, model_summary
    )

    print("\n" + "=" * 80)
    print("SUMMARY STATISTICS")
    print("=" * 80)

    print(f"\n📊 CWE Rejection Rate Ranking:")
    sorted_cwes = sorted(
        cwe_metrics.items(), key=lambda x: x[1]["rejection_rate"], reverse=True
    )
    for i, (cwe, m) in enumerate(sorted_cwes, 1):
        print(
            f"{i:2d}. {cwe.upper():10s} | DA: {m['detection_accuracy']:5.1f}% | RR: {m['rejection_rate']:5.1f}% | SRR: {m['security_reason_rate']:5.1f}%"
        )

    print(f"\n🎭 Framing Effectiveness (by rejection rate):")
    sorted_framings = sorted(
        framing_metrics.items(), key=lambda x: x[1]["rejection_rate"], reverse=True
    )
    for i, (framing, m) in enumerate(sorted_framings, 1):
        print(
            f"{i:2d}. {framing:35s} | RR: {m['rejection_rate']:5.1f}% | DA: {m['detection_accuracy']:5.1f}% | Samples: {m['n_samples']:4d}"
        )

    print(f"\n🤖 Model Performance:")
    sorted_models = sorted(model_metrics.items(), key=lambda x: x[1]["rejection_rate"])
    for i, (model, m) in enumerate(sorted_models, 1):
        print(
            f"{i:2d}. {model:45s} | DA: {m['detection_accuracy']:5.1f}% | RR: {m['rejection_rate']:5.1f}% | Samples: {m['n_samples']:5d}"
        )

    print("\n📊 Creating visualizations...")
    linkage_matrix, features_pca, cwes, _, _ = cluster_cwes(cwe_metrics)

    base_path = Path("/Users/rmelo/Documents/GitHub/malicious-pr-bench")

    plot_cwe_clustering(
        linkage_matrix,
        features_pca,
        cwes,
        str(base_path / "retained_cwe_clustering.png"),
    )
    plot_cwe_difficulty(cwe_metrics, str(base_path / "retained_cwe_difficulty.png"))
    plot_framing_effectiveness(
        framing_metrics, str(base_path / "retained_framing_effectiveness.png")
    )
    plot_cwe_framing_heatmap(
        cwe_framing_metrics, str(base_path / "retained_cwe_framing_heatmap.png")
    )
    plot_model_comparison(
        model_metrics, str(base_path / "retained_model_comparison.png")
    )

    print("\n📋 Exporting analysis...")
    export_analysis(
        cwe_metrics,
        cwe_framing_metrics,
        framing_metrics,
        model_metrics,
        str(base_path / "retained_results_analysis.json"),
    )

    print("\n" + "=" * 80)
    print("✓ Analysis complete!")
    print("=" * 80 + "\n")

    return cwe_metrics, framing_metrics, model_metrics


if __name__ == "__main__":
    cwe_metrics, framing_metrics, model_metrics = main()
