"""
Advanced CWE-Framing Interaction Analysis
Analyzes which (CWE, framing) pairs are most vulnerable, per-model behavior, etc.
"""

import json
import warnings
from collections import defaultdict

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import seaborn as sns

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
# MODEL COMPARISON ANALYSIS
# ============================================================================


def analyze_model_performance(framing_data):
    """Analyze per-model detection performance and vulnerability patterns."""

    model_perf = {}

    for model, framings in framing_data.items():
        total_attacks = sum(f["total"] for f in framings.values())
        total_caught = sum(f["caught"] for f in framings.values())
        total_missed = sum(f["missed"] for f in framings.values())

        # Extract model name (last part after dots)
        model_short = model.split(".")[-1]

        model_perf[model_short] = {
            "full_name": model,
            "total_detection_accuracy": (
                (total_caught / total_attacks) * 100 if total_attacks > 0 else 0
            ),
            "total_attacks": total_attacks,
            "total_caught": total_caught,
            "total_missed": total_missed,
            "missed_by_framing": {},
        }

        # Track which framings fool this model most
        for framing, stats in framings.items():
            miss_rate = (
                (stats["missed"] / stats["total"]) * 100 if stats["total"] > 0 else 0
            )
            model_perf[model_short]["missed_by_framing"][framing] = {
                "miss_rate": miss_rate,
                "missed": stats["missed"],
                "total": stats["total"],
            }

    return model_perf


def analyze_cwe_framing_interaction(srr_data):
    """Analyze which (CWE, framing) pairs are hardest to defend against."""

    # This would require access to per-sample data, which we may not have in aggregated format
    # Instead, we create a proxy based on combining CWE difficulty + framing effectiveness

    with open("nips_frontier_results_by_framing.json") as f:
        framing_data = json.load(f)

    model_key = [k for k in framing_data.keys() if "opus-4-7" in k][0]

    # Get average detection difficulty per CWE
    cwe_difficulty = {}
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
        for model in srr_data["per_cwe"]:
            if cwe_id in srr_data["per_cwe"][model].get("plain", {}):
                das.append(
                    srr_data["per_cwe"][model]["plain"][cwe_id]["detection_accuracy"][
                        "accuracy"
                    ]
                )
        if das:
            cwe_difficulty[cwe_id] = 100 - np.mean(das)

    # Get framing success rates
    framing_success = {}
    for framing, stats in framing_data[model_key].items():
        framing_success[framing] = stats["accuracy"]

    # Compute interaction score (difficulty * effectiveness)
    interactions = []
    for cwe_id, difficulty in cwe_difficulty.items():
        for framing, success in framing_success.items():
            score = (difficulty / 100) * (success / 100) * 100
            interactions.append(
                {
                    "cwe": cwe_id.upper(),
                    "framing": framing.replace("_", " ").title(),
                    "interaction_score": score,
                    "cwe_difficulty": difficulty,
                    "framing_success": success,
                }
            )

    return pd.DataFrame(interactions).sort_values("interaction_score", ascending=False)


# ============================================================================
# VISUALIZATION FUNCTIONS
# ============================================================================


def plot_model_performance(model_perf):
    """Compare detection accuracy across models."""

    models = sorted(
        model_perf.keys(),
        key=lambda x: model_perf[x]["total_detection_accuracy"],
        reverse=True,
    )
    accuracies = [model_perf[m]["total_detection_accuracy"] for m in models]

    fig, ax = plt.subplots(figsize=(12, 6))

    # Color gradient based on accuracy
    colors = plt.cm.RdYlGn(np.array(accuracies) / 100)

    bars = ax.barh(models, accuracies, color=colors, edgecolor="black", linewidth=1.5)

    # Add value labels
    for i, (model, acc) in enumerate(zip(models, accuracies)):
        ax.text(acc + 1, i, f"{acc:.1f}%", va="center", fontweight="bold", fontsize=10)

    ax.set_xlabel("Overall Detection Accuracy (%)", fontsize=12, fontweight="bold")
    ax.set_title(
        "Model Performance Comparison: Detection Accuracy Across All Framings",
        fontsize=13,
        fontweight="bold",
    )
    ax.set_xlim(0, 105)
    ax.grid(axis="x", alpha=0.3)

    plt.tight_layout()
    plt.savefig(
        "/Users/rmelo/Documents/GitHub/malicious-pr-bench/analysis_model_comparison.png",
        dpi=300,
        bbox_inches="tight",
    )
    print("✓ Saved: analysis_model_comparison.png")
    plt.close()


def plot_model_vulnerability_profile(model_perf):
    """Show which framings are most effective for each model."""

    # Get top 5 models
    models = sorted(
        model_perf.keys(),
        key=lambda x: model_perf[x]["total_detection_accuracy"],
        reverse=True,
    )[:5]

    fig, axes = plt.subplots(2, 3, figsize=(18, 10))
    axes = axes.flatten()

    for idx, model in enumerate(models):
        framing_misses = model_perf[model]["missed_by_framing"]
        framings = sorted(
            framing_misses.keys(),
            key=lambda x: framing_misses[x]["miss_rate"],
            reverse=True,
        )[:10]

        miss_rates = [framing_misses[f]["miss_rate"] for f in framings]
        framing_labels = [f.replace("_", " ").title() for f in framings]

        ax = axes[idx]
        colors_vuln = [
            "#FF6B6B" if m > 30 else "#FFA07A" if m > 15 else "#90EE90"
            for m in miss_rates
        ]
        ax.barh(
            framing_labels,
            miss_rates,
            color=colors_vuln,
            edgecolor="black",
            linewidth=1.2,
        )
        ax.set_xlabel("Miss Rate (%)", fontsize=10)
        ax.set_title(
            f'{model}\n(Overall DA: {model_perf[model]["total_detection_accuracy"]:.1f}%)',
            fontsize=11,
            fontweight="bold",
        )
        ax.set_xlim(0, max(miss_rates) + 5)
        ax.grid(axis="x", alpha=0.3)

    # Hide extra subplot
    axes[-1].set_visible(False)

    plt.tight_layout()
    plt.savefig(
        "/Users/rmelo/Documents/GitHub/malicious-pr-bench/analysis_model_vulnerability_profile.png",
        dpi=300,
        bbox_inches="tight",
    )
    print("✓ Saved: analysis_model_vulnerability_profile.png")
    plt.close()


def plot_cwe_framing_interaction(interaction_df):
    """Plot top CWE-framing interaction pairs."""

    # Top 20 hardest (CWE, framing) combinations
    top_interactions = interaction_df.head(20).copy()

    fig, ax = plt.subplots(figsize=(12, 8))

    labels = [
        (
            f"{row['cwe']}\n({row['framing'][:15]}...)"
            if len(row["framing"]) > 15
            else f"{row['cwe']}\n({row['framing']})"
        )
        for _, row in top_interactions.iterrows()
    ]
    scores = top_interactions["interaction_score"].values

    colors_interact = plt.cm.Reds(scores / scores.max())
    ax.bar(
        range(len(labels)),
        scores,
        color=colors_interact,
        edgecolor="black",
        linewidth=1.2,
    )

    ax.set_xticks(range(len(labels)))
    ax.set_xticklabels(labels, fontsize=9, rotation=45, ha="right")
    ax.set_ylabel("Interaction Score", fontsize=12, fontweight="bold")
    ax.set_title(
        "Top 20 Hardest CWE-Framing Interaction Pairs\n(Score = Difficulty × Effectiveness)",
        fontsize=13,
        fontweight="bold",
    )
    ax.grid(axis="y", alpha=0.3)

    plt.tight_layout()
    plt.savefig(
        "/Users/rmelo/Documents/GitHub/malicious-pr-bench/analysis_cwe_framing_interaction.png",
        dpi=300,
        bbox_inches="tight",
    )
    print("✓ Saved: analysis_cwe_framing_interaction.png")
    plt.close()


# ============================================================================
# SUMMARY STATISTICS
# ============================================================================


def print_model_analysis(model_perf):
    """Print detailed model performance analysis."""

    print("\n" + "=" * 80)
    print("MODEL-LEVEL VULNERABILITY ANALYSIS")
    print("=" * 80)

    sorted_models = sorted(
        model_perf.items(), key=lambda x: x[1]["total_detection_accuracy"], reverse=True
    )

    print("\n🎯 OVERALL PERFORMANCE RANKING:")
    print("-" * 80)
    for rank, (model, perf) in enumerate(sorted_models, 1):
        print(
            f"{rank:2d}. {model:20s} | DA: {perf['total_detection_accuracy']:6.2f}% | "
            f"Attacks: {perf['total_attacks']:4d} | Caught: {perf['total_caught']:4d} | "
            f"Missed: {perf['total_missed']:4d}"
        )

    print("\n\n🚨 TOP 3 MODELS - MOST EFFECTIVE FRAMINGS AGAINST THEM:")
    print("-" * 80)
    for rank, (model, perf) in enumerate(sorted_models[:3], 1):
        print(f"\n{rank}. {model}:")
        framing_sorted = sorted(
            perf["missed_by_framing"].items(),
            key=lambda x: x[1]["miss_rate"],
            reverse=True,
        )[:5]
        for framing, miss_data in framing_sorted:
            print(
                f"   • {framing.replace('_', ' ').title():35s} | "
                f"Miss Rate: {miss_data['miss_rate']:5.1f}% | "
                f"({miss_data['missed']}/{miss_data['total']} attacks)"
            )

    print("\n\n📊 PERFORMANCE VARIANCE ACROSS FRAMINGS:")
    print("-" * 80)
    for model, perf in sorted_models:
        miss_rates = [
            miss_data["miss_rate"] for miss_data in perf["missed_by_framing"].values()
        ]
        print(
            f"{model:20s} | Avg Miss Rate: {np.mean(miss_rates):5.1f}% | "
            f"Std Dev: {np.std(miss_rates):5.1f}% | "
            f"Min: {np.min(miss_rates):5.1f}% | Max: {np.max(miss_rates):5.1f}%"
        )


def print_interaction_analysis(interaction_df):
    """Print CWE-framing interaction analysis."""

    print("\n" + "=" * 80)
    print("CWE-FRAMING INTERACTION ANALYSIS")
    print("=" * 80)

    print("\n🎯 TOP 15 HARDEST ATTACK PAIRS (by interaction score):")
    print("-" * 80)
    for rank, row in interaction_df.head(15).iterrows():
        print(
            f"{rank+1:2d}. {row['cwe']:8s} × {row['framing']:35s} | "
            f"Score: {row['interaction_score']:5.1f}"
        )

    print("\n\n📈 CWE RANKING BY AVERAGE INTERACTION DIFFICULTY:")
    print("-" * 80)
    cwe_avg_interact = (
        interaction_df.groupby("cwe")["interaction_score"]
        .mean()
        .sort_values(ascending=False)
    )
    for rank, (cwe, score) in enumerate(cwe_avg_interact.items(), 1):
        print(f"{rank:2d}. {cwe:8s} | Avg Interaction Score: {score:6.2f}")

    print("\n\n🎭 FRAMING RANKING BY AVERAGE INTERACTION EFFECTIVENESS:")
    print("-" * 80)
    framing_avg_interact = (
        interaction_df.groupby("framing")["interaction_score"]
        .mean()
        .sort_values(ascending=False)
    )
    for rank, (framing, score) in enumerate(framing_avg_interact.items(), 1):
        print(f"{rank:2d}. {framing:40s} | Avg Score: {score:6.2f}")

    print("\n" + "=" * 80 + "\n")


# ============================================================================
# EXPORT DATA
# ============================================================================


def export_advanced_analysis(model_perf, interaction_df):
    """Export advanced analysis data."""

    export_data = {
        "model_performance": {
            model: {
                "detection_accuracy": round(perf["total_detection_accuracy"], 2),
                "total_attacks": perf["total_attacks"],
                "caught": perf["total_caught"],
                "missed": perf["total_missed"],
            }
            for model, perf in model_perf.items()
        },
        "top_cwe_framing_pairs": [
            {
                "cwe": row["cwe"],
                "framing": row["framing"],
                "interaction_score": round(row["interaction_score"], 2),
                "cwe_difficulty": round(row["cwe_difficulty"], 2),
                "framing_success": round(row["framing_success"], 2),
            }
            for _, row in interaction_df.head(30).iterrows()
        ],
    }

    with open(
        "/Users/rmelo/Documents/GitHub/malicious-pr-bench/analysis_advanced.json", "w"
    ) as f:
        json.dump(export_data, f, indent=2)

    print("✓ Exported: analysis_advanced.json")


# ============================================================================
# MAIN
# ============================================================================


def main():
    print("\n🔄 Loading data...")
    framing_data, srr_data = load_data()

    print("📊 Analyzing model performance...")
    model_perf = analyze_model_performance(framing_data)

    print("🔍 Computing CWE-Framing interactions...")
    interaction_df = analyze_cwe_framing_interaction(srr_data)

    print("\n📊 Creating visualizations...")
    plot_model_performance(model_perf)
    plot_model_vulnerability_profile(model_perf)
    plot_cwe_framing_interaction(interaction_df)

    print("\n📋 Exporting advanced analysis data...")
    export_advanced_analysis(model_perf, interaction_df)

    print_model_analysis(model_perf)
    print_interaction_analysis(interaction_df)

    return model_perf, interaction_df


if __name__ == "__main__":
    model_perf, interaction_df = main()
