# Analysis and Data Extraction Scripts

Essential scripts for reproducing the paper's analysis and visualizations.

## Scripts

### `extract_nips_results_with_srr.py`
**Generates the aggregated JSON results from raw evaluation logs**

This is the **data pipeline** script that:
1. Scans evaluation logs from `/logs/results_nips/` and `/logs/filtering_releases/`
2. Extracts detection accuracy and security reasoning rates
3. Aggregates results per-CWE and per-framing
4. Generates JSON output with standard errors

**Usage:**
```bash
# Generate for all samples
cd visualizations/scripts/
python3 extract_nips_results_with_srr.py
# Output: nips_results_with_srr.json (in parent directory)

# Generate for retained challenge split only
python3 extract_nips_results_with_srr.py --retained
# Output: nips_results_with_srr_retained_split.json (in parent directory)
```

**Output:**
- `nips_results_with_srr.json` — Full evaluation results (all samples)
- `nips_results_with_srr_retained_split.json` — Filtered to 1,062 retained samples

**Structure:**
```json
{
  "per_cwe": {
    "model_name": {
      "plain": {
        "cwe79": {
          "detection_accuracy": {
            "accuracy": 99.1,
            "standard_error": 1.01,
            "n_samples": 120
          },
          "security_reason_rate": { ... }
        }
      }
    }
  },
  "per_framing": { ... }
}
```

---

### `extract_message_counts.py`
**Extracts reasoning depth: how many back-and-forth messages each model needed**

This script analyzes reasoning complexity by measuring message counts from evaluation logs:
1. Scans evaluation logs from `/logs/results_nips/` and `/logs/filtering_releases/`
2. Extracts message count from each sample's summary JSON
3. Aggregates per-model and per-CWE statistics
4. Computes mean, min, max message counts
5. Correlates message count with detection accuracy

**Usage:**
```bash
# Extract for all samples
cd visualizations/scripts/
python3 extract_message_counts.py
# Output: message_counts.json (in parent directory)

# Extract for retained challenge split only
python3 extract_message_counts.py --retained
# Output: message_counts_retained_split.json (in parent directory)
```

**Output:**
```json
{
  "metadata": {
    "total_samples": 12610,
    "filtered": true
  },
  "per_model": {
    "bedrock_global.anthropic.claude-opus-4-7": {
      "n_samples": 2124,
      "message_count": {
        "mean": 16.72,
        "min": 5,
        "max": 274
      },
      "detection_accuracy": {
        "accuracy": 96.8,
        "n_samples": 2124
      }
    }
  },
  "per_cwe": { ... },
  "raw_samples": { ... }
}
```

**Key Finding**: Frontier models achieve 96% accuracy with ~23 avg messages; baseline models achieve 53% accuracy with ~18 avg messages—efficiency matters more than effort.

---

### `analyze_retained_split_clustering.py`
**Clustering analysis for retained challenge split**

Generates:
1. **CWE Clustering** — Hierarchical clustering + PCA of CWEs by difficulty
2. **Framing Clustering** — Hierarchical clustering + PCA of framings by effectiveness
3. **CWE Difficulty Ranking** — Bar charts of vulnerability difficulty
4. **Framing Effectiveness Ranking** — Bar charts of framing success rates

**Usage:**
```bash
cd visualizations/scripts/
python3 analyze_retained_split_clustering.py
```

**Outputs:**
- `retained_split_cwe_framing_clustering.png` — 4-panel clustering analysis
- `retained_split_cwe_difficulty.png` — CWE difficulty and quality tradeoff
- `retained_split_framing_effectiveness.png` — Framing effectiveness ranking
- `retained_split_clustering_results.json` — Clustering metrics (PCA variance, etc.)

---

## Data Dependencies

Both scripts require data files in the parent directory:

```
malicious-pr-bench/
├── logs/
│   ├── results_nips/           (Frontier model evaluation logs)
│   └── filtering_releases/     (Baseline model evaluation logs)
├── retained_sample_ids.json    (Retained challenge split definition)
└── visualizations/
    └── scripts/
        ├── extract_nips_results_with_srr.py
        └── analyze_retained_split_clustering.py
```

## Data Flow

**Main Pipeline (Detection Accuracy & Security Reasoning):**
```
Raw Logs (logs/*.eval)
    ↓
extract_nips_results_with_srr.py
    ↓
nips_results_with_srr_retained_split.json
    ↓
generate_nips_plots.ipynb (in parent directory)
    ↓
Publication-ready visualizations (1_cwe_scatter.png, 2_model_scatter.png, etc.)
```

**Message Count Pipeline (Reasoning Depth):**
```
Raw Logs (logs/*.eval)
    ↓
extract_message_counts.py
    ↓
message_counts_retained_split.json
    ↓
generate_message_count_plots.py (in parent directory)
    ↓
Reasoning depth visualizations (6_message_count_accuracy.png, etc.)
```

## Running the Full Pipeline

```bash
# Step 1: Generate aggregated results from logs
cd visualizations/scripts/
python3 extract_nips_results_with_srr.py --retained

# Step 2: Generate publication plots
cd ..
python3 generate_nips_plots.py

# Step 3 (Optional): Generate clustering analysis
cd scripts/
python3 analyze_retained_split_clustering.py
```

All output files are saved to parent directory (`malicious-pr-bench/`).

## Notes

- **extract_nips_results_with_srr.py** is deterministic and can be re-run to regenerate JSON data
- Paths in scripts are relative and assume execution from `visualizations/scripts/` directory
- Scripts use plain prompt data only from evaluation logs
- All analysis uses retained challenge split (1,062 curated samples) by default
