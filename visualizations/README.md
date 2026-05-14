# NIPS Publication Visualizations

Complete visualization and analysis pipeline for the malicious PR benchmark paper.

## Folder Structure

```
visualizations/
├── README.md                    (This file - overview)
├── generate_nips_plots.py      (Main visualization script)
├── [PNG outputs]               (Generated scatter plots)
└── scripts/
    ├── README.md               (Scripts documentation)
    ├── extract_nips_results_with_srr.py     (Data extraction)
    └── analyze_retained_split_clustering.py (Clustering analysis)
```

## Notebook

**`generate_nips_plots.ipynb`** — Interactive Jupyter notebook for visualization generation
- Generates all three publication-quality scatter plots
- Uses plain prompt data only (retained challenge split: 1,062 samples)
- Includes markdown documentation and explanations
- Can be run cell-by-cell for iterative exploration or all at once
- Outputs PNG files at 300 DPI, publication-ready for NIPS

**To run:**
```bash
jupyter notebook generate_nips_plots.ipynb
```

Then execute the cells in order:
1. Setup and Configuration
2. Load Data
3. Plot 1: CWE Scatter
4. Plot 2: Model Scatter
5. Plot 3: CWE-Framing Scatter

## Output Plots

### 1_cwe_scatter.png
**CWE Vulnerability Characteristics**
- X-axis: Rejection Rate (%) — how often models are fooled
- Y-axis: Security Reasoning Rate (%) — how often models provide security justifications
- Shows natural grouping of vulnerabilities:
  - Green (easy): CWE-89 (SQL injection, ~25% RR)
  - Red (hard): CWE-416 (Use-After-Free, ~43% RR)
- Key insight: Some vulnerabilities fundamentally harder to reason about

### 2_model_scatter.png
**Model Robustness Analysis**
- X-axis: Average Detection Accuracy (%) across all CWEs
- Y-axis: Consistency (Std Dev %) of accuracy across CWEs
- Red dots: Frontier models (Opus, GPT-5.5, GLM-5)
  - Right side, 80-100% accuracy
  - Low variance (consistent across all CWEs)
- Blue dots: Baseline models (GPT-5.4-nano, DeepSeek, Kimi, Grok)
  - Left side, 35-65% accuracy
  - High variance (inconsistent across CWEs)
- Key insight: Frontier models are categorically different from baselines

### 3_cwe_framing_scatter.png
**Social Engineering Effectiveness by Vulnerability**
- X-axis: CWE Difficulty (Baseline Rejection Rate %)
- Y-axis: CWE-Framing Attack Success Rate (%)
- Red bubbles: High effectiveness (>50% success rate)
- Blue bubbles: Low effectiveness (≤50% success rate)
- Bubble size: Sample count for that CWE-Framing combination
- CWE labels at top: Identify which CWE each region represents
- Key insight: Social engineering more effective on harder vulnerabilities

## Data Sources

Scripts read from parent directory:
- `nips_results_with_srr_retained_split.json` — Aggregated results
- `retained_sample_ids.json` — Retained challenge split definition
- `logs/results_nips/` — Frontier model evaluation logs
- `logs/filtering_releases/` — Baseline model evaluation logs

## Running the Notebook

**Option 1: Interactive mode**
```bash
cd visualizations/
jupyter notebook generate_nips_plots.ipynb
```

**Option 2: Run all cells**
```bash
cd visualizations/
jupyter nbconvert --to notebook --execute generate_nips_plots.ipynb
```

All plots are saved to the visualizations directory at 300 DPI.

## Plot Specifications

- **Resolution**: 300 DPI (publication-ready)
- **Format**: PNG with white background
- **Styling**: Publication-quality seaborn whitegrid theme
- **Data**: Plain prompt only, retained challenge split (1,062 samples)
- **Models**: 7 models (Frontier: Opus 4.7, GPT-5.5, GLM-5; Baseline: GPT-5.4-nano, DeepSeek, Kimi, Grok)
- **CWEs**: All 10 CWEs represented

## Key Findings

1. **Vulnerability difficulty varies**: Some CWEs (SQL injection) are easy to detect; others (Use-After-Free) are fundamentally harder
2. **Frontier models fundamentally different**: Clear stratification shows frontier models achieve high accuracy consistently
3. **Attacks compound on hard targets**: Social engineering is much more effective against difficult-to-detect vulnerabilities
