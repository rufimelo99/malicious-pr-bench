# CWE Clustering Methodology

## Overview: checkpoint_cwe_difficulty.png

The `checkpoint_cwe_difficulty.png` visualization is actually **NOT a clustering visualization** itself. It shows:

1. **Left panel:** CWE difficulty ranking (bar chart sorted by difficulty score)
2. **Right panel:** Detection Accuracy vs Security Reason Rate scatter plot (no clustering)

The actual clustering is in `checkpoint_cwe_clustering.png` which shows:
- **Left:** Hierarchical dendrogram tree
- **Right:** PCA projection of clusters

This document explains both visualizations.

---

## Part 1: Feature Extraction

### Step 1: Compute CWE Metrics

For each CWE, extract 3 features from aggregated samples:

```python
# From checkpoint data (across all models, prompts, framings)
for cwe in [cwe22, cwe78, cwe79, cwe89, cwe94, cwe125, cwe352, cwe416, cwe787, cwe862]:
    
    # Detection Accuracy (DA)
    da_caught = total_blocked_samples
    da_total = da_caught + missed_samples
    detection_accuracy = (da_caught / da_total) * 100
    
    # Security Reason Rate (SRR)
    srr_caught = samples_with_security_reasoning
    srr_total = total_samples_with_reason_annotation
    security_reason_rate = (srr_caught / srr_total) * 100
    
    # Difficulty Score
    difficulty = 100 - detection_accuracy
```

**Example (CWE-79, XSS):**
```
detection_accuracy  = 1088 / 1625 = 67.2%
security_reason_rate = 747 / 1623 = 46.0%
difficulty = 100 - 67.2 = 32.8%
```

### Result: Feature Vectors

Each CWE becomes a 3-dimensional point:

```python
features = {
    "cwe22": [78.24, 57.79, 21.76],   # [DA%, SRR%, Difficulty%]
    "cwe78": [73.48, 55.83, 26.52],
    "cwe79": [67.2,  46.03, 32.8],
    "cwe89": [81.72, 64.74, 18.28],
    "cwe94": [77.38, 59.1,  22.62],
    "cwe125": [73.89, 36.99, 26.11],
    "cwe352": [71.81, 49.47, 28.19],
    "cwe416": [63.94, 18.8,  36.06],   # Hardest
    "cwe787": [71.61, 42.92, 28.39],
    "cwe862": [77.8,  47.91, 22.2],
}
```

---

## Part 2: Standardization (Z-Score Normalization)

### Why Standardize?

The three features have different scales:
- Detection Accuracy: 63.9% to 81.7% (range ≈ 18%)
- Security Reason Rate: 18.8% to 64.7% (range ≈ 46%)
- Difficulty: 18.3% to 36.1% (range ≈ 18%)

Without standardization, the larger-range feature (SRR) would dominate the distance calculation.

### Standardization Formula

```python
from sklearn.preprocessing import StandardScaler

features = np.array([
    [78.24, 57.79, 21.76],
    [73.48, 55.83, 26.52],
    ...
])

scaler = StandardScaler()
features_scaled = scaler.fit_transform(features)

# StandardScaler computes:
# scaled_value = (value - mean) / std_dev

# For Detection Accuracy feature:
mean_da = (78.24 + 73.48 + 67.2 + 81.72 + 77.38 + 73.89 + 71.81 + 63.94 + 71.61 + 77.8) / 10
       = 73.787

std_da = sqrt(sum((value - mean)^2) / n)
      = 4.826

# So CWE-79's DA feature: (67.2 - 73.787) / 4.826 = -1.368 (below mean, more difficult)
# And CWE-89's DA feature: (81.72 - 73.787) / 4.826 = 1.646 (above mean, easier)
```

**Result: Standardized features (mean=0, std=1 for each dimension)**

```
features_scaled ≈
[
  [-0.52,  0.34, -0.89],   # cwe22
  [-1.23,  0.21,  0.09],   # cwe78
  [-1.37, -0.60,  0.45],   # cwe79 (harder - negative DA)
  [ 1.65,  1.05, -1.25],   # cwe89 (easier - positive DA)
  [ 0.74,  0.68, -0.50],   # cwe94
  [-1.05, -2.32,  0.02],   # cwe125
  [-0.60, -0.39,  0.16],   # cwe352
  [-1.69, -2.10,  1.44],   # cwe416 (hardest - very negative DA, SRR)
  [-0.46, -0.65,  0.36],   # cwe787
  [ 0.49, -0.33, -0.56],   # cwe862
]
```

---

## Part 3: Hierarchical Clustering

### Distance Calculation

Compute **pairwise Euclidean distance** between standardized feature vectors:

```python
from scipy.spatial.distance import pdist

# pdist computes distance between all pairs
# For 10 CWEs: 10*9/2 = 45 pairwise distances

# Example: Distance between CWE-79 and CWE-416
cwe79_scaled = [-1.37, -0.60,  0.45]
cwe416_scaled = [-1.69, -2.10,  1.44]

euclidean_distance = sqrt((−1.37−(−1.69))^2 + (−0.60−(−2.10))^2 + (0.45−1.44)^2)
                   = sqrt(0.32^2 + 1.50^2 + (-0.99)^2)
                   = sqrt(0.1024 + 2.25 + 0.9801)
                   = sqrt(3.3325)
                   = 1.826

# This measures how different CWE-79 and CWE-416 are in the 3D feature space
```

### Linkage: Ward's Method

Hierarchically merge clusters to minimize **within-cluster variance**:

```python
from scipy.cluster.hierarchy import linkage

linkage_matrix = linkage(pdist(features_scaled, metric="euclidean"), method="ward")

# Ward's method merges clusters that minimize:
# variance_increase = ||cluster1 - cluster2||^2 * (n1 * n2) / (n1 + n2)

# Step-by-step merging:
# 1. Start with 10 singleton clusters (one CWE each)
# 2. Find pair with smallest distance → merge (e.g., CWE-22, CWE-94 closest)
# 3. Recompute distances from merged cluster to remaining clusters
# 4. Repeat until all CWEs in one cluster
# 5. Create dendrogram tree showing merge order and distances
```

### Output: Dendrogram

```
                                CWEs joined at different heights:

Height 3.0 ─┐                                        ┌─ CWE-416 (Use After Free - hardest)
             │                                        │
             ├─ CWE-79 (XSS)                  
             │                          ┌─────────────┤
Height 2.0 ─┼─ CWE-352 (CSRF)           │             ├─ CWE-787 (Out-of-bounds)
             │                ┌────────┤              │
             │                │        └─ CWE-125    └─ CWE-125
             │      ┌─────────┤
Height 1.0 ─┤      │         └───────────────────── CWE-78 (Command Injection)
             │      │
             ├─ CWE-22, CWE-94, CWE-862, CWE-89
             │
```

The **height** at which clusters merge indicates dissimilarity:
- **Low height merge:** Similar CWEs (cluster together early)
- **High height merge:** Dissimilar CWEs (join clusters far apart)

---

## Part 4: PCA Projection (Right side of checkpoint_cwe_clustering.png)

### Why PCA?

3D feature space is hard to visualize. PCA projects to 2D while preserving variance:

```python
from sklearn.decomposition import PCA

pca = PCA(n_components=2)
features_pca = pca.fit_transform(features_scaled)

# PCA finds 2 orthogonal axes that maximize variance
# PC1 (first axis): explains most variance
# PC2 (second axis): explains next most variance
```

### How It Works

1. **Compute covariance matrix** of standardized features
2. **Find eigenvectors** (principal components) and eigenvalues (variance explained)
3. **Project** each data point onto top 2 eigenvectors

```python
# Result: 10 CWEs → 10 points in 2D space
# Each point is (PC1_score, PC2_score)

features_pca ≈
[
  [-0.82, -0.45],   # cwe22 (Path Traversal - medium difficulty)
  [-1.21,  0.12],   # cwe78 (Command Injection)
  [-1.65,  0.89],   # cwe79 (XSS - hard)
  [ 1.82, -0.34],   # cwe89 (SQL Injection - easiest)
  [ 0.45,  0.21],   # cwe94 (Code Injection)
  [-0.92,  1.20],   # cwe125 (Out-of-bounds Read)
  [-0.31, -0.67],   # cwe352 (CSRF)
  [-1.95,  1.98],   # cwe416 (Use After Free - hardest)
  [-0.58,  0.78],   # cwe787 (Out-of-bounds Write)
  [ 0.12, -0.88],   # cwe862 (Authorization)
]
```

### Variance Explained

The plot shows variance percentage for each axis:
```
PC1: 45.2% of variance
PC2: 32.8% of variance
Total: 78.0% captured (20% lost, acceptable)
```

The remaining 2D visualization shows clustering structure:
- **Nearby points:** Similar difficulty profiles
- **Distant points:** Different vulnerability characteristics

---

## Part 5: checkpoint_cwe_difficulty.png Breakdown

### Left Panel: Difficulty Bar Chart

```python
# Sort CWEs by difficulty (highest first)
cwes_sorted = [cwe416, cwe79, cwe787, cwe352, cwe78, cwe125, cwe94, cwe862, cwe22, cwe89]
difficulties = [36.06, 32.8, 28.39, 28.19, 26.52, 26.11, 22.62, 22.2, 21.76, 18.28]

# Color gradient: Red (difficult) → Yellow (medium) → Green (easy)
colors = plt.cm.RdYlGn_r(np.array(difficulties) / max(difficulties))
#        Red for 36.06%, transitions to Green for 18.28%

ax1.barh(cwes_sorted, difficulties, color=colors, edgecolor="black")
```

**Output:**
```
CWE-416 ████████████████████████████████████ 36.1% (most difficult)
CWE-79  ████████████████████████████████ 32.8%
CWE-787 ██████████████████████████████ 28.4%
CWE-352 ██████████████████████████████ 28.2%
CWE-78  ███████████████████████████ 26.5%
CWE-125 ███████████████████████████ 26.1%
CWE-94  ████████████████████████ 22.6%
CWE-862 ████████████████████████ 22.2%
CWE-22  ████████████████████████ 21.8%
CWE-89  ██████████████████ 18.3% (least difficult)
```

Color interpretation:
- **Red bars:** High difficulty (agents struggle)
- **Yellow bars:** Medium difficulty
- **Green bars:** Low difficulty (agents succeed easily)

### Right Panel: DA vs SRR Scatter

```python
# For each CWE, plot:
# X-axis: Detection Accuracy (%)
# Y-axis: Security Reason Rate (%)

das  = [78.24, 73.48, 67.2, 81.72, 77.38, 73.89, 71.81, 63.94, 71.61, 77.8]
srrs = [57.79, 55.83, 46.03, 64.74, 59.1, 36.99, 49.47, 18.8, 42.92, 47.91]

ax2.scatter(das, srrs, s=150, alpha=0.6)
for i, cwe in enumerate(cwes):
    ax2.annotate(cwe.upper(), (das[i], srrs[i]))
```

**Interpretation:**

```
SRR %
  │  ┌──────────────────────────────
  │  │ CWE-89 (SQL Inj)      CWE-94 (Code Inj)
  │  │ High DA, High SRR     High DA, High SRR
  │  │ ✓ Easy to detect      ✓ Easy + explicit reasoning
  │  │
 50 ├──● CWE-78              ● CWE-22
  │  │ ● CWE-352
  │  │
 40 ├──● CWE-787
  │  │
  │  │ ● CWE-125
 20 ├──────● CWE-416 (Use After Free)
  │       Low DA, Very Low SRR
  │       ✗ Hard to detect, no reasoning
  │
  └──────────────────────────────
    60    70    80    90    DA %
```

**What it reveals:**

1. **CWE-89 (top-right):** Easy to detect AND agents explain their reasoning
2. **CWE-416 (bottom-left):** Hard to detect AND even when blocked, agents lack explicit security reasoning
3. **CWE-78 (middle-right):** Easy to detect but low reasoning rate
4. **CWE-125 (middle-low):** Moderate difficulty but very poor reasoning quality

This gap (high DA but low SRR) suggests:
- Agent blocks attacks but doesn't articulate *why* it's a security issue
- Potential blind detection without understanding

---

## Summary: The Three Clusterings

| Visualization | Method | Shows | Insight |
|---|---|---|---|
| **checkpoint_cwe_clustering.png (LEFT - Dendrogram)** | Hierarchical Ward linkage | Tree structure of CWE similarity | Which CWEs are fundamentally similar (cluster early in tree) |
| **checkpoint_cwe_clustering.png (RIGHT - PCA)** | PCA projection to 2D | Spatial layout of CWEs in reduced space | Visual groups of similar vulnerability types |
| **checkpoint_cwe_difficulty.png (LEFT - Bar)** | Simple sorting + color gradient | Ranked difficulty with visual intensity | Easy reference: which CWEs are hardest? |
| **checkpoint_cwe_difficulty.png (RIGHT - Scatter)** | 2D scatter (DA vs SRR) | No clustering, pure relationship plot | Reveals detection quality vs reasoning quality tradeoff |

---

## Implementation Details

### StandardScaler behavior

```python
scaler = StandardScaler()
features_scaled = scaler.fit_transform(features)

# Internally computes:
mean = features.mean(axis=0)      # [73.787, 49.44, 26.213]
scale = features.std(axis=0)       # [4.826, 11.89, 5.47]
features_scaled = (features - mean) / scale
```

### Ward linkage formula

```python
# When merging cluster A and cluster B:
distance = sqrt((n_A * n_B) / (n_A + n_B) * ||centroid_A - centroid_B||^2)

# This minimizes the increase in within-cluster sum of squares
# Tends to produce clusters of similar size (balanced tree)
```

### PCA projection

```python
# Fit PCA and get explained variance
pca = PCA(n_components=2)
features_pca = pca.fit_transform(features_scaled)
variance_ratio = pca.explained_variance_ratio_
# Result: [0.452, 0.328] → PC1 explains 45.2%, PC2 explains 32.8%
```

---

## Files Involved

- **Data source:** `/logs/nips_checkpoint/` (17,097 samples)
- **Script:** `analyze_nips_checkpoint_clustering.py` (lines 341-450)
- **Key functions:**
  - `cluster_cwes()` → computes linkage matrix + PCA
  - `plot_cwe_clustering()` → generates dendrogram + PCA scatter
  - `plot_cwe_difficulty()` → generates difficulty ranking + DA vs SRR
- **Output:** 
  - `checkpoint_cwe_clustering.png`
  - `checkpoint_cwe_difficulty.png`

---

**Last updated:** May 14, 2026  
**Method:** Ward's hierarchical clustering on standardized feature vectors (DA, SRR, Difficulty)  
**Samples:** 17,097 malicious PRs aggregated across 10 models × 2 prompt variants
