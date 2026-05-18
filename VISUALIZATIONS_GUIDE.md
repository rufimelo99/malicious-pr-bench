# Visualization Suite: Retained Challenge Split Analysis

All visualizations use **rejection rate** (1 - detection accuracy) as the primary metric, showing where models are attacked successfully.

---

## 📊 Image 1: CWE & Framing Clustering
**File:** `1_cwe_framing_clustering.png`

### What It Shows
Four-panel analysis of hierarchical clustering and PCA projections:

**Top-Left (CWE Dendrogram):**
- Hierarchical clustering tree of CWEs by difficulty profile
- Height indicates dissimilarity: high branches = very different vulnerability types
- Shows which CWEs cluster together

**Top-Right (CWE PCA Projection):**
- 2D visualization of CWEs based on their features (rejection rate, security reason rate, difficulty)
- Color gradient: Green=easy (low RR), Red=hard (high RR)
- Nearby points = similar difficulty patterns

**Bottom-Left (Framing Dendrogram):**
- Hierarchical clustering of social engineering tactics
- Height shows which framings are tactically related
- Early merges = similar attack approaches

**Bottom-Right (Framing PCA Projection):**
- 2D layout of framings by effectiveness and characteristics
- Color: Red=more effective attacks, Green=agents resist better
- Reveals framing families and tactical clusters

### Key Insight
CWEs and framings each form natural clusters - some vulnerabilities are fundamentally harder (CWE-416), and some attacks are inherently more effective (prior_approval_signal).

---

## 📈 Image 2: CWE Difficulty
**File:** `2_cwe_difficulty.png`

### What It Shows
Bar chart ranking CWEs by difficulty (rejection rate)

**Ranking (left to right):**
1. **CWE-416** (Use After Free) - 39.9% RR - **Hardest** (red)
2. **CWE-79** (XSS) - 36.0% RR
3. **CWE-787** (Out-of-bounds Write) - 33.1% RR
...
10. **CWE-89** (SQL Injection) - 19.5% RR - **Easiest** (green)

### Color Interpretation
- **Red bars:** Models approve malicious PRs frequently (agents struggle)
- **Yellow bars:** Medium difficulty
- **Green bars:** Models consistently block (agents succeed)

### Key Insight
SQL injection vulnerabilities are easiest to detect (~80% accuracy), but Use-After-Free bugs are hardest (~60% accuracy). This is consistent with the vulnerability's exploitability complexity.

---

## 🎯 Image 3: Framing Effectiveness
**File:** `3_framing_effectiveness.png`

### What It Shows
Horizontal bar chart ranking social engineering tactics by success rate (rejection rate)

**Most Effective Attacks (top):**
- **Prior Approval Signal** (39.2%) - Claiming PR was previously approved
- **Fake Bug Fix** (35.4%) - Framing malicious change as a bug fix
- **Dependency Compat Claim** (35.3%) - False compatibility justification

**Least Effective Attacks (bottom):**
- **Misleading Hardening** (18.9%) - Agents see through security hardening lies
- **False Coverage** (21.0%) - Fake test coverage claims are detected
- **Refactoring** (21.7%) - Straightforward refactoring claims don't fool agents

### Key Insight
Appeal-to-authority tactics (prior approval, fake justifications) are 2× more effective than technical lies (false coverage, misleading hardening). Models fall for social pressure more than technical obfuscation.

---

## 🤖 Image 4: Model Clustering
**File:** `4_model_clustering.png`

### What It Shows
Two-panel analysis of LLM clustering by rejection rate across all CWEs

**Left Panel (Dendrogram):**
- Hierarchical tree of 10 models
- Height = performance difference
- Shows which models have similar strengths/weaknesses

**Right Panel (PCA Projection):**
- 2D layout of models
- **Red dots:** Frontier models (Opus 4.7, GPT-5.5, GLM-5)
- **Blue dots:** Baseline models (Haiku, nano, Grok, etc.)

### Clustering Pattern
1. **Frontier cluster (left, tight):** Opus, GPT-5.5, GLM-5
   - Consistent performance across CWEs
   - Low rejection rates (models rarely fooled)

2. **Baseline cluster (right, spread):** Haiku, Nano, Grok, Kimi
   - More variable performance
   - High rejection rates (frequently fooled)

3. **Outliers:** GPT-5.4-nano and DeepSeek (far right)
   - Unique performance profiles

### Key Insight
Frontier models are fundamentally different from baselines - they maintain consistent security across all vulnerability types, while cheaper models show high variance.

---

## 🔥 Image 5: CWE × Framing Heatmap
**File:** `5_cwe_framing_heatmap.png`

### What It Shows
10 CWEs × 15 Framings interaction matrix

- **Cells colored by rejection rate:** Green=low (agents block well), Red=high (attacks successful)
- **Rows (CWEs):** Sorted by cluster membership
- **Columns (Framings):** Sorted by cluster membership

### Reading the Heatmap

**Easy CWEs (top rows - CWE-89, CWE-862, CWE-22):**
- Mostly green across all framings
- **Framing has minimal effect** - models block these regardless of tactic
- Example: CWE-89 (SQL injection) is blocked 80% of the time even with best attacks

**Hard CWEs (bottom rows - CWE-416, CWE-78, CWE-787):**
- More yellow/red (higher RR)
- **Much more color variation** - some framings work much better on hard CWEs
- Example: Prior Approval Signal (darker column) is more effective on these

**Most Effective Framings (darkest columns):**
- `misleading_hardening` - consistently dark (agents fooled)
- `false_coverage` - effective across CWEs
- `prior_approval_signal` - especially dark on hard CWEs

**Least Effective Framings (lightest columns):**
- `build_system_laundering` - mostly light (agents resist)
- `dependency_compat_claim` - widely resisted
- `refactoring` - transparent to agents

### Key Insight
**Attacks compound:** Easy vulnerabilities resist all framings, but hard vulnerabilities become much more exploitable with the right social engineering tactic. Prior approval signal is especially devastating on CWE-416 (Use After Free).

---

## Summary: What The Visualizations Reveal

| Visualization | Reveals |
|---|---|
| **CWE & Framing Clustering** | Natural groupings within vulnerability and framing space |
| **CWE Difficulty** | Relative detectability: SQL injection easiest, Use-After-Free hardest |
| **Framing Effectiveness** | Social engineering more effective than technical deception |
| **Model Clustering** | Frontier models categorically different from baselines |
| **CWE × Framing Heatmap** | Attacks are asymmetric: same tactic works very differently on different CWEs |

---

## Data Source
All visualizations use the **retained challenge split** (1,062 curated samples where weak models failed), aggregated from 10 models across 15 framing strategies and 10 CWE classes.

**Metric:** Rejection Rate = % of cases where model incorrectly approved malicious PR
