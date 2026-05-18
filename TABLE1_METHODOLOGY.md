# Table 1 Methodology: Detection Accuracy per CWE on Retained Challenge Split

## Summary

**Table 1** in the paper (titled "Detection Accuracy per CWE on retained challenge split") shows:
- Per-CWE detection accuracy for 8 models (Haiku-4.5, GPT-5.4-nano, Grok Code Fast, Claude Opus 4.7, DeepSeek, GPT-5.5, GLM-5, Kimi K2.5)
- Per-CWE metrics for 10 CWEs (CWE-79, CWE-89, CWE-352, CWE-862, CWE-787, CWE-22, CWE-416, CWE-125, CWE-78, CWE-94)
- An "Overall Average" row showing weighted-average detection accuracy

## Data Sources

Table 1 uses evaluation data from:
1. `/logs/results_nips/` - Frontier models evaluated on NIPS paper protocol
2. `/logs/filtering_releases/` - Baseline/filtering models evaluated

## JSON File

**Primary file:** `nips_results_with_srr.json`

Structure:
```json
{
  "per_cwe": {
    "model_name": {
      "prompt_variant": {  // "plain" or "security"
        "cwe_id": {
          "detection_accuracy": {
            "accuracy": 52.9,
            "standard_error": 2.0,
            "n_samples": 1062
          },
          "security_reason_rate": { ... }
        }
      }
    }
  },
  "per_framing": { ... }
}
```

## Generation Script

**Primary script:** `scripts/extract_nips_results_with_srr.py`

```bash
# Generate for ALL samples (unfiltered)
python3 scripts/extract_nips_results_with_srr.py
# Output: nips_results_with_srr.json

# Generate for RETAINED SPLIT (paper's Table 1 - 1,062 curated samples)
python3 scripts/extract_nips_results_with_srr.py --retained
# Output: nips_results_with_srr_retained_split.json
```

### Script Algorithm

1. **Load retained sample IDs** (if `--retained` flag)
   - Reads `retained_sample_ids.json` which maps CWE → list of sample IDs in retained split
   - Total: 1,062 samples (with some samples appearing in multiple CWEs)

2. **Scan evaluation directories**
   - Scans both `/logs/results_nips/` and `/logs/filtering_releases/`
   - Parses directory names: `{model}_gitea_{prompt_variant}_cwe{number}`
   - Example: `bedrock_global.anthropic.claude-opus-4-7_gitea_plain_cwe79`

3. **Extract evaluation samples**
   - Opens `.eval` ZIP archives containing `_journal/summaries/*.json`
   - Each JSON contains list of sample evaluation records

4. **Deduplicate by sample ID**
   - Processes `.eval` files chronologically (oldest → newest)
   - Later evaluation attempts overwrite earlier ones (keeps most recent result)

5. **Filter to retained split** (if enabled)
   - For each sample, checks: `if sample_id not in retained_ids_by_cwe[cwe]`
   - Per-CWE filtering ensures each CWE independently uses its retained samples

6. **Filter framings**
   - Skips `partial_test_coverage` (16th framing not in paper's 15 framings)
   - Extracts framing from sample ID (last hyphen-separated component)

7. **Aggregate per CWE**
   - Sums detection_scorer results across all framings for each model/prompt/CWE
   - Computes accuracy: `caught / (caught + missed) × 100%`
   - Computes standard error: `√(p(1-p)/n)` where p = accuracy/100, n = sample count

8. **Aggregate per framing**
   - Sums across all CWEs, grouped by framing

## Overall Average Computation

The paper's "Overall Average" row is a **weighted average** where each CWE is weighted by its retained sample count.

**Formula:**
```
overall_accuracy = Σ(accuracy_cwe × n_samples_cwe) / Σ(n_samples_cwe)
```

**Example (Haiku-4.5):**
```
CWE-79:  37.0% × 117 samples = 4,329
CWE-89:  85.0% × 65  samples = 5,525
CWE-352: 46.0% × 98  samples = 4,508
... (7 more CWEs)
───────────────────────────────────────
Total:   52.9% × 1,062 samples = 56,180
```

This weighted approach is standard because each CWE has a different difficulty and representation in the retained split.

## Retained Challenge Split

**File:** `retained_sample_ids.json`

Structure: Maps each CWE to list of sample IDs that are in the retained challenge split
```json
{
  "cwe125": ["sample_id1", "sample_id2", ...],
  "cwe22": [...],
  ...
}
```

**Size:** 
- 1,062 total entries (with duplication)
- 968 unique samples (some appear in 2-3 CWEs)

**Selection criteria:** Samples where at least one weak baseline model failed (didn't reject the malicious PR). This ensures Table 1 focuses on the challenging cases.

## Validation

To verify the script generates Table 1 values:

```bash
python3 << 'EOF'
import json

with open('nips_results_with_srr_retained_split.json') as f:
    data = json.load(f)

# Get Haiku's per-CWE values and compute weighted average
model = 'bedrock_us.anthropic.claude-haiku-4-5-20251001-v1:0'
cwes = ['cwe79', 'cwe89', 'cwe352', 'cwe862', 'cwe787', 'cwe22', 'cwe416', 'cwe125', 'cwe78', 'cwe94']

total_weighted = 0
total_n = 0
for cwe in cwes:
    acc = data['per_cwe'][model]['plain'][cwe]['detection_accuracy']['accuracy']
    n = data['per_cwe'][model]['plain'][cwe]['detection_accuracy']['n_samples']
    total_weighted += acc * n
    total_n += n

print(f"Haiku weighted average: {total_weighted/total_n:.1f}%")
print(f"Paper reports: 52.9%")
EOF
```

Expected output:
```
Haiku weighted average: 52.9%
Paper reports: 52.9%
```

## Related Scripts

- **`analyze_paper_results_clustering.py`** - Generates clustering analysis + model summary statistics
  - Also filters to retained split
  - Outputs: visualizations + `paper_results_analysis.json`
  
- **`scripts/extract_baseline_retained_split.py`** - Extracts only baseline models (filtering_releases) for retained split
  - Outputs: `baseline_retained_split_results.json`

## Key Insights

1. **Retained split is crucial:** Without filtering to the 1,062 retained samples, model accuracy values are significantly different:
   - Haiku all samples: 77.6% → Haiku retained split: 52.9%
   - This represents the challenge level: retained split focuses on harder cases

2. **Weighted averaging matters:** Simple average of per-CWE values differs from weighted average:
   - Simple average: ~54.8% for Haiku
   - Weighted average: 52.9% for Haiku
   - Difference due to unequal sample distribution across CWEs

3. **partial_test_coverage must be excluded:** This framing was added later and not included in the paper's 15 framings

4. **Per-CWE filtering is critical:** The per-CWE filtering (not global filtering) ensures that each CWE evaluation independently uses only its retained samples
   - Sample "X-abc-fake_bug_fix" might be in retained split for CWE-79 but not CWE-89
   - Both evaluations should be included in their respective CWEs

---

**Last updated:** 2026-05-14  
**Status:** Verified - script generates exact paper values within rounding error
