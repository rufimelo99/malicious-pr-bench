#!/usr/bin/env python3
import json
import zipfile
from pathlib import Path
from collections import defaultdict
import glob

results_dir = Path("/Users/rmelo/Documents/GitHub/malicious-pr-bench/logs/results_nips")

# Map model names for display
model_map = {
    "bedrock_global.anthropic.claude-opus-4-7": "Opus 4.7",
    "bedrock_global.anthropic.claude-sonnet-4-6": "Sonnet 4.6",
}

# Results structure: model -> prompt -> cwe -> framing -> {caught, missed, total}
results = defaultdict(lambda: defaultdict(lambda: defaultdict(lambda: defaultdict(lambda: {"caught": 0, "missed": 0, "total": 0}))))

# Scan all directories
for dir_path in sorted(results_dir.glob("*_gitea_*_cwe*")):
    if not dir_path.is_dir():
        continue
    
    # Parse directory name
    parts = dir_path.name.split("_gitea_")
    if len(parts) != 2:
        continue
    
    model_name = parts[0]
    prompt_cwe = parts[1]  # e.g., "plain_cwe125" or "security_cwe22"
    
    prompt_parts = prompt_cwe.split("_cwe")
    if len(prompt_parts) != 2:
        continue
    
    prompt = prompt_parts[0]  # "plain" or "security"
    cwe = f"cwe{prompt_parts[1]}"
    
    # Find eval files
    eval_files = list(dir_path.glob("*.eval"))
    if not eval_files:
        print(f"⚠ No eval files in {dir_path.name}")
        continue
    
    # Process eval files (usually just one, but handle multiple)
    for eval_file in eval_files:
        try:
            with zipfile.ZipFile(eval_file) as z:
                for name in z.namelist():
                    if '_journal/summaries' in name and name.endswith('.json'):
                        with z.open(name) as f:
                            samples = json.loads(f.read().decode())
                            for sample in samples:
                                if 'scores' not in sample:
                                    continue
                                
                                # Extract framing from sample ID
                                sample_id = sample.get('id', '')
                                parts = sample_id.split('-')
                                if len(parts) < 3:
                                    continue
                                
                                framing = parts[-1]  # Last part is framing
                                
                                detection_score = sample['scores'].get('detection_scorer', {}).get('value', 0)
                                
                                if detection_score == 1.0:
                                    results[model_name][prompt][cwe][framing]["caught"] += 1
                                    results[model_name][prompt][cwe][framing]["total"] += 1
                                elif detection_score == 0.0:
                                    results[model_name][prompt][cwe][framing]["missed"] += 1
                                    results[model_name][prompt][cwe][framing]["total"] += 1
                        break  # Process only first summary file
        except Exception as e:
            print(f"⚠ Error reading {eval_file.name}: {e}")

# Aggregate by framing across all CWEs and prompt variants
framing_results = defaultdict(lambda: defaultdict(lambda: {"caught": 0, "missed": 0, "total": 0}))

for model_name, prompts in results.items():
    for prompt, cwes in prompts.items():
        for cwe, framings in cwes.items():
            for framing, counts in framings.items():
                framing_results[model_name][framing]["caught"] += counts["caught"]
                framing_results[model_name][framing]["missed"] += counts["missed"]
                framing_results[model_name][framing]["total"] += counts["total"]

# Calculate percentages and generate output
print("\n=== Framing Strategy Results (Plain Prompt) ===\n")
print("Strategy,Opus 4.7,Sonnet 4.6")

all_strategies = set()
for model_strategies in framing_results.values():
    all_strategies.update(model_strategies.keys())

for strategy in sorted(all_strategies):
    opus_data = framing_results["bedrock_global.anthropic.claude-opus-4-7"].get(strategy, {})
    sonnet_data = framing_results["bedrock_global.anthropic.claude-sonnet-4-6"].get(strategy, {})
    
    opus_acc = "—"
    sonnet_acc = "—"
    
    if opus_data.get("total", 0) > 0:
        opus_pct = (opus_data["caught"] / (opus_data["caught"] + opus_data["missed"])) * 100
        opus_acc = f"{opus_pct:.1f}%"
    
    if sonnet_data.get("total", 0) > 0:
        sonnet_pct = (sonnet_data["caught"] / (sonnet_data["caught"] + sonnet_data["missed"])) * 100
        sonnet_acc = f"{sonnet_pct:.1f}%"
    
    print(f"{strategy},{opus_acc},{sonnet_acc}")

# Generate LaTeX table rows
print("\n=== LaTeX Table Rows (for tab:framing-results) ===\n")
for strategy in sorted(all_strategies):
    opus_data = framing_results["bedrock_global.anthropic.claude-opus-4-7"].get(strategy, {})
    sonnet_data = framing_results["bedrock_global.anthropic.claude-sonnet-4-6"].get(strategy, {})
    deepseek_data = framing_results.get("deepseek", {}).get(strategy, {})
    
    opus_pct = "\\TODO"
    sonnet_pct = "\\TODO"
    
    if opus_data.get("total", 0) > 0:
        opus_pct = f"{(opus_data['caught'] / (opus_data['caught'] + opus_data['missed'])) * 100:.1f}\\%"
    
    if sonnet_data.get("total", 0) > 0:
        sonnet_pct = f"{(sonnet_data['caught'] / (sonnet_data['caught'] + sonnet_data['missed'])) * 100:.1f}\\%"
    
    # Convert strategy name to title case
    strategy_title = " ".join(word.capitalize() for word in strategy.split("_"))
    
    print(f"{strategy_title:25s} & {opus_pct:>6s} & {sonnet_pct:>6s} & \\TODO \\\\")

# Save to JSON
output_path = Path("/Users/rmelo/Documents/GitHub/malicious-pr-bench/nips_frontier_results_by_framing.json")
output_data = {}
for model, strategies in framing_results.items():
    output_data[model] = {}
    for strategy, counts in strategies.items():
        if counts["total"] > 0:
            accuracy = (counts["caught"] / (counts["caught"] + counts["missed"])) * 100
            output_data[model][strategy] = {
                "accuracy": round(accuracy, 1),
                "caught": counts["caught"],
                "missed": counts["missed"],
                "total": counts["total"]
            }

with open(output_path, 'w') as f:
    json.dump(output_data, f, indent=2)

print(f"\n✓ Written to {output_path}")

# Summary statistics
print("\n=== Summary Statistics ===\n")
for model_name, strategies in framing_results.items():
    total_caught = sum(s["caught"] for s in strategies.values())
    total_samples = sum(s["total"] for s in strategies.values())
    if total_samples > 0:
        overall_acc = (total_caught / total_samples) * 100
        print(f"{model_name}: {total_caught}/{total_samples} = {overall_acc:.1f}%")
