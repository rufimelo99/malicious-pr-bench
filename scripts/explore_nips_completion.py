#!/usr/bin/env python3
import json
import zipfile
from pathlib import Path
from collections import defaultdict

results_dir = Path("/Users/rmelo/Documents/GitHub/malicious-pr-bench/logs/results_nips")

# Expected sample counts from filtered dataset
filtered_releases_dir = Path("/Users/rmelo/Documents/GitHub/malicious-pr-bench/filtered_releases")
expected_samples = {}

cwes = ["cwe125", "cwe22", "cwe352", "cwe416", "cwe78", "cwe787", "cwe79", "cwe862", "cwe89", "cwe94"]

for cwe in cwes:
    jsonl_path = filtered_releases_dir / cwe / "deterministic" / "generated_prs.jsonl"
    count = 0
    if jsonl_path.exists():
        with open(jsonl_path) as f:
            count = sum(1 for line in f if line.strip())
    expected_samples[cwe] = count

print("Expected samples per CWE (filtered subset):")
for cwe, count in expected_samples.items():
    print(f"  {cwe.upper()}: {count}")

print("\n" + "="*80 + "\n")

# Structure: {model: {prompt: {cwe: {samples: N, complete: bool, metrics: {}}}}}
all_results = defaultdict(lambda: defaultdict(lambda: defaultdict(lambda: {
    "samples": 0,
    "expected": 0,
    "complete": False,
    "metrics": {}
})))

# Scan all directories
for dir_path in sorted(results_dir.glob("*_gitea_*_cwe*")):
    if not dir_path.is_dir():
        continue
    
    # Parse directory name: model_gitea_prompt_cweXXX
    parts = dir_path.name.split("_gitea_")
    if len(parts) != 2:
        continue
    
    model_name = parts[0]
    prompt_cwe = parts[1]
    
    prompt_parts = prompt_cwe.split("_cwe")
    if len(prompt_parts) != 2:
        continue
    
    prompt = prompt_parts[0]
    cwe = f"cwe{prompt_parts[1]}"
    
    eval_files = list(dir_path.glob("*.eval"))
    
    if not eval_files:
        all_results[model_name][prompt][cwe]["samples"] = 0
        all_results[model_name][prompt][cwe]["expected"] = expected_samples.get(cwe, 0)
        continue
    
    # Process eval files - aggregate ALL summaries
    total_samples = 0
    caught = 0
    missed = 0
    errors = 0
    
    for eval_file in eval_files:
        try:
            with zipfile.ZipFile(eval_file) as z:
                # Find ALL summary files (not just the first)
                summary_files = sorted([n for n in z.namelist() if '_journal/summaries' in n and n.endswith('.json')])
                
                for summary_file in summary_files:
                    with z.open(summary_file) as f:
                        samples = json.loads(f.read().decode())
                        total_samples += len(samples)
                        
                        for sample in samples:
                            if 'scores' not in sample:
                                errors += 1
                                continue
                            
                            detection_score = sample['scores'].get('detection_scorer', {}).get('value', None)
                            
                            if detection_score == 1.0:
                                caught += 1
                            elif detection_score == 0.0:
                                missed += 1
                            else:
                                errors += 1
        except Exception as e:
            print(f"⚠ Error reading {eval_file.name}: {e}")
            continue
    
    expected = expected_samples.get(cwe, 0)
    is_complete = (total_samples == expected) if expected > 0 else False
    
    accuracy = None
    if caught + missed > 0:
        accuracy = round((caught / (caught + missed)) * 100, 1)
    
    all_results[model_name][prompt][cwe]["samples"] = total_samples
    all_results[model_name][prompt][cwe]["expected"] = expected
    all_results[model_name][prompt][cwe]["complete"] = is_complete
    all_results[model_name][prompt][cwe]["metrics"] = {
        "caught": caught,
        "missed": missed,
        "errors": errors,
        "accuracy": accuracy
    }

# Print summary
print("=== Completion Status by Model, Prompt, and CWE ===\n")

for model_name in sorted(all_results.keys()):
    for prompt in sorted(all_results[model_name].keys()):
        print(f"\n{model_name} ({prompt}):")
        print("CWE,Expected,Actual,Complete,Accuracy")
        
        complete_count = 0
        for cwe in cwes:
            data = all_results[model_name][prompt][cwe]
            complete_str = "✓" if data["complete"] else "✗"
            accuracy_str = f"{data['metrics'].get('accuracy')}%" if data['metrics'].get('accuracy') is not None else "—"
            
            print(f"  {cwe.upper()},{data['expected']},{data['samples']},{complete_str},{accuracy_str}")
            
            if data["complete"]:
                complete_count += 1
        
        print(f"  TOTAL COMPLETE: {complete_count}/10")

# Save to JSON
output = {}
for model_name in all_results.keys():
    output[model_name] = {}
    for prompt in all_results[model_name].keys():
        output[model_name][prompt] = {}
        for cwe in all_results[model_name][prompt].keys():
            output[model_name][prompt][cwe] = all_results[model_name][prompt][cwe]

output_path = Path("/Users/rmelo/Documents/GitHub/malicious-pr-bench/nips_run_completion_status.json")
with open(output_path, 'w') as f:
    json.dump(output, f, indent=2)

print(f"\n✓ Saved to {output_path}")
