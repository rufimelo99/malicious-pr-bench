#!/usr/bin/env bash

set -e

# Define arrays of values
# cwes=("cwe89")
cwes=("cwe22" "cwe78" "cwe79" "cwe89" "cwe94" "cwe125" "cwe352" "cwe416" "cwe787" "cwe862")
# tool_modes=("gitea" "sandbox")
tool_modes=("gitea")
prompt_variants=("security" "plain")

models=(
#    "openai/azure/gpt-5.4"
#    "bedrock/global.anthropic.claude-opus-4-6-v1"
#    "openai/azure/gpt-oss-120b"
#    "openai/azure/kimi-k2.6"
   "openai/azure/DeepSeek-V4-Flash"
)

# Base command parts
TASK="benchmark/task.py@reviewer_benchmark"
VERSION="deterministic"
MAX_SAMPLES=10
LOG_BASE="logs/malicious"

# Loop over combinations
for cwe in "${cwes[@]}"; do
  for tool_mode in "${tool_modes[@]}"; do
    for prompt_variant in "${prompt_variants[@]}"; do
      for model in "${models[@]}"; do

        log_dir="${LOG_BASE}/${model//\//_}_${tool_mode}_${prompt_variant}_${cwe}"

        # Skip if this config has already been run
        if [ -d "$log_dir" ]; then
          echo "Skipping: model=$model | tool_mode=$tool_mode | prompt_variant=$prompt_variant | cwe=$cwe (already exists)"
          continue
        fi

        echo "Running: model=$model | tool_mode=$tool_mode | prompt_variant=$prompt_variant | cwe=$cwe"

        uv run inspect eval "$TASK" \
          --model "$model" \
          -T cwe="$cwe" \
          -T version="$VERSION" \
          -T tool_mode="$tool_mode" \
          -T prompt_variant="$prompt_variant" \
          --max-samples="$MAX_SAMPLES" \
          --temperature 0 \
          --max-retries 2 \
          --no-fail-on-error \
          --log-dir "$log_dir"

      done
    done
  done
done

# Benign task loop
# TASK="benchmark/task.py@benign_benchmark"
# BENIGN_VERSION="benign"
# LOG_BASE="logs/benign"

# for cwe in "${cwes[@]}"; do
#   for tool_mode in "${tool_modes[@]}"; do
#     for prompt_variant in "${prompt_variants[@]}"; do
#       for model in "${models[@]}"; do

#         log_dir="${LOG_BASE}/${model//\//_}_${tool_mode}_${prompt_variant}_${cwe}_benign"

#         # Skip if this config has already been run
#         if [ -d "$log_dir" ]; then
#           echo "Skipping (benign): model=$model | tool_mode=$tool_mode | prompt_variant=$prompt_variant | cwe=$cwe (already exists)"
#           continue
#         fi

#         echo "Running (benign): model=$model | tool_mode=$tool_mode | prompt_variant=$prompt_variant | cwe=$cwe"

#         uv run inspect eval "$TASK" \
#           --model "$model" \
#           -T cwe="$cwe" \
#           -T tool_mode="$tool_mode" \
#           -T prompt_variant="$prompt_variant" \
#           --max-samples="$MAX_SAMPLES" \
#           --temperature 0 \
#           --log-dir "$log_dir"
#       done
#     done
#   done
# done