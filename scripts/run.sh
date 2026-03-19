#!/usr/bin/env bash
# run.sh — run the reviewer benchmark for a single CWE.
# Expects GITHUB_TOKEN, GITHUB_API_URL, and IMAGE_TAG to already be exported
# (either by setup.sh or manually).
#
# Usage:
#   CWE=cwe89 ./scripts/run.sh
#   CWE=cwe89 MODEL=anthropic/claude-opus-4-6 ./scripts/run.sh
#
# Env vars:
#   CWE          CWE slug (default: cwe89)
#   MODEL        model to evaluate (default: openai/azure/grok-3)
#   HF_DATASET   HF dataset repo ID (default: rufimelo/malicious-pull-requests)
#   LOG_DIR      where to write .eval logs (default: logs/<cwe>)

set -euo pipefail

SCRIPTS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPTS_DIR/.." && pwd)"

source "$SCRIPTS_DIR/cwe_map.sh"

CWE="${CWE:-cwe89}"
MODEL="${MODEL:-openai/azure/grok-3}"
HF_DATASET="${HF_DATASET:-rufimelo/malicious-pull-requests}"
LOG_DIR="${LOG_DIR:-$REPO_ROOT/logs/$CWE}"

if ! cwe_is_supported "$CWE"; then
    echo "ERROR: Unknown CWE '${CWE}'. Supported: ${CWE_SLUGS[*]}"
    exit 1
fi

: "${GITHUB_TOKEN:?GITHUB_TOKEN is not set. Run setup.sh first.}"
: "${GITHUB_API_URL:?GITHUB_API_URL is not set. Run setup.sh first.}"

mkdir -p "$LOG_DIR"

echo "==> Running benchmark: $(cwe_label "$CWE")"
echo "  model   : $MODEL"
echo "  dataset : $HF_DATASET/$CWE"
echo "  logs    : $LOG_DIR"
echo ""

cd "$REPO_ROOT"
inspect eval benchmark/task.py@reviewer_benchmark \
    --model "$MODEL" \
    -T hf_dataset="$HF_DATASET" \
    -T cwe="$CWE" \
    --log-dir "$LOG_DIR"
