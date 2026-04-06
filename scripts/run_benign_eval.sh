#!/usr/bin/env bash
# run_benign_eval.sh — evaluate the benign fix PR benchmark one CWE at a time.
#
# Usage:
#   CWES="cwe79 cwe89" VERSION=gpt5.2 MODEL=openai/azure/gpt-5.2 \
#       ./scripts/run_benign_eval.sh

set -euo pipefail

SCRIPTS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPTS_DIR/.." && pwd)"

CWES="${CWES:-cwe79 cwe89 cwe22 cwe352 cwe416 cwe78 cwe787 cwe862 cwe94 cwe125}"
VERSION="${VERSION:-v0.1.0}"
MODEL="${MODEL:-openai/azure/grok-3}"
MAX_CONNECTIONS="${MAX_CONNECTIONS:-10}"
LOG_DIR="${LOG_DIR:-$REPO_ROOT/logs/${MODEL##*/}_benign}"
GITEA_PORT="${GITEA_PORT:-3001}"

echo "========================================"
echo "  Benign benchmark — per-CWE evaluation"
echo "  CWEs:    $CWES"
echo "  Version: $VERSION"
echo "  Model:   $MODEL"
echo "  Log dir: $LOG_DIR"
echo "========================================"
echo ""

for CWE_SLUG in $CWES; do
    echo "-------- ${CWE_SLUG} --------"
    inspect eval benchmark/benign_task.py@benign_reviewer_benchmark \
        -T cwe="$CWE_SLUG" \
        -T version="$VERSION" \
        -T reset=false \
        -T gitea_port="$GITEA_PORT" \
        --model "$MODEL" \
        --max-connections "$MAX_CONNECTIONS" \
        --log-dir "$LOG_DIR/$CWE_SLUG"
    echo ""
done

echo "==> All CWEs evaluated. Logs in $LOG_DIR"
