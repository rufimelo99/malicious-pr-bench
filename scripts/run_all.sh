#!/usr/bin/env bash
# run_all.sh — run the reviewer benchmark across all supported CWEs sequentially.
# For each CWE: pulls the image, starts Gitea, runs the benchmark, then tears down.
#
# Usage:
#   ./scripts/run_all.sh
#   MODEL=anthropic/claude-opus-4-6 ./scripts/run_all.sh
#   CWES="cwe89 cwe79" ./scripts/run_all.sh   # override subset

set -euo pipefail

SCRIPTS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPTS_DIR/.." && pwd)"

source "$SCRIPTS_DIR/cwe_map.sh"

MODEL="${MODEL:-openai/azure/grok-3}"
HF_DATASET="${HF_DATASET:-rufimelo/malicious-pull-requests}"
GITEA_PORT="${GITEA_PORT:-3001}"

# Allow caller to override the CWE list
IFS=' ' read -r -a CWES <<< "${CWES:-${CWE_SLUGS[*]}}"

echo "========================================"
echo " malicious-pr-bench — full sweep"
echo "========================================"
echo " model   : $MODEL"
echo " dataset : $HF_DATASET"
echo " CWEs    : ${CWES[*]}"
echo "========================================"
echo ""

PASSED=()
FAILED=()

for CWE in "${CWES[@]}"; do
    if ! cwe_is_supported "$CWE"; then
        echo "WARNING: '${CWE}' not in cwe_map.sh — skipping."
        FAILED+=("$CWE (unknown)")
        continue
    fi

    echo ""
    echo "----------------------------------------"
    echo " CWE: $(cwe_label "$CWE")"
    echo "----------------------------------------"

    # Setup
    if ! CWE="$CWE" GITEA_PORT="$GITEA_PORT" source "$SCRIPTS_DIR/setup.sh"; then
        echo "  [FAIL] setup failed for $CWE"
        FAILED+=("$CWE")
        continue
    fi

    # Run benchmark
    if CWE="$CWE" MODEL="$MODEL" HF_DATASET="$HF_DATASET" "$SCRIPTS_DIR/run.sh"; then
        PASSED+=("$CWE")
    else
        echo "  [FAIL] benchmark failed for $CWE"
        FAILED+=("$CWE")
    fi

    # Tear down Gitea before next CWE
    echo ""
    echo "==> Stopping Gitea..."
    docker compose -f "$SCRIPTS_DIR/docker-compose.yml" down --timeout 10 2>/dev/null || true
done

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
echo ""
echo "========================================"
echo " Summary"
echo "========================================"
echo " Passed : ${#PASSED[@]} — ${PASSED[*]:-none}"
echo " Failed : ${#FAILED[@]} — ${FAILED[*]:-none}"
echo ""
echo " Logs saved to: $REPO_ROOT/logs/"
echo "========================================"

[[ ${#FAILED[@]} -eq 0 ]]
