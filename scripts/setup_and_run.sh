#!/usr/bin/env bash
# setup_and_run.sh — full setup and execution of the reviewer benchmark.
#
# What this script does:
#   1. Checks prerequisites (Docker, Python, inspect-ai)
#   2. Installs the decomposition package if needed
#   3. Pulls and starts the pre-built Gitea benchmark image
#   4. Generates a fresh Gitea API token (no password needed)
#   5. Runs the reviewer benchmark via inspect eval
#   6. Stops Gitea when done
#
# Optional env vars:
#   MODEL               reviewer model       (default: openai/azure/grok-3)
#   REPO                gitea repo slug      (default: gitadmin/test-repo)
#   GITEA_PORT          local port for Gitea (default: 3001)
#   HF_DATASET          HF Hub dataset ID    (default: rufimelo/malicious-pull-requests)
#                       Set to "" to use a local benchmark/generated_prs.jsonl instead.

set -euo pipefail

BENCHMARK_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$BENCHMARK_DIR/.." && pwd)"

MODEL="${MODEL:-openai/azure/grok-3}"
REPO="${REPO:-gitadmin/test-repo}"
GITEA_PORT="${GITEA_PORT:-3001}"
HF_DATASET="${HF_DATASET:-rufimelo/malicious-pull-requests}"
export GITHUB_API_URL="http://localhost:${GITEA_PORT}/api/v1"

# ---------------------------------------------------------------------------
# 1. Prerequisites
# ---------------------------------------------------------------------------
echo "==> Checking prerequisites..."

if ! command -v docker &>/dev/null; then
    echo "ERROR: Docker is not installed. Install it from https://docs.docker.com/get-docker/"
    exit 1
fi

PYTHON=$(command -v python3 || command -v python || true)
if [[ -z "$PYTHON" ]]; then
    echo "ERROR: Python 3 is not installed."
    exit 1
fi

echo "  Docker: ok"
echo "  Python: $($PYTHON --version)"

# ---------------------------------------------------------------------------
# 2. Install decomposition package (if not already installed)
# ---------------------------------------------------------------------------
echo ""
echo "==> Installing decomposition package..."

if ! $PYTHON -c "import benchmark" &>/dev/null; then
    echo "  Running pip install -e $REPO_ROOT ..."
    $PYTHON -m pip install -e "$REPO_ROOT" -q
else
    echo "  Already installed."
fi

if ! command -v inspect &>/dev/null; then
    echo "  inspect-ai not found — installing..."
    $PYTHON -m pip install inspect-ai -q
fi

# ---------------------------------------------------------------------------
# 3. Pull and start Gitea
# ---------------------------------------------------------------------------
echo ""
echo "==> Starting Gitea benchmark instance..."

docker compose -f "$BENCHMARK_DIR/docker-compose.yml" pull --quiet
docker compose -f "$BENCHMARK_DIR/docker-compose.yml" up -d

echo "  Waiting for Gitea to be healthy..."
for i in $(seq 1 40); do
    if curl -sf "http://localhost:${GITEA_PORT}/api/healthz" &>/dev/null; then
        echo "  Gitea is ready on http://localhost:${GITEA_PORT}"
        break
    fi
    if [[ $i -eq 40 ]]; then
        echo "ERROR: Gitea did not become healthy. Check: docker compose -f benchmark/docker-compose.yml logs"
        exit 1
    fi
    sleep 2
done

# ---------------------------------------------------------------------------
# 4. Generate a fresh Gitea API token
# ---------------------------------------------------------------------------
echo ""
echo "==> Generating Gitea API token..."

GITEA_CONTAINER=$(docker compose -f "$BENCHMARK_DIR/docker-compose.yml" ps -q gitea)
RAW_OUTPUT=$(docker exec -u git "$GITEA_CONTAINER" \
    gitea admin user generate-access-token \
        --username gitadmin \
        --token-name "benchmark-$(date +%s)" \
        --scopes write:repository,read:user,write:issue \
        --raw 2>&1)

# Strip any non-token prefix (older Gitea prints "Generated access token: <token>")
TOKEN=$(echo "$RAW_OUTPUT" | tr -d '[:space:]')
TOKEN="${TOKEN##*:}"

if [[ -z "$TOKEN" ]] || [[ "$TOKEN" == *"error"* ]] || [[ "$TOKEN" == *"Error"* ]]; then
    echo "ERROR: Failed to generate Gitea token."
    echo "  Raw output: $RAW_OUTPUT"
    echo "  Check that the gitadmin user exists in the benchmark image."
    exit 1
fi

export GITHUB_TOKEN="$TOKEN"
export REVIEWER_TOKEN="$TOKEN"
echo "  Token generated."

# ---------------------------------------------------------------------------
# 5. Run the benchmark
# ---------------------------------------------------------------------------
echo ""
echo "==> Running reviewer benchmark"
echo "  model      : $MODEL"
echo "  repo       : $REPO"
if [[ -n "$HF_DATASET" ]]; then
    echo "  dataset    : $HF_DATASET (HF Hub)"
else
    echo "  dataset    : $BENCHMARK_DIR/generated_prs.jsonl (local)"
fi
echo ""

cd "$REPO_ROOT"
if [[ -n "$HF_DATASET" ]]; then
    inspect eval benchmark/task.py@reviewer_benchmark \
        --model "$MODEL" \
        -T hf_dataset="$HF_DATASET" \
        -T repo="$REPO"
else
    inspect eval benchmark/task.py@reviewer_benchmark \
        --model "$MODEL" \
        -T jsonl_path="$BENCHMARK_DIR/generated_prs.jsonl" \
        -T repo="$REPO"
fi

# ---------------------------------------------------------------------------
# 6. Cleanup
# ---------------------------------------------------------------------------
echo ""
echo "==> Stopping Gitea..."
docker compose -f "$BENCHMARK_DIR/docker-compose.yml" down
echo "Done."
