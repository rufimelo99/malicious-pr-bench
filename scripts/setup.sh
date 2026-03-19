#!/usr/bin/env bash
# setup.sh — pull the Gitea image for a given CWE, start it, and export
# GITHUB_TOKEN + GITHUB_API_URL ready for run.sh.
#
# Usage:
#   CWE=cwe89 ./scripts/setup.sh           # or run standalone (vars lost after exit)
#
# Env vars:
#   CWE          CWE slug (default: cwe89). Must be in cwe_map.sh.
#   GITEA_PORT   local port (default: 3001)

set -euo pipefail

SCRIPTS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPTS_DIR/.." && pwd)"

source "$SCRIPTS_DIR/cwe_map.sh"

CWE="${CWE:-cwe89}"
GITEA_PORT="${GITEA_PORT:-3001}"

# Validate CWE is supported
if ! cwe_is_supported "$CWE"; then
    echo "ERROR: Unknown CWE '${CWE}'. Supported: ${CWE_SLUGS[*]}"
    exit 1
fi

export IMAGE_TAG="$CWE"
export GITHUB_API_URL="http://localhost:${GITEA_PORT}/api/v1"

# ---------------------------------------------------------------------------
# Prerequisites
# ---------------------------------------------------------------------------
if ! command -v docker &>/dev/null; then
    echo "ERROR: Docker is not installed."
    exit 1
fi

PYTHON=$(command -v python3 || command -v python || true)
if [[ -z "$PYTHON" ]]; then
    echo "ERROR: Python 3 is not installed."
    exit 1
fi

if ! $PYTHON -c "import benchmark" &>/dev/null; then
    echo "==> Installing benchmark package..."
    $PYTHON -m pip install -e "$REPO_ROOT" -q
fi

if ! command -v inspect &>/dev/null; then
    echo "==> Installing inspect-ai..."
    $PYTHON -m pip install inspect-ai -q
fi

# ---------------------------------------------------------------------------
# Pull + start Gitea
# ---------------------------------------------------------------------------
echo "==> Starting Gitea for $(cwe_label "$CWE")..."

docker compose -f "$SCRIPTS_DIR/docker-compose.yml" pull --quiet
docker compose -f "$SCRIPTS_DIR/docker-compose.yml" up -d

echo "  Waiting for Gitea to be healthy..."
for i in $(seq 1 60); do
    if curl -sf "http://localhost:${GITEA_PORT}/api/healthz" &>/dev/null; then
        echo "  Gitea is ready on http://localhost:${GITEA_PORT}"
        break
    fi
    if [[ $i -eq 60 ]]; then
        echo "ERROR: Gitea did not become healthy after 5 minutes."
        echo "  Check logs: docker compose -f scripts/docker-compose.yml logs"
        exit 1
    fi
    printf "\r  Waiting... %ds" $((i * 5))
    sleep 5
done

# ---------------------------------------------------------------------------
# Generate API token
# ---------------------------------------------------------------------------
GITEA_CONTAINER=$(docker compose -f "$SCRIPTS_DIR/docker-compose.yml" ps -q gitea)
RAW_OUTPUT=$(docker exec -u git "$GITEA_CONTAINER" \
    gitea admin user generate-access-token \
        --username gitadmin \
        --token-name "bench-$(date +%s)" \
        --scopes write:repository,read:user,write:issue \
        --raw 2>&1)

TOKEN=$(echo "$RAW_OUTPUT" | tr -d '[:space:]')
TOKEN="${TOKEN##*:}"

if [[ -z "$TOKEN" ]] || [[ "$TOKEN" == *"error"* ]] || [[ "$TOKEN" == *"Error"* ]]; then
    echo "ERROR: Failed to generate Gitea token. Raw output: $RAW_OUTPUT"
    exit 1
fi

export GITHUB_TOKEN="$TOKEN"
export REVIEWER_TOKEN="$TOKEN"
echo "  Token generated."
