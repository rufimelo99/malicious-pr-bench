#!/usr/bin/env bash
# setup.sh — (re)start the benchmark container from a clean image state.
# Safe to run before every eval: tears down any existing container first so
# all PRs are reset to open, then starts fresh and prints a new token.
#
# Usage:
#   CWE=cwe79 ./scripts/setup.sh
#   # export the printed vars, then run inspect eval

set -euo pipefail

SCRIPTS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPTS_DIR/.." && pwd)"

source "$SCRIPTS_DIR/cwe_map.sh"

CWE="${CWE:-cwe89}"
GITEA_PORT="${GITEA_PORT:-3001}"

if ! cwe_is_supported "$CWE"; then
    echo "ERROR: Unknown CWE '${CWE}'. Supported: ${CWE_SLUGS[*]}"
    exit 1
fi

export IMAGE_TAG="$CWE"

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

echo "==> Resetting Gitea for $(cwe_label "$CWE")..."
docker compose -f "$SCRIPTS_DIR/docker-compose.yml" down --remove-orphans 2>/dev/null || true
docker compose -f "$SCRIPTS_DIR/docker-compose.yml" pull
docker compose -f "$SCRIPTS_DIR/docker-compose.yml" up -d

echo "  Waiting for Gitea to be healthy..."
for i in $(seq 1 60); do
    if curl -sf "http://localhost:${GITEA_PORT}/api/healthz" &>/dev/null; then
        echo "  Gitea is ready on http://localhost:${GITEA_PORT}"
        break
    fi
    if [[ $i -eq 60 ]]; then
        echo "ERROR: Gitea did not become healthy after 5 minutes."
        docker compose -f "$SCRIPTS_DIR/docker-compose.yml" logs --tail=20 benchmark
        exit 1
    fi
    echo "  [${i}/60] waiting... (${SECONDS}s)"
    sleep 5
done

TOKEN=$(curl -sf -X POST \
    -H "Content-Type: application/json" \
    -u "gitadmin:adminpass123" \
    "http://localhost:${GITEA_PORT}/api/v1/users/gitadmin/tokens" \
    -d "{\"name\":\"bench-$(date +%s)\",\"scopes\":[\"write:repository\",\"read:user\",\"write:issue\"]}" \
    | $PYTHON -c "import sys,json; print(json.load(sys.stdin)['sha1'])")

if [[ -z "$TOKEN" ]]; then
    echo "ERROR: Failed to generate token."
    exit 1
fi

echo ""
echo "  Export before running:"
echo "    export GITHUB_TOKEN=${TOKEN}"
echo "    export GITHUB_API_URL=http://localhost:${GITEA_PORT}/api/v1"
