#!/usr/bin/env bash
# reset.sh — tear down the benchmark container and start fresh from the image,
# restoring all PRs to their original open state.
#
# Usage:
#   CWE=cwe79 ./scripts/reset.sh
#   # then export the printed vars before running inspect eval

set -euo pipefail

SCRIPTS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

source "$SCRIPTS_DIR/cwe_map.sh"

CWE="${CWE:-cwe89}"
GITEA_PORT="${GITEA_PORT:-3001}"

export IMAGE_TAG="$CWE"
export GITHUB_API_URL="http://localhost:${GITEA_PORT}/api/v1"

echo "==> Resetting Gitea for $(cwe_label "$CWE")..."

docker compose -f "$SCRIPTS_DIR/docker-compose.yml" down --remove-orphans
docker compose -f "$SCRIPTS_DIR/docker-compose.yml" up -d

echo "  Waiting for Gitea to be healthy..."
for i in $(seq 1 60); do
    if curl -sf "http://localhost:${GITEA_PORT}/api/healthz" &>/dev/null; then
        echo "  Gitea is ready."
        break
    fi
    if [[ $i -eq 60 ]]; then
        echo "ERROR: Gitea did not become healthy after 5 minutes."
        docker compose -f "$SCRIPTS_DIR/docker-compose.yml" logs --tail=20 benchmark
        exit 1
    fi
    sleep 5
done

TOKEN=$(curl -sf -X POST \
    -H "Content-Type: application/json" \
    -u "gitadmin:adminpass123" \
    "http://localhost:${GITEA_PORT}/api/v1/users/gitadmin/tokens" \
    -d "{\"name\":\"bench-$(date +%s)\",\"scopes\":[\"write:repository\",\"read:user\",\"write:issue\"]}" \
    | python3 -c "import sys,json; print(json.load(sys.stdin)['sha1'])")

if [[ -z "$TOKEN" ]]; then
    echo "ERROR: Failed to generate token."
    exit 1
fi

echo ""
echo "  Container reset. Export before running:"
echo "    export GITHUB_TOKEN=${TOKEN}"
echo "    export GITHUB_API_URL=http://localhost:${GITEA_PORT}/api/v1"
