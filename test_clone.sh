#!/bin/bash
# Standalone test to verify Docker container repo cloning.
# This test builds the Dockerfile and starts a container, checking if the
# repo gets cloned to /workspace/repo via the entrypoint script.
#
# Usage:
#   ./test_clone.sh <repo> [<gitea_base_url>]
#
# Example:
#   ./test_clone.sh owner/repo http://localhost:3001

set -e

if [ $# -lt 1 ]; then
    echo "Usage: $0 <repo> [<gitea_base_url>]"
    echo "Example: $0 owner/repo http://localhost:3001"
    exit 1
fi

REPO="$1"
GITEA_URL="${2:-http://localhost:3001}"
DOCKERFILE="scripts/Dockerfile.sandbox"

echo "========================================================================"
echo "Testing repo cloning in Docker sandbox"
echo "========================================================================"
echo "Repository: $REPO"
echo "Gitea URL: $GITEA_URL"
echo "Dockerfile: $DOCKERFILE"
echo ""

if [ ! -f "$DOCKERFILE" ]; then
    echo "ERROR: Dockerfile not found at $DOCKERFILE"
    exit 1
fi

# Build the Docker image
echo "[TEST] Building Docker image from $DOCKERFILE..."
DOCKER_IMAGE="sandbox-clone-test:latest"
docker build -f "$DOCKERFILE" -t "$DOCKER_IMAGE" . > /dev/null 2>&1 || {
    echo "[ERROR] Docker build failed"
    docker build -f "$DOCKERFILE" -t "$DOCKER_IMAGE" .
    exit 1
}
echo "[TEST] ✓ Docker image built successfully"
echo ""

# Run the container with environment variables on the docker-compose network
# This allows the container to reach Gitea via its service name
echo "[TEST] Running container with GITEA_REPO=$REPO and GITEA_URL=$GITEA_URL..."
CONTAINER_ID=$(docker run -d \
    --network scripts_default \
    -e GITEA_REPO="$REPO" \
    -e GITEA_URL="$GITEA_URL" \
    "$DOCKER_IMAGE")

echo "[TEST] Container ID: $CONTAINER_ID"
echo "[TEST] Waiting 3 seconds for entrypoint script to run..."
sleep 3

# Check if /workspace/repo exists
echo ""
echo "[TEST] Checking if /workspace/repo exists..."
docker exec "$CONTAINER_ID" test -d /workspace/repo > /dev/null 2>&1 && {
    echo "[TEST] ✓ /workspace/repo directory EXISTS"
    echo ""
    echo "[TEST] Contents of /workspace/repo:"
    docker exec "$CONTAINER_ID" ls -la /workspace/repo
} || {
    echo "[TEST] ✗ /workspace/repo directory DOES NOT EXIST"
    echo ""
    echo "[TEST] Contents of /workspace:"
    docker exec "$CONTAINER_ID" ls -la /workspace || true
}

# Check container logs to see what the entrypoint script did
echo ""
echo "[TEST] Entrypoint script output:"
docker logs "$CONTAINER_ID" || true

# Optional: Try manual clone from inside container
echo ""
echo "[TEST] Testing manual git clone from inside container..."
GIT_URL="$GITEA_URL/$REPO.git"
echo "[TEST] Git URL: $GIT_URL"

docker exec "$CONTAINER_ID" git clone "$GIT_URL" /tmp/test-clone > /tmp/git-clone-output.txt 2>&1 && {
    echo "[TEST] ✓ Manual git clone SUCCEEDED"
    echo "[TEST] Contents of /tmp/test-clone:"
    docker exec "$CONTAINER_ID" ls -la /tmp/test-clone
} || {
    echo "[TEST] ✗ Manual git clone FAILED"
    echo "[TEST] Git output:"
    cat /tmp/git-clone-output.txt
}

# Cleanup
echo ""
echo "[TEST] Cleaning up container..."
docker stop "$CONTAINER_ID" > /dev/null 2>&1
docker rm "$CONTAINER_ID" > /dev/null 2>&1

echo ""
echo "========================================================================"
echo "Test complete"
echo "========================================================================"
