#!/bin/bash
# Setup test environment: pull Gitea image, start it, and build sandbox image

set -e

echo "========================================================================"
echo "Setting up test environment"
echo "========================================================================"

# Step 1: Pull Gitea image
echo ""
echo "[1/5] Pulling Gitea image from Docker Hub..."
docker pull rufimelo/malicious-pr-cwe89:gpt5.2-filtered

# Step 2: Start Gitea container
echo ""
echo "[2/5] Starting Gitea container..."
docker run -d \
  --name gitea \
  -p 3001:3001 \
  rufimelo/malicious-pr-cwe89:gpt5.2-filtered

# Step 3: Wait for Gitea to be ready
echo ""
echo "[3/5] Waiting for Gitea to be ready..."
for i in {1..30}; do
  if curl -s http://localhost:3001/api/healthz > /dev/null 2>&1; then
    echo "✓ Gitea is ready"
    break
  fi
  echo -n "."
  sleep 2
done

# Step 4: Check available repos
echo ""
echo "[4/5] Checking available repositories..."
echo "Available repos:"
curl -s http://localhost:3001/api/v1/users/gitadmin/repos | python3 -c "
import sys, json
repos = json.load(sys.stdin)
for repo in repos[:10]:
    print(f\"  - {repo['full_name']}\")
"

# Step 5: Build sandbox image
echo ""
echo "[5/5] Building sandbox Docker image..."
docker build -f scripts/Dockerfile.sandbox -t test-sandbox:latest .

echo ""
echo "========================================================================"
echo "✓ Setup complete!"
echo "========================================================================"
echo ""
echo "Next steps:"
echo "  1. Test cloning with one of the repos listed above:"
echo "     ./test_clone.sh gitadmin/rails http://host.docker.internal:3001"
echo ""
echo "  2. Or manually test with docker run:"
echo "     docker run -it \\"
echo "       -e GITEA_REPO=gitadmin/rails \\"
echo "       -e GITEA_URL=http://host.docker.internal:3001 \\"
echo "       test-sandbox:latest \\"
echo "       bash"
echo ""
echo "     Then inside the container:"
echo "       ls -la /workspace/repo"
echo "       cd /workspace/repo && git log --oneline | head -5"
echo ""
