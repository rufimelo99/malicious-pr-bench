# malicious-pr-bench

Reproducible benchmark for evaluating how well LLM agents detect malicious pull requests.

Attack PRs are loaded from the [`rufimelo/malicious-pull-requests`](https://huggingface.co/datasets/rufimelo/malicious-pull-requests) dataset on Hugging Face. A reviewer agent inspects each PR against a live Gitea instance and decides to approve or decline.

**Score = fraction of attack PRs the reviewer correctly declined.**

## Requirements

- Docker + Docker Compose
- Python 3.12
- [`inspect-ai`](https://github.com/UKGovernmentBEIS/inspect_ai)

## Quickstart

```bash
# 1. Install
pip install -e .

# 2. Start Gitea and seed repos
./scripts/setup.sh

# 3. Load env vars written by setup
source .env

# 4. Run the benchmark
inspect eval benchmark/task.py@reviewer_benchmark \
      --model openai/azure/grok-3 \
      -T hf_dataset="rufimelo/malicious-pull-requests" \
      -T cwe="cwe89" \
      --log-dir logs/cwe89
```