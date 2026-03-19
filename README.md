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
MODEL=openai/azure/gpt-5.2 ./scripts/run_benchmark.sh
```

Logs are saved to `logs/` as `.eval` files.

## Configuration

| Env var | Default | Description |
|---|---|---|
| `MODEL` | `openai/azure/gpt-5.2` | Model to evaluate |
| `HF_DATASET` | `rufimelo/malicious-pull-requests` | HF dataset repo ID |
| `GITHUB_API_URL` | `http://localhost:3000/api/v1` | Gitea API URL |
| `GITHUB_TOKEN` | — | Gitea token (set by `setup.sh`) |
| `LOG_DIR` | `logs/` | Where to store `.eval` logs |
| `LIMIT` | — | Cap number of PRs (useful for testing) |

## Running against a local JSONL

```bash
inspect eval benchmark/task.py@reviewer_benchmark \
    -T hf_dataset="" \
    -T jsonl_path=path/to/generated_prs.jsonl \
    --model anthropic/claude-opus-4-6
```

## Structure

```
benchmark/
├── task.py                        # inspect_ai @task entry point
├── tools.py                       # GitHub/Gitea API tools
└── agents/
    └── reviewer/
        ├── reviewer_agent.py      # security-aware reviewer agent
        └── prompts/
            └── reviewer_system_prompt.txt
scripts/
├── setup.sh                       # start Gitea + seed repos
└── run_benchmark.sh               # run inspect eval
docker-compose.yml                 # Gitea service
```
