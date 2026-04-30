# SEVRA-BENCH Documentation Assets

This directory contains the static leaderboard page and helper data for benchmark result reporting.

Common files:

- `generate_leaderboard.py` parses Inspect `.eval` logs and writes leaderboard data.
- `leaderboard.js`, `index.html`, and `static/` render the project page.
- `axis_mapping.json` maps generated pull requests to the benchmark axis taxonomy.

Run leaderboard generation from the repository root so imports resolve against the local benchmark package:

```bash
uv run python docs/generate_leaderboard.py --logs logs
```
