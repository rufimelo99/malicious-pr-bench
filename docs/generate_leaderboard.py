#!/usr/bin/env python3
"""Generate leaderboard HTML from benchmark logs using Academic template."""

import argparse
import json
import zipfile
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

# Load axis mapping from HuggingFace dataset
AXIS_MAPPING = {}
AXIS_MAPPING_PATH = Path(__file__).parent / "axis_mapping.json"
if AXIS_MAPPING_PATH.exists():
    with open(AXIS_MAPPING_PATH) as f:
        AXIS_MAPPING = json.load(f)


def parse_eval_file(eval_path: Path) -> Optional[dict[str, Any]]:
    """Parse .eval ZIP file to extract metadata and scores."""
    try:
        with zipfile.ZipFile(eval_path) as zf:
            header_data = zf.read("header.json")
            header = json.loads(header_data)
            eval_meta = header.get("eval", {})

            # Extract scores from reductions.json (actual evaluation results)
            try:
                reductions_data = zf.read("reductions.json")
                reductions = json.loads(reductions_data) if reductions_data else []

                if reductions:
                    # Get the first reducer (usually detection_scorer)
                    for reduction in reductions:
                        if reduction.get("scorer") == "detection_scorer":
                            samples = reduction.get("samples", [])
                            if samples:
                                scores = [s.get("value", 0) for s in samples]
                                if scores:
                                    eval_meta["avg_score"] = sum(scores) / len(scores)
                                    eval_meta["score_count"] = len(scores)

                                    # Extract axis data from sample IDs
                                    # Format: repo-prN-axis1-axis2-axis3
                                    axes_data = {
                                        "axis1": {},
                                        "axis2": {},
                                        "axis3": {},
                                    }
                                    for sample, score in zip(samples, scores):
                                        sample_id = sample.get("sample_id", "")
                                        # Parse axis values from sample ID
                                        # Use negative indices to handle repos with dashes
                                        parts = sample_id.split("-")
                                        if len(parts) >= 5:
                                            try:
                                                axis1 = parts[-3]
                                                axis2 = parts[-2]
                                                axis3 = parts[-1]

                                                # Aggregate by axis
                                                for axis_num, axis_val in [
                                                    ("axis1", axis1),
                                                    ("axis2", axis2),
                                                    ("axis3", axis3),
                                                ]:
                                                    if (
                                                        axis_val
                                                        and axis_val != "undefined"
                                                    ):
                                                        if (
                                                            axis_val
                                                            not in axes_data[axis_num]
                                                        ):
                                                            axes_data[axis_num][
                                                                axis_val
                                                            ] = []
                                                        axes_data[axis_num][
                                                            axis_val
                                                        ].append(score)
                                            except (IndexError, ValueError):
                                                pass

                                    # Calculate average per axis
                                    for axis_key in axes_data:
                                        for key, values in axes_data[axis_key].items():
                                            if values:
                                                axes_data[axis_key][key] = sum(
                                                    values
                                                ) / len(values)

                                    eval_meta["axes"] = axes_data
                            break
            except Exception:
                pass

            return eval_meta
    except Exception:
        return None


def extract_model_and_harness(metadata: dict) -> tuple[str, str]:
    """Extract model name and harness from metadata.

    Harness is determined by:
    - CLI agent (claude-code, copilot-cli) takes priority
    - Otherwise: inspect + tool_mode (gitea, sandbox)
    """
    model_str = metadata.get("model", "unknown")
    task_args = metadata.get("task_args", {})
    agent = task_args.get("agent")
    tool_mode = task_args.get("tool_mode")

    # Clean up model name
    if model_str and model_str != "none/none":
        # Handle paths like "openai/azure/gpt-5.2" or "global.anthropic.claude-opus"
        parts = model_str.split("/")
        model = parts[-1]
    else:
        model = "unknown"

    # Determine harness
    if agent:
        # CLI agent (copilot, claude-code, etc.)
        harness = agent
    elif tool_mode:
        # Inspect AI + explicit tool mode
        harness = f"inspect + {tool_mode}"
    else:
        # Default to inspect (no tool mode specified)
        harness = "inspect + gitea"

    return model, harness


def parse_logs(
    log_dir: Path,
    skip_years: Optional[list[int]] = None,
    tool_modes: Optional[list[str]] = None,
) -> dict[str, dict[str, list[dict[str, Any]]]]:
    """Parse benchmark logs and aggregate results by task type."""
    skip_years = skip_years or []
    tool_modes = tool_modes or []

    results = defaultdict(lambda: defaultdict(list))  # task_type -> cwe -> [entries]

    if not log_dir.exists():
        return results

    for eval_file in log_dir.rglob("*.eval"):
        metadata = parse_eval_file(eval_file)
        if not metadata:
            continue

        # Extract timestamp
        created_str = metadata.get("created", "")
        try:
            created_date = datetime.fromisoformat(created_str.replace("Z", "+00:00"))
            if created_date.year in skip_years:
                continue
            date_str = created_date.strftime("%Y-%m-%d")
        except Exception:
            date_str = "unknown"

        # Extract task and cwe
        task = metadata.get("task", "unknown")
        task_args = metadata.get("task_args", {})
        cwe = task_args.get("cwe", "all")

        # Check tool mode if filtering
        if tool_modes:
            detected_tool_mode = task_args.get("tool_mode", "gitea")
            if detected_tool_mode not in tool_modes:
                continue

        # Extract model and harness
        model, harness = extract_model_and_harness(metadata)

        # Create result entry
        result = {
            "model": model,
            "harness": harness,
            "date": date_str,
            "samples": metadata.get("dataset", {}).get("samples", 0),
            "cwe": cwe,
            "status": metadata.get("status", "unknown"),
            "created": created_str,
            "score": metadata.get("avg_score"),
            "axes": metadata.get("axes", {}),
        }

        results[task][cwe].append(result)

    # Sort by date descending
    for task in results:
        for cwe in results[task]:
            results[task][cwe].sort(key=lambda x: x["created"], reverse=True)

    return dict(results)


def generate_filters_html() -> str:
    """Generate filter UI and charts for leaderboard."""
    return """
  <!-- Filters Section -->
  <section class="section">
    <div class="container is-max-desktop">
      <h2 class="title is-4">Filters</h2>
      <div class="columns">
        <div class="column">
          <div class="field">
            <label class="label">Model</label>
            <div class="control">
              <div class="select">
                <select id="model-filter"></select>
              </div>
            </div>
          </div>
        </div>
        <div class="column">
          <div class="field">
            <label class="label">Harness</label>
            <div class="control">
              <div class="select">
                <select id="harness-filter"></select>
              </div>
            </div>
          </div>
        </div>
        <div class="column">
          <div class="field">
            <label class="label">CWE Type</label>
            <div class="control">
              <div class="select">
                <select id="cwe-filter"></select>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  </section>

  <!-- Charts Section -->
  <section class="section">
    <div class="container is-max-desktop">
      <div class="tabs">
        <ul>
          <li class="is-active"><a onclick="switchChart('timeSeries')">📈 Time Series</a></li>
          <li><a onclick="switchChart('bar')">📊 Model Comparison</a></li>
          <li><a onclick="switchChart('deception')">🎭 Deception Patterns</a></li>
          <li><a onclick="switchChart('radar')">🎯 Attack Types</a></li>
          <li><a onclick="switchChart('axes')">📋 Axis Breakdown</a></li>
        </ul>
      </div>

      <div id="timeSeriesContainer" class="chart-container">
        <h2 class="title is-4">Score Over Time</h2>
        <canvas id="timeSeriesChart"></canvas>
      </div>

      <div id="barContainer" class="chart-container" style="display:none;">
        <h2 class="title is-4">Model Comparison</h2>
        <canvas id="barChart"></canvas>
      </div>

      <div id="deceptionContainer" class="chart-container" style="display:none;">
        <h2 class="title is-4">Performance by Deception Pattern</h2>
        <canvas id="deceptionChart"></canvas>
      </div>

      <div id="radarContainer" class="chart-container" style="display:none;">
        <h2 class="title is-4">Performance by Attack Type</h2>
        <canvas id="radarChart"></canvas>
      </div>

      <div id="axisTableContainer" class="chart-container" style="display:none; margin-top: 4rem;">
        <h2 class="title is-4">Model Performance by Axis</h2>
      </div>
    </div>
  </section>

  <script>
    function switchChart(chartType) {
      const containers = {
        'timeSeries': 'timeSeriesContainer',
        'bar': 'barContainer',
        'deception': 'deceptionContainer',
        'radar': 'radarContainer',
        'axes': 'axisTableContainer'
      };

      // Hide all containers
      Object.values(containers).forEach(id => {
        document.getElementById(id).style.display = 'none';
      });

      // Show selected container
      document.getElementById(containers[chartType]).style.display = 'block';

      // Update tab styling
      document.querySelectorAll('.tabs li').forEach(li => li.classList.remove('is-active'));
      event.target.closest('li').classList.add('is-active');
    }
  </script>

  <style>
    .tabs a { cursor: pointer; }
    .chart-container { position: relative; height: 400px; }
    #radarChart { max-width: 500px; margin: 0 auto; }
    #axisTableContainer { margin-top: 4rem; padding-top: 2rem; border-top: 1px solid #e5e5e5; }
  </style>
"""


def generate_table_html(task_name: str, entries: dict[str, list[dict]]) -> str:
    """Generate HTML table for a task type using Bulma styling."""
    task_display = _format_task_name(task_name)

    html = f"""
  <!-- {task_display} Section -->
  <section class="section">
    <div class="container is-max-desktop">
      <h2 class="title is-3">{task_display}</h2>

      <div class="table-container">
        <table class="table is-striped is-hoverable is-fullwidth">
          <thead>
            <tr>
              <th>Model</th>
              <th>Harness</th>
              <th>CWE Type</th>
              <th>Date</th>
              <th>Samples</th>
              <th>Accuracy</th>
            </tr>
          </thead>
          <tbody>
"""

    if entries:
        for cwe in sorted(entries.keys()):
            for entry in entries[cwe]:
                # Format score
                score_display = (
                    f"{entry['score']:.1%}" if entry["score"] is not None else "—"
                )
                score_color = (
                    "has-text-success"
                    if entry["score"] and entry["score"] > 0.8
                    else (
                        "has-text-warning"
                        if entry["score"] and entry["score"] > 0.6
                        else (
                            "has-text-danger"
                            if entry["score"] and entry["score"] < 0.5
                            else ""
                        )
                    )
                )

                html += f"""            <tr>
              <td><strong>{entry['model']}</strong></td>
              <td><code>{entry['harness']}</code></td>
              <td><code>{entry['cwe']}</code></td>
              <td>{entry['date']}</td>
              <td>{entry['samples']}</td>
              <td class="{score_color}"><strong>{score_display}</strong></td>
            </tr>
"""
    else:
        html += """            <tr>
              <td colspan="6" class="has-text-centered has-text-grey">
                No results yet
              </td>
            </tr>
"""

    html += """          </tbody>
        </table>
      </div>
    </div>
  </section>
"""

    return html


def load_template(template_path: Path) -> str:
    """Load the Academic template HTML."""
    if not template_path.exists():
        raise FileNotFoundError(f"Template not found: {template_path}")
    return template_path.read_text()


def insert_leaderboard_content(
    template: str, results: dict[str, dict[str, list[dict]]]
) -> str:
    """Insert leaderboard content into the template."""

    # Generate filters and charts first
    leaderboard_content = generate_filters_html()

    # Generate all tables
    for task_name in sorted(results.keys()):
        leaderboard_content += generate_table_html(task_name, results[task_name])

    # Add update timestamp
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC")
    leaderboard_content += f"""
  <section class="section">
    <div class="container is-max-desktop has-text-centered has-text-grey-light">
      <p style="font-size: 0.9rem; margin-top: 2rem;">
        Last updated: {timestamp}
      </p>
    </div>
  </section>

  <!-- Chart.js and leaderboard scripts -->
  <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
  <script src="leaderboard.js"></script>
"""

    # Find and replace the placeholder section
    placeholder_start = "  <!-- 🔍 Malicious PR Detection Section -->"

    if placeholder_start in template:
        # Find the actual section
        start_idx = template.find(placeholder_start)

        # Find the end by looking for the next major comment or body closing
        # The placeholder ends with: </section></body></html>
        # We need to find where the timestamp section ends
        end_search_start = start_idx + len(placeholder_start)
        end_idx = template.find("</body>", end_search_start)

        if start_idx != -1 and end_idx != -1:
            # Replace placeholder with generated content (keep </body></html>)
            modified = template[:start_idx] + leaderboard_content + template[end_idx:]
        else:
            modified = template
    else:
        # Fallback: insert before poster
        insertion_marker = "<!-- Paper poster -->"
        if insertion_marker in template:
            modified = template.replace(
                insertion_marker, leaderboard_content + insertion_marker
            )
        else:
            modified = template

    return modified


def update_template_metadata(template: str) -> str:
    """Update template metadata for the leaderboard."""
    replacements = {
        "PAPER_TITLE": "Malicious PR Benchmark Leaderboard",
        "AUTHOR_NAMES": "SocialAITBD",
        "BRIEF_DESCRIPTION_OF_YOUR_RESEARCH_CONTRIBUTION_AND_FINDINGS": "Model evaluation on security review and malicious PR detection capabilities",
        "INSTITUTION_OR_LAB_NAME": "SocialAITBD",
        "YOUR_DOMAIN.com": "github.com",
        "YOUR_PROJECT_PAGE": "SocialAITBD/malicious-pr-bench",
    }

    result = template
    for old, new in replacements.items():
        result = result.replace(old, new)

    return result


def generate_leaderboard_data(
    results: dict[str, dict[str, list[dict]]], output_path: Path
) -> None:
    """Generate JSON data file for frontend visualization and filtering."""
    # Flatten results into a single list with all metadata
    data_points = []

    for task_name, cwes_dict in results.items():
        for cwe, entries in cwes_dict.items():
            for entry in entries:
                data_point = {
                    **entry,
                    "task": task_name,
                }
                data_points.append(data_point)

    # Group by model/harness for easier filtering
    grouped = {}
    for point in data_points:
        key = f"{point['model']}_{point['harness']}"
        if key not in grouped:
            grouped[key] = {
                "model": point["model"],
                "harness": point["harness"],
                "data": [],
            }
        grouped[key]["data"].append(point)

    # Create output structure
    output = {
        "timestamp": datetime.now().isoformat(),
        "total_runs": len(data_points),
        "data_points": data_points,
        "grouped": grouped,
        "models": sorted(set(p["model"] for p in data_points)),
        "harnesses": sorted(set(p["harness"] for p in data_points)),
        "cwes": sorted(set(p["cwe"] for p in data_points)),
        "tasks": sorted(set(p["task"] for p in data_points)),
    }

    # Write JSON
    output_path.write_text(json.dumps(output, indent=2))
    print(f"📊 Data exported: {output_path}")


def _format_task_name(task: str) -> str:
    """Format task name for display."""
    task_map = {
        "reviewer_benchmark": "🔍 Malicious PR Detection",
        "pov_benchmark": "✅ Proof of Vulnerability",
        "benign_benchmark": "📋 Benign PR Evaluation",
    }
    return task_map.get(task, task.replace("_", " ").title())


def _get_status_badge(status: str) -> str:
    """Generate Bulma badge for status."""
    status_map = {
        "completed": ("is-success", "✓"),
        "running": ("is-warning", "⟳"),
        "failed": ("is-danger", "✗"),
        "cancelled": ("is-info", "−"),
    }

    tag_class, icon = status_map.get(status, ("is-info", "?"))
    return f'<span class="tag {tag_class}">{icon} {status}</span>'


def main():
    parser = argparse.ArgumentParser(
        description="Generate benchmark leaderboard from Academic template"
    )
    parser.add_argument(
        "--logs",
        type=Path,
        default=Path("docs/logs"),
        help="Input logs directory (default: docs/logs)",
    )
    parser.add_argument(
        "--template",
        type=Path,
        default=Path("docs/index.html"),
        help="Academic template HTML (default: docs/index.html)",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("docs/index.html"),
        help="Output HTML file (default: docs/index.html)",
    )
    parser.add_argument(
        "--skip-years",
        type=int,
        nargs="+",
        help="Skip logs from specific years",
    )
    parser.add_argument(
        "--tool-modes",
        choices=["sandbox", "gitea"],
        nargs="+",
        help="Only include specific tool modes",
    )

    args = parser.parse_args()

    print(f"📊 Scanning logs in {args.logs}...")
    results = parse_logs(
        args.logs,
        skip_years=args.skip_years,
        tool_modes=args.tool_modes,
    )

    total = sum(
        sum(len(entries) for entries in cwes_dict.values())
        for cwes_dict in results.values()
    )
    print(f"Found {total} benchmark runs across {len(results)} tasks")

    print(f"📄 Loading template from {args.template}...")
    template = load_template(args.template)

    print(f"🎨 Generating leaderboard...")
    template = update_template_metadata(template)
    html = insert_leaderboard_content(template, results)

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(html)
    print(f"✅ Leaderboard generated: {args.output}")

    # Generate data JSON for frontend
    data_output = args.output.parent / "leaderboard_data.json"
    generate_leaderboard_data(results, data_output)


if __name__ == "__main__":
    main()
