#!/usr/bin/env python3
"""Analyse malicious-pr-bench evaluation results with per-axis breakdowns.

Usage:
    python scripts/analyse_results.py                        # scans logs/ directory
    python scripts/analyse_results.py logs/my_run.eval       # specific file(s)
    python scripts/analyse_results.py --logs-dir logs/cwe79  # specific sub-directory
"""

import argparse
import sys
from collections import defaultdict
from pathlib import Path
from typing import NamedTuple

from inspect_ai.log import read_eval_log
from rich import box
from rich.console import Console
from rich.rule import Rule
from rich.table import Table

console = Console()


class SampleResult(NamedTuple):
    category: str
    axis1: str
    axis2: str
    axis3: str
    detection_score: float  # 1.0 = blocked, 0.0 = fooled
    security_reason_score: float | None  # 1.0 = security-motivated, 0.0 = other, None = N/A


def load_results(log_paths: list[Path]) -> list[SampleResult]:
    results: list[SampleResult] = []
    for path in log_paths:
        try:
            log = read_eval_log(str(path))
        except Exception as exc:
            console.print(f"[yellow]Warning: could not read {path}: {exc}[/yellow]")
            continue
        if not log.samples:
            continue
        for sample in log.samples:
            meta = sample.metadata or {}
            scores = sample.scores or {}

            det = scores.get("detection_scorer")
            if det is None:
                continue

            sec = scores.get("security_reason_scorer")
            sec_val: float | None = None
            if sec is not None and sec.answer != "not_applicable":
                try:
                    sec_val = float(sec.value)
                except (TypeError, ValueError):
                    pass

            results.append(
                SampleResult(
                    category=meta.get("category", "unknown"),
                    axis1=meta.get("axis1", "unknown"),
                    axis2=meta.get("axis2", "unknown"),
                    axis3=meta.get("axis3", "unknown"),
                    detection_score=float(det.value),
                    security_reason_score=sec_val,
                )
            )
    return results


def _axis_table(title: str, groups: dict[str, list[float]]) -> Table:
    table = Table(title=title, box=box.SIMPLE_HEAD, title_style="bold")
    table.add_column("Value", style="cyan", no_wrap=True)
    table.add_column("N", justify="right")
    table.add_column("Detected", justify="right", style="green")
    table.add_column("Fooled", justify="right", style="red")
    table.add_column("Detection %", justify="right")
    table.add_column("ASR %", justify="right")

    # Sort by detection rate ascending (hardest to detect first)
    sorted_items = sorted(
        groups.items(),
        key=lambda kv: sum(kv[1]) / len(kv[1]) if kv[1] else 0.0,
    )

    for value, scores in sorted_items:
        n = len(scores)
        detected = sum(scores)
        fooled = n - detected
        det_pct = f"{100 * detected / n:.1f}%"
        asr_pct = f"{100 * fooled / n:.1f}%"
        table.add_row(value, str(n), str(int(detected)), str(int(fooled)), det_pct, asr_pct)

    return table


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Summarise malicious-pr-bench results broken down by axis."
    )
    parser.add_argument(
        "logs",
        nargs="*",
        help="Path(s) to .eval log files. Defaults to scanning --logs-dir.",
    )
    parser.add_argument(
        "--logs-dir",
        default="logs",
        help="Directory to scan recursively for .eval files (default: logs/).",
    )
    args = parser.parse_args()

    if args.logs:
        paths = [Path(p) for p in args.logs]
    else:
        logs_dir = Path(args.logs_dir)
        if not logs_dir.is_dir():
            console.print(f"[red]Directory not found: {logs_dir}[/red]")
            sys.exit(1)
        paths = sorted(logs_dir.rglob("*.eval"))

    if not paths:
        console.print("[red]No .eval files found.[/red]")
        sys.exit(1)

    console.print(f"[dim]Loading {len(paths)} log file(s)…[/dim]")
    results = load_results(paths)

    if not results:
        console.print("[red]No scored samples found in the provided logs.[/red]")
        sys.exit(1)

    n = len(results)
    detected = sum(r.detection_score for r in results)
    fooled = n - detected

    console.print()
    console.print(Rule("[bold]malicious-pr-bench — Results Summary[/bold]"))
    console.print(
        f"  Samples: [bold]{n}[/bold]  |  "
        f"Detected: [green]{int(detected)}[/green] ({100 * detected / n:.1f}%)  |  "
        f"Fooled: [red]{int(fooled)}[/red] ({100 * fooled / n:.1f}%)"
    )
    console.print()

    # Aggregate by each dimension
    by_category: dict[str, list[float]] = defaultdict(list)
    by_axis1: dict[str, list[float]] = defaultdict(list)
    by_axis2: dict[str, list[float]] = defaultdict(list)
    by_axis3: dict[str, list[float]] = defaultdict(list)

    for r in results:
        by_category[r.category].append(r.detection_score)
        by_axis1[r.axis1].append(r.detection_score)
        by_axis2[r.axis2].append(r.detection_score)
        by_axis3[r.axis3].append(r.detection_score)

    console.print(_axis_table("Category — Vulnerability Type", by_category))
    console.print(_axis_table("Axis 1 — Distribution Strategy", by_axis1))
    console.print(_axis_table("Axis 2 — Code Concealment", by_axis2))
    console.print(_axis_table("Axis 3 — PR Framing / Social Engineering", by_axis3))

    # Security-reason scorer (only populated for blocked samples)
    sec_results = [r for r in results if r.security_reason_score is not None]
    if sec_results:
        sec_n = len(sec_results)
        sec_motivated = sum(r.security_reason_score for r in sec_results)
        console.print()
        console.print(Rule("[bold]Security Reason Scorer[/bold]"))
        console.print(
            f"  Of {sec_n} blocked samples: "
            f"[green]{int(sec_motivated)}[/green] ({100 * sec_motivated / sec_n:.1f}%) "
            f"refused for security reasons, "
            f"[yellow]{int(sec_n - sec_motivated)}[/yellow] "
            f"({100 * (sec_n - sec_motivated) / sec_n:.1f}%) for other reasons."
        )
        console.print()


if __name__ == "__main__":
    main()
