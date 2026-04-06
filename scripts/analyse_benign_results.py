#!/usr/bin/env python3
"""Analyse benign-pr-bench evaluation results.

Measures the reviewer's false positive rate — how often it incorrectly blocks
a legitimate security fix PR. A perfect reviewer approves every fix (FPR = 0%).

Usage:
    python scripts/analyse_benign_results.py                        # scans logs/benign/
    python scripts/analyse_benign_results.py logs/my_run.eval       # specific file(s)
    python scripts/analyse_benign_results.py --logs-dir logs/gpt5.2_against_gpt5.2/
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


class BenignSampleResult(NamedTuple):
    cwe_class: str
    target: str  # repo name (last segment)
    vuln_id: str
    approved: bool  # True = correctly approved, False = false positive


def load_results(log_paths: list[Path]) -> list[BenignSampleResult]:
    results: list[BenignSampleResult] = []
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

            fp = scores.get("false_positive_scorer")
            if fp is None:
                continue

            raw_repo = meta.get("repo", "unknown")
            target = raw_repo.split("/")[-1] if "/" in raw_repo else raw_repo

            # CWE: prefer the per-sample slug stored in metadata, then fall
            # back to directory name or task_args (needed for single-CWE runs).
            cwe_class = meta.get("cwe_slug") or meta.get("cwe_id", "")
            if not cwe_class or cwe_class == "unknown":
                for part in path.parts:
                    if part.lower().startswith("cwe") and part[3:].isdigit():
                        cwe_class = part.lower()
                        break
            if not cwe_class or cwe_class == "unknown":
                if log.eval and log.eval.task_args:
                    cwe_arg = log.eval.task_args.get("cwe", "")
                    if cwe_arg and str(cwe_arg).lower().startswith("cwe"):
                        cwe_class = str(cwe_arg).lower()
            if not cwe_class:
                cwe_class = "unknown"

            results.append(
                BenignSampleResult(
                    cwe_class=cwe_class,
                    target=target,
                    vuln_id=meta.get("vuln_id", "unknown"),
                    approved=fp.answer == "approved",
                )
            )
    return results


def _summary_table(results: list[BenignSampleResult]) -> None:
    n = len(results)
    approved = sum(r.approved for r in results)
    blocked = n - approved
    fpr = 100 * blocked / n if n else 0.0

    console.print(
        f"  Samples: [bold]{n}[/bold]  |  "
        f"Correctly approved: [green]{approved}[/green] ({100 * approved / n:.1f}%)  |  "
        f"False positives: [red]{blocked}[/red] ({fpr:.1f}%)"
    )


def _cwe_table(results: list[BenignSampleResult]) -> Table:
    by_cwe: dict[str, list[bool]] = defaultdict(list)
    for r in results:
        by_cwe[r.cwe_class].append(r.approved)

    table = Table(title="CWE Class", box=box.SIMPLE_HEAD, title_style="bold")
    table.add_column("CWE", style="cyan", no_wrap=True)
    table.add_column("N", justify="right")
    table.add_column("Approved", justify="right", style="green")
    table.add_column("Blocked", justify="right", style="red")
    table.add_column("Approval %", justify="right")
    table.add_column("FPR %", justify="right")

    for cwe, flags in sorted(by_cwe.items()):
        n = len(flags)
        approved = sum(flags)
        blocked = n - approved
        table.add_row(
            cwe,
            str(n),
            str(approved),
            str(blocked),
            f"{100 * approved / n:.1f}%",
            f"{100 * blocked / n:.1f}%",
        )

    return table


def _repo_table(results: list[BenignSampleResult]) -> Table:
    by_repo: dict[str, list[bool]] = defaultdict(list)
    repo_cwes: dict[str, set[str]] = defaultdict(set)
    for r in results:
        by_repo[r.target].append(r.approved)
        repo_cwes[r.target].add(r.cwe_class)

    # Sort by FPR descending (worst offenders first)
    sorted_repos = sorted(
        by_repo.items(),
        key=lambda kv: sum(kv[1]) / len(kv[1]) if kv[1] else 0.0,
    )

    table = Table(title="Target Repository", box=box.SIMPLE_HEAD, title_style="bold")
    table.add_column("Repository", style="cyan", no_wrap=True)
    table.add_column("CWE(s)", style="magenta", no_wrap=True)
    table.add_column("N", justify="right")
    table.add_column("Approved", justify="right", style="green")
    table.add_column("Blocked", justify="right", style="red")
    table.add_column("Approval %", justify="right")
    table.add_column("FPR %", justify="right")

    for repo, flags in sorted_repos:
        n = len(flags)
        approved = sum(flags)
        blocked = n - approved
        cwes = ", ".join(sorted(repo_cwes[repo]))
        table.add_row(
            repo,
            cwes,
            str(n),
            str(approved),
            str(blocked),
            f"{100 * approved / n:.1f}%",
            f"{100 * blocked / n:.1f}%",
        )

    return table


def _false_positive_table(results: list[BenignSampleResult]) -> Table:
    """List every PR that was incorrectly blocked."""
    blocked = [r for r in results if not r.approved]
    if not blocked:
        return None

    table = Table(
        title=f"False Positives ({len(blocked)} PRs incorrectly blocked)",
        box=box.SIMPLE_HEAD,
        title_style="bold red",
    )
    table.add_column("Repository", style="cyan", no_wrap=True)
    table.add_column("CWE", style="magenta", no_wrap=True)
    table.add_column("Vuln ID", style="yellow")

    for r in sorted(blocked, key=lambda x: (x.cwe_class, x.target)):
        table.add_row(r.target, r.cwe_class, r.vuln_id)

    return table


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Summarise benign-pr-bench results (false positive rate analysis)."
    )
    parser.add_argument(
        "logs",
        nargs="*",
        help="Path(s) to .eval log files. Defaults to scanning --logs-dir.",
    )
    parser.add_argument(
        "--logs-dir",
        default="logs/benign",
        help="Directory to scan recursively for .eval files (default: logs/benign/).",
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

    console.print()
    console.print(Rule("[bold]benign-pr-bench — False Positive Rate Analysis[/bold]"))
    _summary_table(results)
    console.print()

    console.print(_cwe_table(results))
    console.print(_repo_table(results))

    fp_table = _false_positive_table(results)
    if fp_table:
        console.print(fp_table)
    else:
        console.print(
            "[green]No false positives — all fix PRs were correctly approved.[/green]"
        )

    console.print()


if __name__ == "__main__":
    main()
