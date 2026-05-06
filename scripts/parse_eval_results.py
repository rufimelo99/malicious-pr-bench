#!/usr/bin/env python3
"""Parse .eval files from logs/malicious/ into a flat CSV table."""

import csv
import json
import os
import re
import sys
import zipfile
from pathlib import Path


LOGS_DIR = Path(__file__).parent.parent / "logs" / "malicious"
OUTPUT_CSV = Path(__file__).parent.parent / "results.csv"

FIELDNAMES = [
    "folder",
    "model",
    "cwe",
    "prompt_variant",
    "tool_mode",
    "sample_id",
    "repo",
    "pr_number",
    "axis1",
    "axis2",
    "axis3",
    "pr_title",
    "detection_score",
    "detection_answer",
    "security_reason_score",
    "security_reason_answer",
    "status",
    "total_time",
    "error",
]


def find_eval_file(folder: Path) -> Path | None:
    for f in folder.iterdir():
        if f.suffix == ".eval":
            return f
    return None


def load_json_from_zip(zf: zipfile.ZipFile, path: str) -> dict | list | None:
    try:
        with zf.open(path) as f:
            return json.load(f)
    except (KeyError, json.JSONDecodeError):
        return None


def get_status(scores: dict, error) -> str:
    if error:
        return "incomplete"
    detection = scores.get("detection_scorer", {})
    answer = detection.get("answer", "")
    if answer == "blocked":
        return "success"
    if answer == "merged":
        return "fail"
    if not answer:
        return "incomplete"
    return "fail"


def parse_eval(folder: Path) -> list[dict]:
    eval_file = find_eval_file(folder)
    if eval_file is None:
        print(f"  WARNING: no .eval file in {folder.name}", file=sys.stderr)
        return []

    rows = []
    try:
        with zipfile.ZipFile(eval_file) as zf:
            start = load_json_from_zip(zf, "_journal/start.json")
            if start is None:
                print(f"  WARNING: could not read start.json in {folder.name}", file=sys.stderr)
                return []

            task_args = start.get("eval", {}).get("task_args", {})
            cwe = task_args.get("cwe", "")
            prompt_variant = task_args.get("prompt_variant", "")
            tool_mode = task_args.get("tool_mode", "")

            sample_names = [
                n for n in zf.namelist()
                if n.startswith("samples/") and n.endswith(".json")
            ]

            model = None

            for sample_name in sample_names:
                sample = load_json_from_zip(zf, sample_name)
                if sample is None:
                    continue

                if model is None:
                    model = sample.get("output", {}).get("model", "")

                metadata = sample.get("metadata", {})
                scores = sample.get("scores", {})
                error = sample.get("error")

                repo_full = metadata.get("repo", "")
                repo = repo_full.split("/")[-1] if "/" in repo_full else repo_full

                detection = scores.get("detection_scorer", {})
                security = scores.get("security_reason_scorer", {})

                rows.append({
                    "folder": folder.name,
                    "model": model or "",
                    "cwe": cwe,
                    "prompt_variant": prompt_variant,
                    "tool_mode": tool_mode,
                    "sample_id": sample.get("id", ""),
                    "repo": repo,
                    "pr_number": metadata.get("pr_number", ""),
                    "axis1": metadata.get("axis1", ""),
                    "axis2": metadata.get("axis2", ""),
                    "axis3": metadata.get("axis3", ""),
                    "pr_title": metadata.get("pr_title", ""),
                    "detection_score": detection.get("value", ""),
                    "detection_answer": detection.get("answer", ""),
                    "security_reason_score": security.get("value", ""),
                    "security_reason_answer": security.get("answer", ""),
                    "status": get_status(scores, error),
                    "total_time": sample.get("total_time", ""),
                    "error": error or "",
                })

    except zipfile.BadZipFile:
        print(f"  ERROR: bad zip file {eval_file}", file=sys.stderr)

    return rows


def main():
    all_rows = []

    folders = sorted(
        p for p in LOGS_DIR.iterdir()
        if p.is_dir()
    )

    for folder in folders:
        print(f"Parsing {folder.name} ...", file=sys.stderr)
        rows = parse_eval(folder)
        print(f"  -> {len(rows)} samples", file=sys.stderr)
        all_rows.extend(rows)

    output_path = Path(sys.argv[1]) if len(sys.argv) > 1 else OUTPUT_CSV

    with open(output_path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=FIELDNAMES)
        writer.writeheader()
        writer.writerows(all_rows)

    print(f"\nWrote {len(all_rows)} rows to {output_path}", file=sys.stderr)


if __name__ == "__main__":
    main()
