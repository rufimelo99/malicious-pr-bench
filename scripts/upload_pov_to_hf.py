#!/usr/bin/env python3
"""Upload ProofOfVulnerability data to HuggingFace Hub."""

import argparse
import json
from pathlib import Path
from typing import Optional

from huggingface_hub import CommitOperationAdd, HfApi, create_repo

POV_PROOFS_DIR = Path(__file__).parent.parent / "proof_of_vulnerability" / "proofs"
POV_LOGS_DIR = (
    Path(__file__).parent.parent / "proof_of_vulnerability" / "trajectory_logs"
)

ORG_NAME = "SocialAITBD"
PROOFS_REPO_ID = f"{ORG_NAME}/ProofOfVulnerability"
LOGS_REPO_ID = f"{ORG_NAME}/ProofOfVulnerabilityLogs"


def create_proofs_readme() -> str:
    """Generate README for proofs dataset."""
    return """---
license: cc-by-4.0
dataset_info:
  features:
    - name: cwe_id
      dtype: string
    - name: proof_id
      dtype: string
    - name: data
      dtype: json
  splits:
    - name: train
      num_examples: null
---

# ProofOfVulnerability

Proof of vulnerability (POV) datasets containing JSON structures documenting code vulnerabilities and their exploitation paths.

## Structure

- **cwe79/**: Cross-site scripting (XSS) proofs
- **cwe89/**: SQL injection proofs
- **pov_results.jsonl**: Summary results across all proofs

## Data Format

Each `.json` file contains:
- Vulnerability details
- Exploitation steps
- Code context
- Metadata

See individual proof files for full schema.

## Usage

```python
from datasets import load_dataset
ds = load_dataset("SocialAITBD/ProofOfVulnerability")
```

## Citation

```bibtex
@dataset{pov_vulnerability,
  title={Proof of Vulnerability Dataset},
  organization={SocialAITBD}
}
```
"""


def create_logs_readme() -> str:
    """Generate README for trajectory logs dataset."""
    return """---
license: cc-by-4.0
---

# ProofOfVulnerabilityLogs

Trajectory logs documenting the discovery and exploitation process for each proof of vulnerability.

## Structure

Organized by CWE type:
- **cwe79/**: XSS trajectory logs
- **cwe89/**: SQL injection trajectory logs

Each `.log` file corresponds to a proof in the ProofOfVulnerability dataset (same filename).

## Format

Plain text logs containing:
- Step-by-step execution traces
- Model reasoning
- API calls and responses
- Vulnerability discovery process

## Usage

Load alongside proofs dataset using matching filenames.

## Citation

```bibtex
@dataset{pov_logs,
  title={Proof of Vulnerability Trajectory Logs},
  organization={SocialAITBD}
}
```
"""


def upload_dataset(
    repo_id: str,
    source_dir: Path,
    readme_content: str,
    token: Optional[str] = None,
    private: bool = False,
) -> None:
    """Upload directory to HuggingFace dataset repository."""
    api = HfApi(token=token)

    # Create repo if it doesn't exist
    create_repo(
        repo_id, repo_type="dataset", private=private, exist_ok=True, token=token
    )

    # Prepare upload operations
    operations = []

    # Add README
    operations.append(
        CommitOperationAdd(
            path_in_repo="README.md",
            path_or_fileobj=readme_content.encode(),
        )
    )

    # Add all files from source directory, preserving structure
    for file_path in sorted(source_dir.rglob("*")):
        if file_path.is_file():
            rel_path = file_path.relative_to(source_dir)
            operations.append(
                CommitOperationAdd(
                    path_in_repo=str(rel_path),
                    path_or_fileobj=file_path,
                )
            )
            print(f"  → {rel_path}")

    if not operations:
        print(f"No files found in {source_dir}")
        return

    print(f"\nUploading {len(operations) - 1} files to {repo_id}...")
    api.create_commit(
        repo_id=repo_id,
        operations=operations,
        commit_message="Update POV data",
        repo_type="dataset",
        token=token,
    )
    print(f"✓ Successfully uploaded to {repo_id}")


def main():
    parser = argparse.ArgumentParser(description="Upload POV data to HuggingFace Hub")
    parser.add_argument(
        "--token",
        type=str,
        help="HuggingFace API token (or use HF_TOKEN env var)",
    )
    parser.add_argument(
        "--proofs-only",
        action="store_true",
        help="Only upload proofs dataset",
    )
    parser.add_argument(
        "--logs-only",
        action="store_true",
        help="Only upload logs dataset",
    )
    parser.add_argument(
        "--private",
        action="store_true",
        help="Make datasets private",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Show what would be uploaded without uploading",
    )

    args = parser.parse_args()

    if not POV_PROOFS_DIR.exists():
        raise FileNotFoundError(f"POV proofs directory not found: {POV_PROOFS_DIR}")
    if not POV_LOGS_DIR.exists():
        raise FileNotFoundError(f"POV logs directory not found: {POV_LOGS_DIR}")

    # Count files
    proofs_count = sum(1 for p in POV_PROOFS_DIR.rglob("*") if p.is_file())
    logs_count = sum(1 for p in POV_LOGS_DIR.rglob("*") if p.is_file())

    print(f"Found {proofs_count} proof files")
    print(f"Found {logs_count} log files")

    if args.dry_run:
        print("\n[DRY RUN] Would upload:")
        if not args.logs_only:
            print(f"\n{PROOFS_REPO_ID}:")
            for f in sorted(POV_PROOFS_DIR.rglob("*"))[:5]:
                if f.is_file():
                    print(f"  → {f.relative_to(POV_PROOFS_DIR)}")
            print("  ...")
        if not args.proofs_only:
            print(f"\n{LOGS_REPO_ID}:")
            for f in sorted(POV_LOGS_DIR.rglob("*"))[:5]:
                if f.is_file():
                    print(f"  → {f.relative_to(POV_LOGS_DIR)}")
            print("  ...")
        return

    if not args.logs_only:
        print(f"\n📤 Uploading proofs to {PROOFS_REPO_ID}...")
        upload_dataset(
            PROOFS_REPO_ID,
            POV_PROOFS_DIR,
            create_proofs_readme(),
            token=args.token,
            private=args.private,
        )

    if not args.proofs_only:
        print(f"\n📤 Uploading logs to {LOGS_REPO_ID}...")
        upload_dataset(
            LOGS_REPO_ID,
            POV_LOGS_DIR,
            create_logs_readme(),
            token=args.token,
            private=args.private,
        )

    print("\n✅ Done!")


if __name__ == "__main__":
    main()
