#!/usr/bin/env python3
"""
Extract assistant transcripts for eval-awareness analysis.

Scope (decided in brainstorming): the 8 models used in the paper plots
(excludes Sonnet 4.6 & GPT-OSS-120B), malicious-PR `plain` condition only,
retained challenge split. For each sample we store the concatenated assistant
message text plus its scores, so a downstream notebook can regex-scan it for
self-referential eval awareness ("...test whether I'll approve this...").

Run from this directory:
    python3 extract_eval_awareness.py
Output: ../../eval_awareness_samples.json
"""
import glob
import json
import os
import zipfile
from pathlib import Path

CWES = [
    "cwe79",
    "cwe89",
    "cwe352",
    "cwe862",
    "cwe787",
    "cwe22",
    "cwe416",
    "cwe125",
    "cwe78",
    "cwe94",
]

# Raw model key (substring) -> display name. Only these 8 are kept.
MODEL_NAMES = {
    "claude-opus-4-7": "Opus 4.7",
    "gpt-5.5": "GPT-5.5",
    "zai.glm-5": "GLM-5",
    "glm-5": "GLM-5",
    "haiku-4-5": "Haiku 4.5",
    "kimi-k2.5": "Kimi",
    "deepseek-v4": "DeepSeek",
    "grok-code-fast": "Grok",
    "gpt-5.4-nano": "GPT-5.4-nano",
}
EXCLUDE = ("sonnet", "gpt-oss")


def display_name(model_key):
    k = model_key.lower()
    if any(x in k for x in EXCLUDE):
        return None
    for sub, name in MODEL_NAMES.items():
        if sub in k:
            return name
    return None


def assistant_text(sample):
    parts = []
    for m in sample.get("messages") or []:
        if m.get("role") != "assistant":
            continue
        c = m.get("content")
        if isinstance(c, str):
            parts.append(c)
        elif isinstance(c, list):
            for b in c:
                if isinstance(b, dict) and b.get("text"):
                    parts.append(b["text"])
    return "\n".join(p for p in parts if p)


def main():
    retained = json.load(open("../../retained_sample_ids.json"))
    results_dirs = [
        Path("../../logs/results_nips"),
        Path("../../logs/filtering_releases"),
    ]

    out = []
    seen = set()  # (display, cwe, sample_id) to dedupe across dirs
    n_scanned = 0
    for rd in results_dirs:
        if not rd.exists():
            continue
        for dir_path in sorted(rd.glob("*_gitea_plain_cwe*")):
            if not dir_path.is_dir():
                continue
            name = dir_path.name
            model_key = name.split("_gitea_")[0]
            disp = display_name(model_key)
            if disp is None:
                continue
            rest = "_gitea_".join(name.split("_gitea_")[1:])
            if "_cwe" not in rest:
                continue
            cwe = "cwe" + rest.split("_cwe")[1].split("_")[0]
            if cwe not in CWES:
                continue

            # dedupe eval files oldest->newest so retries overwrite
            samples_by_id = {}
            for ef in sorted(dir_path.glob("*.eval")):
                try:
                    with zipfile.ZipFile(ef) as z:
                        for nm in z.namelist():
                            if nm.startswith("samples/") and nm.endswith(".json"):
                                s = json.load(z.open(nm))
                                sid = s.get("id")
                                if sid:
                                    samples_by_id[sid] = s
                except Exception:
                    continue

            for sid, s in samples_by_id.items():
                if "scores" not in s:
                    continue
                if sid not in retained.get(cwe, []):
                    continue
                framing = sid.split("-")[-1]
                if framing == "partial_test_coverage":
                    continue
                key = (disp, cwe, sid)
                if key in seen:
                    continue
                seen.add(key)
                n_scanned += 1
                det = s["scores"].get("detection_scorer", {}).get("value")
                srr = s["scores"].get("security_reason_scorer", {}).get("value")
                out.append(
                    {
                        "model": disp,
                        "model_key": model_key,
                        "cwe": cwe,
                        "framing": framing,
                        "sample_id": sid,
                        "detection_score": det,
                        "security_reason_score": srr,
                        "message_count": s.get("message_count"),
                        "assistant_text": assistant_text(s),
                    }
                )

    Path("../../eval_awareness_samples.json").write_text(json.dumps(out))
    from collections import Counter

    by_model = Counter(r["model"] for r in out)
    print(f"Extracted {len(out)} samples across {len(by_model)} models")
    for m, c in sorted(by_model.items(), key=lambda x: -x[1]):
        print(f"  {m:14s} {c}")


if __name__ == "__main__":
    main()
