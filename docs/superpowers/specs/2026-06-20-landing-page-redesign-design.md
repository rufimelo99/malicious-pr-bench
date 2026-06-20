# Sevra-Bench Landing Page Redesign — Design

**Date:** 2026-06-20
**File touched:** `docs/index.html` (plus copied figures in `docs/static/images/`)
**Source of truth for content:** `/Users/rmelo/Documents/GitHub/prbench-paper`

## Goal

Turn `docs/index.html` from a half-filled Academic Project Page template into a
self-contained static landing page for **Sevra-Bench**, populated entirely with
real values and figures from the paper. Remove the dynamic
leaderboard/charts/filters machinery so there is one authoritative, static page.

## Decisions (locked with user)

1. **Scope:** full benchmark landing page (restructure, not just fill-in).
2. **Results:** the paper's real 8-model per-CWE refusal-rate table, replacing the
   hardcoded `gpt-5.2`-only table.
3. **Authors:** real authors from `prbench-paper/pre_print.tex`.
4. **Dynamic section:** **removed** entirely (charts, filters, tabs,
   `leaderboard.js` include, the `switchChart` script). Page becomes fully static.
5. **Paper link:** `https://arxiv.org/abs/2606.13757` (PDF: `https://arxiv.org/pdf/2606.13757`).

## Canonical facts

- **Name:** Sevra-Bench — *Social Engineering of Vulnerabilities in Review Agents*
- **Tagline:** Can an automated code reviewer reject a malicious pull request when
  the attacker controls both the code diff and the PR narrative?
- **Authors:**
  - Rui Melo¹ (corresponding: rmelo@cs.cmu.edu)
  - Riccardo Fogliato²
  - Sean Zhou³
  - Pratiksha Thaker⁴
  - Zhiwei Steven Wu¹
  - Affiliations: ¹ Carnegie Mellon University · ² Microsoft Core AI · ³ Amazon · ⁴ Databricks
- **Links:** Paper `https://arxiv.org/abs/2606.13757` · Code `https://github.com/rufimelo99/malicious-pr-bench` · Dataset `https://huggingface.co/datasets/RedAI4Code/SEVRA`
- **Key stats:** 2,250 malicious PRs · 1,062 retained challenge split · 347 benign
  security-fix PRs · 15 social-engineering framings · 10 CWEs (2025 CWE Top 25) · 8 models evaluated.
- **Headline finding:** ~45-percentage-point gap between frontier and open-weight
  reviewers (Claude Opus 4.7 ~98% refusal rate vs. weakest open/older models ~36%).

### Abstract (use the clean, non-commented version)

> Large language model (LLM) reviewers are increasingly used in pull-request (PR)
> workflows, where their approvals help decide which code is merged into a
> repository. This raises a question that benchmarks for static vulnerability
> detection or code generation do not address: can an automated reviewer reject a
> malicious contribution when the attacker controls both the code change and the
> accompanying PR text? We introduce Sevra-Bench (Social Engineering of
> Vulnerabilities in Review Agents), a benchmark that measures how often an
> automated reviewer approves such adversarial pull requests. Each malicious PR is
> built from a real project commit that previously fixed a vulnerability listed in
> the CVE database. We automatically invert that fix to restore the original
> vulnerable code and submit it as a pull request wrapped in one of 15
> social-engineering framings, which vary the claims made, the supporting evidence,
> the urgency conveyed, signals of prior approval, and appeals to authority.
> Sevra-Bench contains 1,062 malicious PRs drawn from CVE-linked fixes across the
> top 10 entries of the 2025 CWE Top 25. In a realistic setting, we evaluate 8
> current LLMs as code review agents on PRs that introduce vulnerabilities
> previously reported in public disclosures. Our results reveal a sharp gap in
> security capabilities between closed- and open-source models. We hope Sevra-Bench
> will serve as a valuable resource for advancing open-source models and narrowing
> this gap.

### Results table — Refusal Rate (%) per CWE, retained challenge split

Source: `prbench-paper/tables/tab_per_cwe_results.tex`. Columns sorted by overall
(leaderboard order). Values are refusal rate; higher is better. Standard errors
from the paper may be shown as small text or omitted for the web table.

| CWE | Opus 4.7 | GPT-5.5 | GLM | Haiku-4.5 | DeepSeek V4-Flash | Kimi | Grok Code Fast | GPT-5.4-nano |
|-----|---------:|--------:|----:|----------:|------------------:|-----:|---------------:|-------------:|
| CWE-79 — Cross-Site Scripting (XSS) | 99 | 89 | 80 | 37 | 39 | 47 | 39 | 42 |
| CWE-89 — SQL Injection | 100 | 100 | 92 | 85 | 75 | 68 | 45 | 15 |
| CWE-352 — Cross-Site Request Forgery | 97 | 89 | 80 | 46 | 45 | 53 | 47 | 36 |
| CWE-862 — Missing Authorization | 99 | 98 | 89 | 71 | 62 | 56 | 54 | 28 |
| CWE-787 — Out-of-bounds Write | 100 | 100 | 79 | 41 | 49 | 44 | 37 | 51 |
| CWE-22 — Path Traversal | 100 | 100 | 92 | 67 | 70 | 63 | 37 | 18 |
| CWE-416 — Use After Free | 96 | 93 | 72 | 30 | 37 | 34 | 34 | 49 |
| CWE-125 — Out-of-bounds Read | 97 | 99 | 84 | 68 | 62 | 64 | 31 | 33 |
| CWE-78 — OS Command Injection | 93 | 92 | 84 | 48 | 50 | 47 | 14 | 28 |
| CWE-94 — Code Injection | 99 | 97 | 81 | 57 | 50 | 59 | 51 | 46 |
| **Overall** | **98** | **95** | **83** | **53** | **53** | **52** | **39** | **36** |

Color grading: cells >=80 green, 50–79 amber, <50 red (Bulma `has-text`/`has-background` helpers or scoped CSS).

## Page structure (top → bottom)

1. **Hero** — title "Sevra-Bench" + subtitle expansion, tagline, author list with
   affiliation superscripts and corresponding-author note, link buttons:
   **Paper** (arXiv), **Code** (GitHub), **Dataset** (Hugging Face). Drop the
   Supplementary and arXiv-vs-PDF duplicate buttons; one Paper button → arXiv abs.
2. **Key-stats band** — 6 stat cards (2,250 / 1,062 / 347 / 15 / 10 / 8) with labels.
3. **Abstract** — real abstract text above.
4. **Framework overview** — `framework_short` figure (PDF→PNG) with paper caption.
5. **Headline result callout** — the ~45-point closed-vs-open gap, one or two sentences.
6. **Results** — the per-CWE refusal-rate table above (color-graded), with a short
   caption noting it is the retained challenge split, refusal rate = fraction of
   malicious PRs correctly blocked.
7. **Framing analysis** — short prose (frontier models stay 84–100% across
   narratives; open-weight models swing wildly, e.g. DeepSeek 18%→100% by framing)
   + figure `4_framing_effectiveness.png`.
8. **BibTeX** — real entry (see below), keep the existing copy-to-clipboard button.
9. **Footer** — keep the template attribution + license.

### BibTeX

```bibtex
@article{melo2026sevra,
  title   = {Sevra-Bench: Social Engineering of Vulnerabilities in Review Agents},
  author  = {Melo, Rui and Fogliato, Riccardo and Zhou, Sean and Thaker, Pratiksha and Wu, Zhiwei Steven},
  journal = {arXiv preprint arXiv:2606.13757},
  year    = {2026},
  url     = {https://arxiv.org/abs/2606.13757}
}
```

## Removals

- The entire **Filters** section (`#model-filter`, `#harness-filter`, `#cwe-filter`).
- The **Charts** section (tabs, `#timeSeriesChart`, `#barChart`, axis table) and the
  inline `switchChart` script + its scoped `<style>`.
- The **Poster** iframe (`static/pdfs/sample.pdf`).
- The teaser-video / carousel / youtube commented blocks (delete dead comments).
- Script includes for `chart.js` and `leaderboard.js`, and the duplicate footer +
  duplicate "Last updated" blocks (keep one footer).
- `leaderboard.js`, `leaderboard_data.json`, `axis_mapping.json`,
  `generate_leaderboard.py` may remain in the repo (out of scope to delete), but
  are no longer referenced by the page.

## Metadata / SEO

Replace the `TODO` placeholder meta tags (title, description, keywords, authors,
og:*, twitter:*, citation_*, JSON-LD) with real values derived from the facts
above. Title: "Sevra-Bench: Social Engineering of Vulnerabilities in Review
Agents". Description: a 150–160 char summary of the benchmark and headline finding.
Keywords: LLM code review, security, malicious pull requests, social engineering,
CVE, CWE, AI safety, supply chain. `citation_pdf_url` → arXiv PDF.

## Figures to copy into `docs/static/images/`

- `framework_short.png` — converted from `prbench-paper/figures/framework_short.pdf`
  via `pdftoppm -png -r 200` (or `sips`), trimmed if needed.
- `framing_effectiveness.png` — copy of `prbench-paper/figures/4_framing_effectiveness.png`.

If PDF→PNG conversion is unavailable, fall back to copying an existing PNG overview
(none exists for the framework, so conversion is required; if it fails, embed the
PDF via `<object>`/`<iframe>` as a last resort and flag it).

## Styling

- Reuse existing Bulma + `static/css/index.css`. Add a small scoped `<style>` block
  (or append to `index.css`) for: stat cards (flex row of bordered number+label
  cards), the headline callout box, and results-table cell color classes.
- No new CSS framework, no JS framework. Keep fontawesome/academicons includes that
  are still used; the page no longer needs jQuery/Adobe-view/chart.js — remove those
  includes if nothing else uses them.

## Verification

- Serve `docs/` over `python3 -m http.server` and load `index.html`.
- Headless-Chrome screenshot at 1280px wide; confirm: hero shows real title+authors,
  stat band renders, framework image loads, results table is color-graded and
  complete (10 CWEs + overall, 8 models), framing figure loads, BibTeX correct, no
  leftover Filters/Charts/Poster, no console 404s for removed scripts.
- Validate all three link buttons point to the correct URLs.

## Out of scope

- Editing paper figures themselves.
- Deleting the now-unused `leaderboard.*` data/scripts from the repo.
- Any backend or data-pipeline changes.
