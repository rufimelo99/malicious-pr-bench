# Sevra-Bench Landing Page Redesign Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Rebuild `docs/index.html` into a self-contained static landing page for Sevra-Bench, populated entirely with real paper values/figures, removing the dynamic charts/filters/leaderboard machinery.

**Architecture:** Single static HTML file using the existing Bulma + `static/css/index.css` setup, with a small scoped `<style>` block for stat cards, the headline callout, and color-graded results-table cells. Two figures are copied/converted from the paper repo into `docs/static/images/`. No JS framework, no data fetching.

**Tech Stack:** HTML5, Bulma CSS, FontAwesome/Academicons (already vendored), `pdftoppm` (figure conversion), `python3 -m http.server` + headless Chrome (verification).

## Global Constraints

- Benchmark name (verbatim): **Sevra-Bench** — *Social Engineering of Vulnerabilities in Review Agents*.
- Paper link: `https://arxiv.org/abs/2606.13757`; PDF: `https://arxiv.org/pdf/2606.13757`.
- Code: `https://github.com/rufimelo99/malicious-pr-bench`; Dataset: `https://huggingface.co/datasets/RedAI4Code/SEVRA`.
- Authors (order + affiliation superscripts): Rui Melo¹ (corresponding, rmelo@cs.cmu.edu), Riccardo Fogliato², Sean Zhou³, Pratiksha Thaker⁴, Zhiwei Steven Wu¹. Affiliations: ¹ Carnegie Mellon University · ² Microsoft Core AI · ³ Amazon · ⁴ Databricks.
- Key stats (verbatim): 2,250 malicious PRs · 1,062 retained challenge split · 347 benign security-fix PRs · 15 framings · 10 CWEs · 8 models.
- Results table = per-CWE **Refusal Rate (%)** on retained challenge split. Models sorted by overall descending: Opus 4.7 (98), GPT-5.5 (95), GLM (83), Haiku-4.5 (53), DeepSeek V4-Flash (53), Kimi (52), Grok Code Fast (39), GPT-5.4-nano (36). ±SE dropped for the web table.
- Color grading: refusal rate ≥80 green, 50–79 amber, <50 red.
- Source paper repo (read-only): `/Users/rmelo/Documents/GitHub/prbench-paper`.
- No new third-party CSS/JS frameworks. Keep the template footer attribution + CC license.
- Single page, fully static: no `leaderboard.js`, `chart.js`, jQuery, Adobe view SDK, filters, tabs, or `switchChart` script remaining referenced.

**Verification note:** there is no unit-test harness for a static HTML page. Each task is verified by `grep` assertions against the file and, for the final task, a headless-Chrome screenshot + console-404 check. Treat the "Run / Expected" blocks as the test cycle.

---

### Task 1: Copy and convert figures into `docs/static/images/`

**Files:**
- Create: `docs/static/images/framework_short.png`
- Create: `docs/static/images/framing_effectiveness.png`
- Source (read-only): `/Users/rmelo/Documents/GitHub/prbench-paper/figures/framework_short.pdf`, `/Users/rmelo/Documents/GitHub/prbench-paper/figures/4_framing_effectiveness.png`

**Interfaces:**
- Produces: two web image assets referenced by `docs/index.html` in Task 4 (`static/images/framework_short.png`) and Task 6 (`static/images/framing_effectiveness.png`).

- [ ] **Step 1: Convert the framework PDF to PNG and copy the framing PNG**

Run:
```bash
cd /Users/rmelo/Documents/GitHub/malicious-pr-bench
pdftoppm -png -r 200 -singlefile \
  /Users/rmelo/Documents/GitHub/prbench-paper/figures/framework_short.pdf \
  docs/static/images/framework_short
cp /Users/rmelo/Documents/GitHub/prbench-paper/figures/4_framing_effectiveness.png \
  docs/static/images/framing_effectiveness.png
```

- [ ] **Step 2: Verify both images exist and are non-empty**

Run:
```bash
cd /Users/rmelo/Documents/GitHub/malicious-pr-bench
ls -l docs/static/images/framework_short.png docs/static/images/framing_effectiveness.png && \
file docs/static/images/framework_short.png docs/static/images/framing_effectiveness.png
```
Expected: both files listed with non-zero size; `file` reports "PNG image data" for each.

- [ ] **Step 3: Commit**

```bash
cd /Users/rmelo/Documents/GitHub/malicious-pr-bench
git add docs/static/images/framework_short.png docs/static/images/framing_effectiveness.png
git commit -m "docs: add framework and framing figures for landing page

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 2: Replace the page `<head>` (metadata, SEO, includes)

This task rewrites everything from `<head>` through the closing `</head>` and removes now-unneeded script includes. The `<body>` is rewritten in Tasks 3–7; to keep the file valid between tasks, this task replaces only the `<head>` content.

**Files:**
- Modify: `docs/index.html` (lines ~3–180, the `<head>` block)

**Interfaces:**
- Produces: a `<head>` with real meta/SEO/JSON-LD and only the CSS/JS includes the static page needs (Bulma, index.css, fontawesome, academicons, Inter font). No jQuery, no Adobe view SDK, no chart.js, no bulma-carousel/slider JS required by remaining content — but carousel/slider CSS+JS may stay if harmless; remove jQuery + Adobe SDK + (later) chart.js/leaderboard.js.

- [ ] **Step 1: Read the current head to anchor the edit**

Run: `sed -n '1,181p' docs/index.html`
Expected: confirms the `<head>` spans the `<!DOCTYPE html>` line through line 180 `</head>` and `<body>` begins at 181.

- [ ] **Step 2: Replace the entire `<head>` block**

Replace lines from `<!DOCTYPE html>` through `</head>` (inclusive) with:

```html
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">

  <!-- Primary Meta Tags -->
  <meta name="title" content="Sevra-Bench: Social Engineering of Vulnerabilities in Review Agents">
  <meta name="description" content="Sevra-Bench benchmarks whether LLM code-review agents reject malicious pull requests when the attacker controls both the diff and the narrative. Reveals a 45-point gap between frontier and open-weight reviewers.">
  <meta name="keywords" content="LLM code review, AI security, malicious pull requests, social engineering, CVE, CWE, software supply chain, AI safety, agent evaluation, benchmark">
  <meta name="author" content="Rui Melo, Riccardo Fogliato, Sean Zhou, Pratiksha Thaker, Zhiwei Steven Wu">
  <meta name="robots" content="index, follow">
  <meta name="language" content="English">

  <!-- Open Graph / Facebook -->
  <meta property="og:type" content="article">
  <meta property="og:site_name" content="Sevra-Bench">
  <meta property="og:title" content="Sevra-Bench: Social Engineering of Vulnerabilities in Review Agents">
  <meta property="og:description" content="Can an automated reviewer reject a malicious PR when the attacker controls both the code diff and the narrative? A benchmark of 8 LLM reviewers across 10 CWEs and 15 social-engineering framings.">
  <meta property="og:url" content="https://github.com/rufimelo99/malicious-pr-bench">
  <meta property="og:image" content="static/images/framework_short.png">
  <meta property="og:image:alt" content="Sevra-Bench framework overview">

  <!-- Twitter -->
  <meta name="twitter:card" content="summary_large_image">
  <meta name="twitter:title" content="Sevra-Bench: Social Engineering of Vulnerabilities in Review Agents">
  <meta name="twitter:description" content="A benchmark measuring how often LLM code-review agents approve adversarial pull requests. Frontier vs. open-weight reviewers differ by ~45 points.">
  <meta name="twitter:image" content="static/images/framework_short.png">

  <!-- Academic/Research Specific -->
  <meta name="citation_title" content="Sevra-Bench: Social Engineering of Vulnerabilities in Review Agents">
  <meta name="citation_author" content="Melo, Rui">
  <meta name="citation_author" content="Fogliato, Riccardo">
  <meta name="citation_author" content="Zhou, Sean">
  <meta name="citation_author" content="Thaker, Pratiksha">
  <meta name="citation_author" content="Wu, Zhiwei Steven">
  <meta name="citation_publication_date" content="2026">
  <meta name="citation_pdf_url" content="https://arxiv.org/pdf/2606.13757">
  <meta name="citation_arxiv_id" content="2606.13757">

  <!-- Additional SEO -->
  <meta name="theme-color" content="#2563eb">

  <!-- Preconnect for performance -->
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link rel="preconnect" href="https://cdn.jsdelivr.net">

  <title>Sevra-Bench: Social Engineering of Vulnerabilities in Review Agents</title>

  <!-- Favicon -->
  <link rel="icon" type="image/x-icon" href="static/images/sevra_favicon.png">
  <link rel="apple-touch-icon" href="static/images/sevra_favicon.png">

  <!-- CSS -->
  <link rel="stylesheet" href="static/css/bulma.min.css">
  <link rel="stylesheet" href="static/css/index.css">
  <link rel="preload" href="static/css/fontawesome.all.min.css" as="style" onload="this.onload=null;this.rel='stylesheet'">
  <link rel="preload" href="https://cdn.jsdelivr.net/gh/jpswalsh/academicons@1/css/academicons.min.css" as="style" onload="this.onload=null;this.rel='stylesheet'">
  <noscript>
    <link rel="stylesheet" href="static/css/fontawesome.all.min.css">
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/gh/jpswalsh/academicons@1/css/academicons.min.css">
  </noscript>

  <!-- Fonts -->
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&display=swap" rel="stylesheet">

  <!-- JS (static page only needs fontawesome + copy button; no jQuery/Adobe/chart.js) -->
  <script defer src="static/js/fontawesome.all.min.js"></script>

  <!-- Structured Data -->
  <script type="application/ld+json">
  {
    "@context": "https://schema.org",
    "@type": "ScholarlyArticle",
    "headline": "Sevra-Bench: Social Engineering of Vulnerabilities in Review Agents",
    "description": "A benchmark measuring how often LLM code-review agents approve adversarial pull requests in which the attacker controls both the code diff and the PR narrative.",
    "author": [
      { "@type": "Person", "name": "Rui Melo", "affiliation": { "@type": "Organization", "name": "Carnegie Mellon University" } },
      { "@type": "Person", "name": "Riccardo Fogliato", "affiliation": { "@type": "Organization", "name": "Microsoft Core AI" } },
      { "@type": "Person", "name": "Sean Zhou", "affiliation": { "@type": "Organization", "name": "Amazon" } },
      { "@type": "Person", "name": "Pratiksha Thaker", "affiliation": { "@type": "Organization", "name": "Databricks" } },
      { "@type": "Person", "name": "Zhiwei Steven Wu", "affiliation": { "@type": "Organization", "name": "Carnegie Mellon University" } }
    ],
    "datePublished": "2026",
    "url": "https://arxiv.org/abs/2606.13757",
    "image": "static/images/framework_short.png",
    "keywords": ["LLM code review", "AI security", "malicious pull requests", "social engineering", "CVE", "CWE", "software supply chain"],
    "isAccessibleForFree": true,
    "license": "https://creativecommons.org/licenses/by/4.0/"
  }
  </script>
</head>
```

- [ ] **Step 3: Verify head replacement**

Run:
```bash
cd /Users/rmelo/Documents/GitHub/malicious-pr-bench
grep -c "Sevra-Bench" docs/index.html
grep -c "TODO" docs/index.html
grep -E "jquery|adobe|documentcloud" docs/index.html || echo "NO-JQUERY-ADOBE-OK"
grep -c "</head>" docs/index.html
```
Expected: `Sevra-Bench` count ≥ 6; remaining `TODO` count is whatever the still-untouched body holds (non-zero is fine at this stage); `NO-JQUERY-ADOBE-OK` printed; exactly one `</head>`.

- [ ] **Step 4: Commit**

```bash
cd /Users/rmelo/Documents/GitHub/malicious-pr-bench
git add docs/index.html
git commit -m "docs: real metadata and trimmed includes for landing head

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 3: Rewrite hero + key-stats band + abstract

This task replaces the body from `<main id="main-content">` through the end of the abstract area. It also drops the teaser/carousel/youtube commented-out blocks in that range. The body below the abstract (poster, bibtex, footer, filters, charts, leaderboard) is handled in Tasks 4–7; to keep the file renderable, this task replaces the hero/abstract region and leaves a clear marker comment `<!-- SECTIONS BELOW REPLACED IN LATER TASKS -->` before the still-old content.

**Files:**
- Modify: `docs/index.html` (from `<main id="main-content">` down to just before the old `<!-- Paper poster -->` section)

**Interfaces:**
- Consumes: nothing.
- Produces: `<main id="main-content">` open tag (closed in Task 7), hero `<section class="hero">`, stat-band `<section>`, abstract `<section>`. Defines CSS classes `.stat-band`, `.stat-card`, `.stat-num`, `.stat-label` (styled in Task 7).

- [ ] **Step 1: Anchor the region**

Run: `grep -n 'id="main-content"\|Paper poster\|scroll-to-top' docs/index.html`
Expected: shows the `scroll-to-top` button, the `<main id="main-content">` line, and the `<!-- Paper poster -->` line — these bound the region to replace (replace from `<main id="main-content">` up to but NOT including `<!-- Paper poster -->`). Keep the `scroll-to-top` button as-is above `<main>`.

- [ ] **Step 2: Replace the hero/teaser/abstract region**

Replace everything from `<main id="main-content">` up to (but not including) the line `<!-- Paper poster -->` with:

```html
  <main id="main-content">
  <section class="hero">
    <div class="hero-body">
      <div class="container is-max-desktop">
        <div class="columns is-centered">
          <div class="column has-text-centered">
            <h1 class="title is-1 publication-title">Sevra-Bench</h1>
            <h2 class="subtitle is-4" style="margin-top:-0.5rem;">Social Engineering of Vulnerabilities in Review Agents</h2>
            <p class="is-size-5" style="max-width:760px;margin:0.75rem auto 1.5rem;color:#4a4a4a;">
              Can an automated code reviewer reject a malicious pull request when the attacker
              controls both the code diff <em>and</em> the PR narrative?
            </p>

            <div class="is-size-5 publication-authors">
              <span class="author-block"><a href="mailto:rmelo@cs.cmu.edu">Rui Melo</a><sup>1</sup>,</span>
              <span class="author-block">Riccardo Fogliato<sup>2</sup>,</span>
              <span class="author-block">Sean Zhou<sup>3</sup>,</span>
              <span class="author-block">Pratiksha Thaker<sup>4</sup>,</span>
              <span class="author-block">Zhiwei Steven Wu<sup>1</sup></span>
            </div>
            <div class="is-size-6 publication-authors" style="margin-top:0.5rem;">
              <span class="author-block"><sup>1</sup>Carnegie Mellon University</span>&nbsp;&nbsp;
              <span class="author-block"><sup>2</sup>Microsoft Core AI</span>&nbsp;&nbsp;
              <span class="author-block"><sup>3</sup>Amazon</span>&nbsp;&nbsp;
              <span class="author-block"><sup>4</sup>Databricks</span>
              <br><small>Correspondence: <a href="mailto:rmelo@cs.cmu.edu">rmelo@cs.cmu.edu</a></small>
            </div>

            <div class="column has-text-centered" style="margin-top:1.25rem;">
              <div class="publication-links">
                <span class="link-block">
                  <a href="https://arxiv.org/abs/2606.13757" target="_blank" class="external-link button is-normal is-rounded is-dark">
                    <span class="icon"><i class="fas fa-file-pdf"></i></span><span>Paper</span>
                  </a>
                </span>
                <span class="link-block">
                  <a href="https://github.com/rufimelo99/malicious-pr-bench" target="_blank" class="external-link button is-normal is-rounded is-dark">
                    <span class="icon"><i class="fab fa-github"></i></span><span>Code</span>
                  </a>
                </span>
                <span class="link-block">
                  <a href="https://huggingface.co/datasets/RedAI4Code/SEVRA" target="_blank" class="external-link button is-normal is-rounded is-dark">
                    <span class="icon">🤗</span><span>Dataset</span>
                  </a>
                </span>
                <span class="link-block">
                  <a href="https://arxiv.org/abs/2606.13757" target="_blank" class="external-link button is-normal is-rounded is-dark">
                    <span class="icon"><i class="ai ai-arxiv"></i></span><span>arXiv</span>
                  </a>
                </span>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  </section>

  <!-- Key stats -->
  <section class="section" style="padding-top:1rem;">
    <div class="container is-max-desktop">
      <div class="stat-band">
        <div class="stat-card"><div class="stat-num">2,250</div><div class="stat-label">Malicious PRs</div></div>
        <div class="stat-card"><div class="stat-num">1,062</div><div class="stat-label">Challenge split</div></div>
        <div class="stat-card"><div class="stat-num">347</div><div class="stat-label">Benign fixes</div></div>
        <div class="stat-card"><div class="stat-num">15</div><div class="stat-label">Framings</div></div>
        <div class="stat-card"><div class="stat-num">10</div><div class="stat-label">CWEs (Top 25)</div></div>
        <div class="stat-card"><div class="stat-num">8</div><div class="stat-label">Models</div></div>
      </div>
    </div>
  </section>

  <!-- Abstract -->
  <section class="section hero is-light">
    <div class="container is-max-desktop">
      <div class="columns is-centered has-text-centered">
        <div class="column is-four-fifths">
          <h2 class="title is-3">Abstract</h2>
          <div class="content has-text-justified">
            <p>
              Large language model (LLM) reviewers are increasingly used in pull-request (PR) workflows,
              where their approvals help decide which code is merged into a repository. This raises a
              question that benchmarks for static vulnerability detection or code generation do not address:
              can an automated reviewer reject a malicious contribution when the attacker controls both the
              code change and the accompanying PR text? We introduce <strong>Sevra-Bench</strong>
              (Social Engineering of Vulnerabilities in Review Agents), a benchmark that measures how often an
              automated reviewer approves such adversarial pull requests. Each malicious PR is built from a
              real project commit that previously fixed a vulnerability listed in the CVE database. We
              automatically invert that fix to restore the original vulnerable code and submit it as a pull
              request wrapped in one of 15 social-engineering framings, which vary the claims made, the
              supporting evidence, the urgency conveyed, signals of prior approval, and appeals to authority.
              Sevra-Bench contains 1,062 malicious PRs drawn from CVE-linked fixes across the top 10 entries
              of the 2025 CWE Top 25. In a realistic setting, we evaluate 8 current LLMs as code-review agents
              on PRs that introduce vulnerabilities previously reported in public disclosures. Our results
              reveal a sharp gap in security capabilities between closed- and open-source models. We hope
              Sevra-Bench will serve as a valuable resource for advancing open-source models and narrowing
              this gap.
            </p>
          </div>
        </div>
      </div>
    </div>
  </section>

  <!-- SECTIONS BELOW REPLACED IN LATER TASKS -->
```

- [ ] **Step 3: Verify hero/stats/abstract present and old teaser comments gone**

Run:
```bash
cd /Users/rmelo/Documents/GitHub/malicious-pr-bench
grep -c "stat-card" docs/index.html
grep -c "Riccardo Fogliato" docs/index.html
grep -c "Teaser video" docs/index.html || echo "NO-TEASER-OK"
grep -c "SECTIONS BELOW REPLACED" docs/index.html
```
Expected: `stat-card` count = 6; `Riccardo Fogliato` count = 1; `NO-TEASER-OK` printed (teaser comment removed); marker count = 1.

- [ ] **Step 4: Commit**

```bash
cd /Users/rmelo/Documents/GitHub/malicious-pr-bench
git add docs/index.html
git commit -m "docs: rewrite hero, key-stats band, and abstract

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 4: Add framework overview figure + headline result callout

This task replaces the old `<!-- Paper poster -->` section (the `sample.pdf` iframe) with the framework figure and the headline callout, sitting right after the abstract.

**Files:**
- Modify: `docs/index.html` (the `<!-- Paper poster -->` … `<!--End paper poster -->` section)

**Interfaces:**
- Consumes: `static/images/framework_short.png` from Task 1.
- Produces: figure section + `.headline-callout` block (styled in Task 7).

- [ ] **Step 1: Anchor the poster section**

Run: `grep -n "Paper poster\|End paper poster" docs/index.html`
Expected: shows the start `<!-- Paper poster -->` and end `<!--End paper poster -->` lines bounding the section to replace.

- [ ] **Step 2: Replace the poster section**

Replace from `<!-- Paper poster -->` through `<!--End paper poster -->` (inclusive) with:

```html
  <!-- Framework overview -->
  <section class="section">
    <div class="container is-max-desktop has-text-centered">
      <h2 class="title is-3">How Sevra-Bench Works</h2>
      <figure class="image">
        <img src="static/images/framework_short.png" alt="Sevra-Bench framework overview" loading="lazy" style="max-width:100%;height:auto;">
      </figure>
      <p class="is-size-6 has-text-grey" style="margin-top:0.75rem;max-width:820px;margin-left:auto;margin-right:auto;">
        Each malicious episode reverses a project commit that fixed a CVE-linked vulnerability, then
        presents the resulting pull request under one of 15 social-engineering framings. The reviewer
        agent evaluates the live PR in an isolated Gitea repository through tool calls, and decides
        whether to approve or decline.
      </p>
    </div>
  </section>

  <!-- Headline result -->
  <section class="section" style="padding-top:0;">
    <div class="container is-max-desktop">
      <div class="headline-callout">
        <div class="headline-num">~45 points</div>
        <p>
          The gap in detection ability between frontier and open-weight reviewers is not marginal.
          <strong>Claude Opus 4.7 blocks ~98%</strong> of adversarial PRs on the challenge split, while the
          weakest evaluated reviewer manages only <strong>~36%</strong> — a ~45-percentage-point gulf, with
          open-weight models swinging dramatically depending on how the PR is framed.
        </p>
      </div>
    </div>
  </section>
```

- [ ] **Step 3: Verify**

Run:
```bash
cd /Users/rmelo/Documents/GitHub/malicious-pr-bench
grep -c "framework_short.png" docs/index.html
grep -c "sample.pdf" docs/index.html || echo "NO-SAMPLE-PDF-OK"
grep -c "headline-callout" docs/index.html
```
Expected: `framework_short.png` count = 1; `NO-SAMPLE-PDF-OK` printed (poster iframe gone); `headline-callout` count = 1.

- [ ] **Step 4: Commit**

```bash
cd /Users/rmelo/Documents/GitHub/malicious-pr-bench
git add docs/index.html
git commit -m "docs: add framework overview figure and headline result callout

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 5: Replace the leaderboard with the real 8-model per-CWE results table

This removes the old hardcoded `gpt-5.2`-only "Malicious PR Detection" table, the Filters section, the Charts section + `switchChart` script + its scoped `<style>`, and the duplicate "Last updated" blocks, replacing them with the real results table.

**Files:**
- Modify: `docs/index.html` (from the BibTeX section's predecessor down through the second footer — see anchors)

**Interfaces:**
- Consumes: nothing (static data).
- Produces: `<section>` with `id="results"` containing the color-graded `<table>`. Uses cell classes `.rr-hi` / `.rr-mid` / `.rr-lo` (styled in Task 7).

- [ ] **Step 1: Anchor the regions to delete/replace**

Run: `grep -n 'Filters Section\|Charts Section\|switchChart\|Malicious PR Detection\|id="BibTeX"\|Last updated\|<!-- Footer -->\|leaderboard.js\|chart.js' docs/index.html`
Expected: lists the Filters section, Charts section, the inline `switchChart` script + `<style>`, the "Malicious PR Detection" table, both "Last updated" blocks, the second footer, and the `chart.js`/`leaderboard.js` script tags near `</body>`.

- [ ] **Step 2: Delete the Filters + Charts + switchChart + style + the hardcoded leaderboard table + their "Last updated" block**

Delete the contiguous block that starts at `<!-- Filters Section -->` and ends just before `<!-- Footer -->` (the second footer). This removes: Filters section, Charts section, the `<script>switchChart…</script>`, the `<style>…</style>`, the `<!-- 🔍 Malicious PR Detection Section -->` table, and the `Last updated: 2026-05-07` block.

In its place insert the real results section:

```html
  <!-- Results -->
  <section class="section" id="results">
    <div class="container is-max-desktop">
      <h2 class="title is-3">Results: Refusal Rate by CWE</h2>
      <p class="content">
        Refusal Rate (%) on the retained challenge split — the fraction of malicious PRs each reviewer
        correctly blocked. Higher is better. Models are ordered by overall refusal rate.
        <span class="tag rr-hi">&ge;80</span>
        <span class="tag rr-mid">50&ndash;79</span>
        <span class="tag rr-lo">&lt;50</span>
      </p>
      <div class="table-container">
        <table class="table is-striped is-hoverable is-fullwidth results-table">
          <thead>
            <tr>
              <th>CWE</th>
              <th>Opus&nbsp;4.7</th>
              <th>GPT-5.5</th>
              <th>GLM</th>
              <th>Haiku-4.5</th>
              <th>DeepSeek&nbsp;V4-Flash</th>
              <th>Kimi</th>
              <th>Grok&nbsp;Code&nbsp;Fast</th>
              <th>GPT-5.4-nano</th>
            </tr>
          </thead>
          <tbody>
            <tr><td>CWE-79 — Cross-Site Scripting (XSS)</td><td class="rr-hi">99</td><td class="rr-hi">89</td><td class="rr-hi">80</td><td class="rr-lo">37</td><td class="rr-lo">39</td><td class="rr-lo">47</td><td class="rr-lo">39</td><td class="rr-lo">42</td></tr>
            <tr><td>CWE-89 — SQL Injection</td><td class="rr-hi">100</td><td class="rr-hi">100</td><td class="rr-hi">92</td><td class="rr-hi">85</td><td class="rr-mid">75</td><td class="rr-mid">68</td><td class="rr-lo">45</td><td class="rr-lo">15</td></tr>
            <tr><td>CWE-352 — Cross-Site Request Forgery</td><td class="rr-hi">97</td><td class="rr-hi">89</td><td class="rr-hi">80</td><td class="rr-lo">46</td><td class="rr-lo">45</td><td class="rr-mid">53</td><td class="rr-lo">47</td><td class="rr-lo">36</td></tr>
            <tr><td>CWE-862 — Missing Authorization</td><td class="rr-hi">99</td><td class="rr-hi">98</td><td class="rr-hi">89</td><td class="rr-mid">71</td><td class="rr-mid">62</td><td class="rr-mid">56</td><td class="rr-mid">54</td><td class="rr-lo">28</td></tr>
            <tr><td>CWE-787 — Out-of-bounds Write</td><td class="rr-hi">100</td><td class="rr-hi">100</td><td class="rr-mid">79</td><td class="rr-lo">41</td><td class="rr-lo">49</td><td class="rr-lo">44</td><td class="rr-lo">37</td><td class="rr-mid">51</td></tr>
            <tr><td>CWE-22 — Path Traversal</td><td class="rr-hi">100</td><td class="rr-hi">100</td><td class="rr-hi">92</td><td class="rr-mid">67</td><td class="rr-mid">70</td><td class="rr-mid">63</td><td class="rr-lo">37</td><td class="rr-lo">18</td></tr>
            <tr><td>CWE-416 — Use After Free</td><td class="rr-hi">96</td><td class="rr-hi">93</td><td class="rr-mid">72</td><td class="rr-lo">30</td><td class="rr-lo">37</td><td class="rr-lo">34</td><td class="rr-lo">34</td><td class="rr-lo">49</td></tr>
            <tr><td>CWE-125 — Out-of-bounds Read</td><td class="rr-hi">97</td><td class="rr-hi">99</td><td class="rr-hi">84</td><td class="rr-mid">68</td><td class="rr-mid">62</td><td class="rr-mid">64</td><td class="rr-lo">31</td><td class="rr-lo">33</td></tr>
            <tr><td>CWE-78 — OS Command Injection</td><td class="rr-hi">93</td><td class="rr-hi">92</td><td class="rr-hi">84</td><td class="rr-lo">48</td><td class="rr-mid">50</td><td class="rr-lo">47</td><td class="rr-lo">14</td><td class="rr-lo">28</td></tr>
            <tr><td>CWE-94 — Code Injection</td><td class="rr-hi">99</td><td class="rr-hi">97</td><td class="rr-hi">81</td><td class="rr-mid">57</td><td class="rr-mid">50</td><td class="rr-mid">59</td><td class="rr-mid">51</td><td class="rr-lo">46</td></tr>
            <tr class="overall-row"><td><strong>Overall Average</strong></td><td class="rr-hi"><strong>98</strong></td><td class="rr-hi"><strong>95</strong></td><td class="rr-hi"><strong>83</strong></td><td class="rr-mid"><strong>53</strong></td><td class="rr-mid"><strong>53</strong></td><td class="rr-mid"><strong>52</strong></td><td class="rr-lo"><strong>39</strong></td><td class="rr-lo"><strong>36</strong></td></tr>
          </tbody>
        </table>
      </div>
    </div>
  </section>
```

- [ ] **Step 3: Verify removals and additions**

Run:
```bash
cd /Users/rmelo/Documents/GitHub/malicious-pr-bench
grep -E "switchChart|model-filter|timeSeriesChart|gpt-5.2|Malicious PR Detection|Score Over Time" docs/index.html || echo "DYNAMIC-REMOVED-OK"
grep -c 'id="results"' docs/index.html
grep -c "Cross-Site Scripting" docs/index.html
grep -c "Overall Average" docs/index.html
```
Expected: `DYNAMIC-REMOVED-OK` printed; `id="results"` = 1; `Cross-Site Scripting` = 1; `Overall Average` = 1.

- [ ] **Step 4: Commit**

```bash
cd /Users/rmelo/Documents/GitHub/malicious-pr-bench
git add docs/index.html
git commit -m "docs: replace dynamic charts/leaderboard with static 8-model per-CWE results

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 6: Add framing-analysis section + fix BibTeX + remove dead script tags

**Files:**
- Modify: `docs/index.html` (BibTeX section content; insert framing section before BibTeX; remove `chart.js`/`leaderboard.js` script tags before `</body>`)

**Interfaces:**
- Consumes: `static/images/framing_effectiveness.png` from Task 1.
- Produces: framing `<section>` and corrected `#bibtex-code` content. Relies on `copyBibTeX()` from `static/js/index.js` (existing) — verify it exists; if not, the inline button still degrades gracefully.

- [ ] **Step 1: Verify the copy handler and anchor BibTeX**

Run:
```bash
cd /Users/rmelo/Documents/GitHub/malicious-pr-bench
grep -rn "function copyBibTeX" docs/static/js/index.js || echo "NO-COPY-HANDLER"
grep -n 'id="BibTeX"\|YourPaperKey2024\|chart.js\|leaderboard.js' docs/index.html
```
Expected: shows whether `copyBibTeX` exists in `index.js`, and the BibTeX section + the two dead script tags near `</body>`.

- [ ] **Step 2: Insert the framing section immediately before `<!--BibTex citation -->`**

Insert before the `<!--BibTex citation -->` line:

```html
  <!-- Framing analysis -->
  <section class="section hero is-light">
    <div class="container is-max-desktop">
      <h2 class="title is-3">It's Not Just the Code — It's the Story</h2>
      <div class="content">
        <p>
          Sevra-Bench holds the vulnerable diff fixed and varies only the PR narrative across 15
          social-engineering framings. Frontier reviewers stay robust regardless of the story:
          <strong>Claude Opus 4.7 blocks 84–100%</strong> and <strong>GPT-5.5 75–100%</strong> across every framing.
          Open-weight reviewers are far more susceptible — DeepSeek V4-Flash blocks 100% of PRs that appeal to
          authority but only 18% of PRs claiming prior approval, an 82-point swing driven purely by how the
          same change is described.
        </p>
      </div>
      <figure class="image has-text-centered">
        <img src="static/images/framing_effectiveness.png" alt="Effect of framing strategy on refusal rate by model" loading="lazy" style="max-width:100%;height:auto;">
      </figure>
    </div>
  </section>

```

- [ ] **Step 3: Replace the BibTeX `<code>` body**

Replace the existing `@article{YourPaperKey2024, … }` block inside `<pre id="bibtex-code"><code>…</code></pre>` with:

```html
<pre id="bibtex-code"><code>@article{melo2026sevra,
  title   = {Sevra-Bench: Social Engineering of Vulnerabilities in Review Agents},
  author  = {Melo, Rui and Fogliato, Riccardo and Zhou, Sean and Thaker, Pratiksha and Wu, Zhiwei Steven},
  journal = {arXiv preprint arXiv:2606.13757},
  year    = {2026},
  url     = {https://arxiv.org/abs/2606.13757}
}</code></pre>
```

- [ ] **Step 4: Remove the dead `chart.js` and `leaderboard.js` script tags**

Remove these two lines near the end of the file:

```html
  <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
  <script src="leaderboard.js"></script>
```

- [ ] **Step 5: Verify**

Run:
```bash
cd /Users/rmelo/Documents/GitHub/malicious-pr-bench
grep -c "framing_effectiveness.png" docs/index.html
grep -c "melo2026sevra" docs/index.html
grep -E "chart.js|leaderboard.js|YourPaperKey2024" docs/index.html || echo "DEAD-SCRIPTS-REMOVED-OK"
```
Expected: `framing_effectiveness.png` = 1; `melo2026sevra` = 1; `DEAD-SCRIPTS-REMOVED-OK` printed.

- [ ] **Step 6: Commit**

```bash
cd /Users/rmelo/Documents/GitHub/malicious-pr-bench
git add docs/index.html
git commit -m "docs: add framing analysis, real BibTeX, remove dead scripts

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 7: Add scoped styles, dedupe footer, final verification

This task adds the scoped CSS (stat cards, headline callout, results cell colors), ensures exactly one footer + one `</main>` + valid tag balance, and runs the visual verification.

**Files:**
- Modify: `docs/index.html` (append a scoped `<style>` in `<head>` region or just before `</body>`; ensure single footer; close `</main>`)

**Interfaces:**
- Consumes: classes from Tasks 3–5 (`.stat-band`, `.stat-card`, `.stat-num`, `.stat-label`, `.headline-callout`, `.headline-num`, `.rr-hi`, `.rr-mid`, `.rr-lo`, `.results-table`, `.overall-row`).

- [ ] **Step 1: Confirm there is exactly one footer and one closing `</main>`**

Run:
```bash
cd /Users/rmelo/Documents/GitHub/malicious-pr-bench
grep -c "<footer" docs/index.html
grep -c "</main>" docs/index.html
grep -n "This page was built using" docs/index.html
```
Expected: ideally one `<footer>`. If two remain, delete the first (the one that appeared right after the old abstract/BibTeX duplication) keeping the final centered footer. Ensure exactly one `</main>` exists; if zero, add `</main>` just before the final `<footer`.

- [ ] **Step 2: Insert the scoped style block just before `</body>`**

Insert before `</body>`:

```html
  <style>
    .stat-band { display:flex; flex-wrap:wrap; gap:1rem; justify-content:center; }
    .stat-card { flex:1 1 140px; max-width:200px; border:1px solid #e5e5e5; border-radius:10px;
                 padding:1rem 0.75rem; text-align:center; background:#fff; }
    .stat-num { font-size:1.9rem; font-weight:800; color:#2563eb; line-height:1.1; }
    .stat-label { font-size:0.85rem; color:#6b6b6b; margin-top:0.25rem; }
    .headline-callout { border-left:5px solid #2563eb; background:#f5f8ff; border-radius:8px;
                        padding:1.25rem 1.5rem; display:flex; gap:1.25rem; align-items:center; flex-wrap:wrap; }
    .headline-num { font-size:2rem; font-weight:800; color:#2563eb; white-space:nowrap; }
    .headline-callout p { margin:0; flex:1 1 320px; }
    .results-table td, .results-table th { text-align:center; vertical-align:middle; }
    .results-table td:first-child, .results-table th:first-child { text-align:left; }
    .results-table .overall-row td { border-top:2px solid #b5b5b5; }
    .rr-hi  { background:#e8f6ec !important; color:#1f7a3d; font-weight:600; }
    .rr-mid { background:#fdf6e3 !important; color:#9a6b00; font-weight:600; }
    .rr-lo  { background:#fde8e8 !important; color:#b3261e; font-weight:600; }
    span.tag.rr-hi { color:#1f7a3d; } span.tag.rr-mid { color:#9a6b00; } span.tag.rr-lo { color:#b3261e; }
  </style>
```

- [ ] **Step 3: Validate structural integrity (no leftover placeholders, balanced major tags)**

Run:
```bash
cd /Users/rmelo/Documents/GitHub/malicious-pr-bench
grep -E "TODO|Lorem ipsum|YourPaperKey|sample.pdf|First Author|Academic Project Page" docs/index.html || echo "NO-PLACEHOLDERS-OK"
python3 -c "import re,sys; s=open('docs/index.html').read(); print('sections', s.count('<section'), s.count('</section>')); print('main', s.count('<main'), s.count('</main>')); print('footer', s.count('<footer'))"
```
Expected: `NO-PLACEHOLDERS-OK` printed; `<section>`/`</section>` counts equal; `<main>`/`</main>` both = 1; `<footer>` = 1.

- [ ] **Step 4: Serve and screenshot for visual verification**

Run:
```bash
cd /Users/rmelo/Documents/GitHub/malicious-pr-bench/docs
(python3 -m http.server 8766 >/tmp/prbench_verify.log 2>&1 &) ; sleep 1
curl -s -o /dev/null -w "http %{http_code}\n" http://localhost:8766/index.html
CHROME="/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
"$CHROME" --headless --disable-gpu --hide-scrollbars --window-size=1280,3600 \
  --screenshot=/tmp/prbench_new.png http://localhost:8766/index.html >/dev/null 2>&1 && echo "screenshot ok"
```
Expected: `http 200` and `screenshot ok`. Then open `/tmp/prbench_new.png` and confirm visually: hero shows "Sevra-Bench" + 5 authors + Paper/Code/Dataset/arXiv buttons; 6 stat cards; abstract; framework image renders; headline callout; full 8-model results table with green/amber/red cells; framing figure renders; correct BibTeX; one footer; no Filters/Charts/Poster.

- [ ] **Step 5: Check for console/network 404s on removed assets**

Run:
```bash
cd /Users/rmelo/Documents/GitHub/malicious-pr-bench/docs
for u in index.html static/images/framework_short.png static/images/framing_effectiveness.png static/css/index.css static/css/bulma.min.css; do
  printf "%s -> " "$u"; curl -s -o /dev/null -w "%{http_code}\n" "http://localhost:8766/$u"; done
```
Expected: every line ends in `200`.

- [ ] **Step 6: Stop the server and commit**

```bash
cd /Users/rmelo/Documents/GitHub/malicious-pr-bench
pkill -f "http.server 8766" 2>/dev/null
git add docs/index.html
git commit -m "docs: scoped styles, dedupe footer, finalize Sevra-Bench landing page

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Self-Review Notes

- **Spec coverage:** hero+links (Task 3), stats band (Task 3), abstract (Task 3), framework figure (Tasks 1+4), headline callout (Task 4), 8-model results table (Task 5), framing analysis (Tasks 1+6), BibTeX (Task 6), SEO/meta (Task 2), removals of filters/charts/poster/leaderboard/dead scripts (Tasks 2,4,5,6), styling+footer dedupe (Task 7), figure conversion (Task 1), verification (Task 7). All spec sections mapped.
- **Class consistency:** `.stat-band/.stat-card/.stat-num/.stat-label` (Task 3 → styled Task 7); `.headline-callout/.headline-num` (Task 4 → Task 7); `.rr-hi/.rr-mid/.rr-lo/.results-table/.overall-row` (Task 5 → Task 7) — names match across tasks.
- **Removed-asset references:** `leaderboard.js`/`chart.js` removed in Task 6; `jquery`/Adobe removed in Task 2; `sample.pdf` removed in Task 4. Verified via grep gates.
- **Note for executor:** `bulma-carousel`/`bulma-slider` CSS/JS were dropped from `<head>` in Task 2 along with the carousels; this is intentional and nothing remaining uses them.
