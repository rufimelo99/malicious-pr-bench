(() => {
  const state = {
    zip: null,
    header: null,
    summaries: [],
    filteredSummaries: [],
    sampleFiles: [],
    samplePathById: new Map(),
    sampleCache: new Map(),
    sortKey: 'id',
    sortDirection: 'asc',
    filters: {
      detection: 'all',
      security: 'all',
      axis1: 'all',
      axis2: 'all',
      axis3: 'all',
      search: '',
    },
    currentDetailId: null,
    detailRequestToken: 0,
  };

  const elements = {
    fileInput: document.getElementById('file-input'),
    dropZone: document.getElementById('drop-zone'),
    runBanner: document.getElementById('run-banner'),
    dashboard: document.getElementById('dashboard'),
    statsBar: document.getElementById('stats-bar'),
    globalStatus: document.getElementById('global-status'),
    statusMessage: document.getElementById('status-message'),
    filterCount: document.getElementById('filter-count'),
    samplesBody: document.getElementById('samples-body'),
    detailModal: document.getElementById('detail-modal'),
    detailBackdrop: document.getElementById('detail-backdrop'),
    detailClose: document.getElementById('detail-close'),
    detailPrev: document.getElementById('detail-prev'),
    detailNext: document.getElementById('detail-next'),
    detailCounter: document.getElementById('detail-counter'),
    detailTitle: document.getElementById('detail-title'),
    detailContent: document.getElementById('detail-content'),
    themeToggle: document.getElementById('theme-toggle'),
    themeIconSun: document.getElementById('theme-icon-sun'),
    themeIconMoon: document.getElementById('theme-icon-moon'),
    filters: {
      detection: document.getElementById('filter-detection'),
      security: document.getElementById('filter-security'),
      axis1: document.getElementById('filter-axis1'),
      axis2: document.getElementById('filter-axis2'),
      axis3: document.getElementById('filter-axis3'),
      search: document.getElementById('filter-search'),
    },
    headers: Array.from(document.querySelectorAll('th[data-sort-key]')),
  };

  const SORT_KEYS = {
    id: (item) => item.id || '',
    repo: (item) => item.repo || '',
    prNumber: (item) => Number.isFinite(item.prNumber) ? item.prNumber : Number.POSITIVE_INFINITY,
    axis1: (item) => item.axis1 || '',
    axis2: (item) => item.axis2 || '',
    axis3: (item) => item.axis3 || '',
    detectionSort: (item) => item.detection.sortValue,
    securitySort: (item) => item.security.sortValue,
    decision: (item) => item.decision || '',
    duration: (item) => Number.isFinite(item.duration) ? item.duration : Number.POSITIVE_INFINITY,
  };

  init();

  function init() {
    if (!window.JSZip) {
      setStatus('JSZip failed to load. Check viewer/lib/jszip.min.js.', true);
      return;
    }

    elements.fileInput.addEventListener('change', (event) => {
      const [file] = event.target.files || [];
      if (file) {
        loadEvalFile(file);
      }
    });

    ['dragenter', 'dragover'].forEach((eventName) => {
      elements.dropZone.addEventListener(eventName, (event) => {
        event.preventDefault();
        elements.dropZone.classList.add('dragover');
      });
    });

    ['dragleave', 'dragend', 'drop'].forEach((eventName) => {
      elements.dropZone.addEventListener(eventName, (event) => {
        event.preventDefault();
        elements.dropZone.classList.remove('dragover');
      });
    });

    elements.dropZone.addEventListener('drop', (event) => {
      const [file] = event.dataTransfer?.files || [];
      if (file) {
        loadEvalFile(file);
      }
    });

    elements.dropZone.addEventListener('click', () => elements.fileInput.click());
    elements.dropZone.addEventListener('keydown', (event) => {
      if (event.key === 'Enter' || event.key === ' ') {
        event.preventDefault();
        elements.fileInput.click();
      }
    });

    Object.entries(elements.filters).forEach(([key, element]) => {
      const eventName = key === 'search' ? 'input' : 'change';
      element.addEventListener(eventName, () => {
        state.filters[key] = element.value.trim();
        applyFiltersAndRender();
      });
    });

    elements.headers.forEach((header) => {
      header.classList.add('sortable');
      header.tabIndex = 0;
      const toggleSort = () => {
        const key = header.dataset.sortKey;
        if (!key) return;
        if (state.sortKey === key) {
          state.sortDirection = state.sortDirection === 'asc' ? 'desc' : 'asc';
        } else {
          state.sortKey = key;
          state.sortDirection = 'asc';
        }
        updateSortIndicators();
        renderTable();
      };
      header.addEventListener('click', toggleSort);
      header.addEventListener('keydown', (event) => {
        if (event.key === 'Enter' || event.key === ' ') {
          event.preventDefault();
          toggleSort();
        }
      });
    });
    updateSortIndicators();

    elements.detailClose.addEventListener('click', closeDetailModal);
    elements.detailBackdrop.addEventListener('click', closeDetailModal);
    elements.detailPrev.addEventListener('click', () => navigateDetail(-1));
    elements.detailNext.addEventListener('click', () => navigateDetail(1));
    document.addEventListener('keydown', (event) => {
      if (elements.detailModal.classList.contains('hidden')) return;
      if (event.key === 'Escape') {
        closeDetailModal();
      } else if (event.key === 'ArrowLeft') {
        navigateDetail(-1);
      } else if (event.key === 'ArrowRight') {
        navigateDetail(1);
      }
    });

    initThemeToggle();
  }

  function initThemeToggle() {
    function updateIcons() {
      const isDark = document.documentElement.classList.contains('dark');
      elements.themeIconSun.style.display = isDark ? 'block' : 'none';
      elements.themeIconMoon.style.display = isDark ? 'none' : 'block';
    }

    elements.themeToggle.addEventListener('click', () => {
      const isDark = document.documentElement.classList.toggle('dark');
      try { localStorage.setItem('theme', isDark ? 'dark' : 'light'); } catch (e) {}
      updateIcons();
    });

    updateIcons();
  }

  function getSortedItems() {
    return [...state.filteredSummaries].sort(compareSummaries);
  }

  function navigateDetail(delta) {
    const items = getSortedItems();
    const currentIdx = items.findIndex((item) => item.id === state.currentDetailId);
    if (currentIdx < 0) return;
    const newIndex = currentIdx + delta;
    if (newIndex < 0 || newIndex >= items.length) return;
    openSampleDetail(items[newIndex]);
  }

  function updateDetailNav() {
    const items = getSortedItems();
    const idx = items.findIndex((item) => item.id === state.currentDetailId);
    const total = items.length;
    elements.detailPrev.disabled = idx <= 0;
    elements.detailNext.disabled = idx >= total - 1;
    elements.detailCounter.textContent = total > 0 && idx >= 0 ? `${idx + 1} / ${total}` : '— / —';
  }

  async function loadEvalFile(file) {
    resetViewer();
    setStatus(`Loading ${file.name}...`);

    try {
      const arrayBuffer = await file.arrayBuffer();
      const zip = await JSZip.loadAsync(arrayBuffer);
      const sampleFiles = Object.keys(zip.files)
        .filter((name) => name.startsWith('samples/') && name.endsWith('.json'))
        .sort((a, b) => a.localeCompare(b, undefined, { numeric: true }));

      if (!zip.file('header.json')) {
        throw new Error('header.json is missing from this archive.');
      }
      if (sampleFiles.length === 0) {
        throw new Error('No samples/*.json entries found in this archive.');
      }

      state.zip = zip;
      state.sampleFiles = sampleFiles;
      state.header = await parseJsonEntry('header.json');

      const summariesFile = zip.file('summaries.json');
      if (summariesFile) {
        setStatus('Reading summaries.json...');
        const summaries = await parseJsonEntry('summaries.json');
        if (!Array.isArray(summaries)) {
          throw new Error('summaries.json must contain an array.');
        }
        state.summaries = summaries.map((summary, index) => normalizeSummary(summary, index, sampleFiles[index] || null));
      } else {
        setStatus('summaries.json missing; scanning sample files...');
        state.summaries = await buildSummariesFromSamples(sampleFiles);
      }

      if (!state.summaries.length) {
        throw new Error('No sample summaries were loaded.');
      }

      populateFilters();
      renderRunBanner(file.name);
      renderStatsBar();
      elements.dashboard.classList.remove('hidden');
      elements.runBanner.classList.remove('hidden');
      applyFiltersAndRender();
      setStatus(`Loaded ${state.summaries.length} samples from ${file.name}.`);
    } catch (error) {
      console.error(error);
      setStatus(error.message || 'Failed to load .eval file.', true);
    }
  }

  async function buildSummariesFromSamples(sampleFiles) {
    const summaries = [];
    for (let index = 0; index < sampleFiles.length; index += 1) {
      if (index % 25 === 0 || index === sampleFiles.length - 1) {
        setStatus(`Scanning samples... ${index + 1}/${sampleFiles.length}`);
      }
      const sample = await parseJsonEntry(sampleFiles[index]);
      const normalized = normalizeSummary(sample, index, sampleFiles[index]);
      summaries.push(normalized);
      if (normalized.id) {
        state.samplePathById.set(normalized.id, sampleFiles[index]);
      }
      state.sampleCache.set(normalized.id, sample);
    }
    return summaries;
  }

  function resetViewer() {
    state.zip = null;
    state.header = null;
    state.summaries = [];
    state.filteredSummaries = [];
    state.sampleFiles = [];
    state.samplePathById = new Map();
    state.sampleCache = new Map();
    state.sortKey = 'id';
    state.sortDirection = 'asc';
    state.currentDetailId = null;
    state.detailRequestToken = 0;
    state.filters = {
      detection: 'all',
      security: 'all',
      axis1: 'all',
      axis2: 'all',
      axis3: 'all',
      search: '',
    };
    Object.entries(elements.filters).forEach(([key, element]) => {
      element.value = key === 'search' ? '' : 'all';
    });
    closeDetailModal();
    updateSortIndicators();
    elements.runBanner.classList.add('hidden');
    elements.dashboard.classList.add('hidden');
    elements.samplesBody.replaceChildren(createEmptyRow('No log loaded', 'Drop a .eval file or use the file picker to get started'));
    elements.statsBar.replaceChildren();
  }

  async function parseJsonEntry(path) {
    const file = state.zip.file(path);
    if (!file) {
      throw new Error(`Archive entry not found: ${path}`);
    }
    const text = await file.async('string');
    return JSON.parse(text);
  }

  function normalizeSummary(source, index, samplePath) {
    const metadata = source?.metadata || {};
    const scores = source?.scores || {};
    const cliReview = Array.isArray(metadata.cli_reviews) ? metadata.cli_reviews[0] || {} : {};
    const detection = normalizeScore(scores.detection_scorer);
    const security = normalizeScore(scores.security_reason_scorer, true);
    const runStatus = valueOrEmpty(metadata.cli_run_status) || valueOrEmpty(cliReview.run_status);
    const decision = inferDecision(source, metadata, cliReview);
    const duration = toFiniteNumber(cliReview.duration_seconds)
      ?? toFiniteNumber(metadata.duration_seconds)
      ?? toFiniteNumber(source?.total_time)
      ?? toFiniteNumber(source?.execution_time);
    const reasonParts = [
      valueOrEmpty(metadata.cli_reason),
      valueOrEmpty(cliReview.reason),
      valueOrEmpty(detection.explanation),
      valueOrEmpty(security.explanation),
    ].filter(Boolean);

    const normalized = {
      index,
      id: valueOrEmpty(source?.id) || `sample-${index + 1}`,
      repo: valueOrEmpty(metadata.repo),
      prNumber: toFiniteNumber(metadata.pr_number),
      axis1: valueOrEmpty(metadata.axis1),
      axis2: valueOrEmpty(metadata.axis2),
      axis3: valueOrEmpty(metadata.axis3),
      detection,
      security,
      decision,
      duration,
      runStatus,
      reasonsText: reasonParts.join(' '),
      samplePath,
    };

    if (normalized.id && samplePath) {
      state.samplePathById.set(normalized.id, samplePath);
    }

    return normalized;
  }

  function normalizeScore(score, allowNa = false) {
    const answer = valueOrEmpty(score?.answer);
    const explanation = valueOrEmpty(score?.explanation);
    const rawValue = score?.value;

    if (rawValue === undefined || rawValue === null || rawValue === '') {
      return {
        kind: allowNa ? 'na' : 'missing',
        pass: null,
        label: allowNa ? '➖ n/a' : '⚠️ missing',
        pillClass: allowNa ? 'pill-muted' : 'pill-warning',
        sortValue: allowNa ? 2 : 3,
        explanation,
        answer,
      };
    }

    const normalizedValue = typeof rawValue === 'number'
      ? rawValue
      : String(rawValue).trim().toUpperCase();

    const pass = normalizedValue === 1 || normalizedValue === '1' || normalizedValue === '1.0' || normalizedValue === 'C';
    const fail = normalizedValue === 0 || normalizedValue === '0' || normalizedValue === '0.0' || normalizedValue === 'I';

    if (!pass && !fail) {
      return {
        kind: allowNa ? 'na' : 'missing',
        pass: null,
        label: allowNa ? '➖ n/a' : '⚠️ missing',
        pillClass: allowNa ? 'pill-muted' : 'pill-warning',
        sortValue: allowNa ? 2 : 3,
        explanation,
        answer,
      };
    }

    return {
      kind: pass ? 'pass' : 'fail',
      pass,
      label: pass ? '✅ pass' : '❌ fail',
      pillClass: pass ? 'pill-success' : 'pill-danger',
      sortValue: pass ? 0 : 1,
      explanation,
      answer,
    };
  }

  function inferDecision(sample, metadata, cliReview) {
    const direct = valueOrEmpty(metadata.cli_decision) || valueOrEmpty(cliReview.decision);
    if (direct) {
      return direct;
    }

    const assistantMessages = Array.isArray(sample?.messages)
      ? sample.messages.filter((message) => message?.role === 'assistant')
      : [];

    for (let index = assistantMessages.length - 1; index >= 0; index -= 1) {
      const text = normalizeContent(assistantMessages[index]?.content);
      if (!text) continue;
      const decisionMatch = text.match(/decision\s*[:=]\s*(approve|decline|error)/i);
      if (decisionMatch) {
        return decisionMatch[1].toLowerCase();
      }
      const jsonMatch = text.match(/"decision"\s*:\s*"(approve|decline|error)"/i);
      if (jsonMatch) {
        return jsonMatch[1].toLowerCase();
      }
    }

    return '';
  }

  function renderRunBanner(fileName) {
    const header = state.header || {};
    const total = state.summaries.length;
    const items = [
      ['File', fileName],
      ['Model', pickValue(header, ['eval.model', 'model', 'spec.model']) || '—'],
      ['Task', pickValue(header, ['eval.task', 'task', 'eval.task_id', 'spec.task']) || '—'],
      ['Timestamp', formatDate(pickValue(header, ['started_at', 'created_at', 'eval.created_at', 'stats.started_at'])) || '—'],
      ['Samples', String(total)],
    ];

    elements.runBanner.replaceChildren(...items.map(([label, value]) => {
      const item = document.createElement('div');
      item.className = 'run-item';
      const span = document.createElement('span');
      span.textContent = label;
      const strong = document.createElement('strong');
      strong.textContent = value;
      item.append(span, strong);
      return item;
    }));
  }

  function renderStatsBar() {
    const total = state.summaries.length;
    const detectionPasses = state.summaries.filter((item) => item.detection.pass === true).length;
    const detectionEvaluated = state.summaries.filter((item) => item.detection.pass !== null).length;
    const securityPasses = state.summaries.filter((item) => item.security.pass === true).length;
    const securityEvaluated = state.summaries.filter((item) => item.security.pass !== null).length;
    const errorCount = state.summaries.filter(isErrorSummary).length;

    const stats = [
      ['Total samples', String(total), 'All loaded samples'],
      ['Detection accuracy', `${detectionPasses}/${detectionEvaluated} (${formatPercent(detectionPasses, detectionEvaluated)})`, 'Blocked malicious PRs'],
      ['Security reason accuracy', `${securityPasses}/${securityEvaluated} (${formatPercent(securityPasses, securityEvaluated)})`, 'Correct rationale when scored'],
      ['Error count', String(errorCount), 'Runs missing a usable verdict'],
    ];

    elements.statsBar.replaceChildren(...stats.map(([label, value, hint]) => {
      const card = document.createElement('div');
      card.className = 'stat-card';
      const title = document.createElement('span');
      title.className = 'muted';
      title.textContent = label;
      const strong = document.createElement('strong');
      strong.textContent = value;
      const detail = document.createElement('span');
      detail.className = 'muted';
      detail.textContent = hint;
      card.append(title, strong, detail);
      return card;
    }));
  }

  function populateFilters() {
    populateSelect(elements.filters.detection, [
      ['all', 'All detection outcomes'],
      ['pass', 'Blocked / pass'],
      ['fail', 'Fooled / fail'],
      ['error', 'Error / missing'],
    ]);
    populateSelect(elements.filters.security, [
      ['all', 'All security reason outcomes'],
      ['pass', 'Pass'],
      ['fail', 'Fail'],
      ['na', 'N/A or missing'],
    ]);
    populateSelect(elements.filters.axis1, buildAxisOptions('axis1', 'All axis 1'));
    populateSelect(elements.filters.axis2, buildAxisOptions('axis2', 'All axis 2'));
    populateSelect(elements.filters.axis3, buildAxisOptions('axis3', 'All axis 3'));
    elements.filters.search.value = '';
  }

  function buildAxisOptions(key, label) {
    const values = Array.from(new Set(state.summaries.map((item) => item[key]).filter(Boolean)))
      .sort((a, b) => a.localeCompare(b));
    return [['all', label], ...values.map((value) => [value, value])];
  }

  function populateSelect(select, options) {
    select.replaceChildren(...options.map(([value, label]) => {
      const option = document.createElement('option');
      option.value = value;
      option.textContent = label;
      return option;
    }));
    select.value = 'all';
  }

  function applyFiltersAndRender() {
    const searchTerm = state.filters.search.toLowerCase();
    state.filteredSummaries = state.summaries.filter((item) => {
      if (state.filters.detection !== 'all') {
        if (state.filters.detection === 'error' && !(isErrorSummary(item) || item.detection.kind === 'missing')) {
          return false;
        }
        if (state.filters.detection === 'pass' && item.detection.pass !== true) {
          return false;
        }
        if (state.filters.detection === 'fail' && item.detection.pass !== false) {
          return false;
        }
      }

      if (state.filters.security !== 'all') {
        if (state.filters.security === 'pass' && item.security.pass !== true) {
          return false;
        }
        if (state.filters.security === 'fail' && item.security.pass !== false) {
          return false;
        }
        if (state.filters.security === 'na' && item.security.pass !== null) {
          return false;
        }
      }

      if (state.filters.axis1 !== 'all' && item.axis1 !== state.filters.axis1) return false;
      if (state.filters.axis2 !== 'all' && item.axis2 !== state.filters.axis2) return false;
      if (state.filters.axis3 !== 'all' && item.axis3 !== state.filters.axis3) return false;

      if (searchTerm) {
        const haystack = `${item.id} ${item.reasonsText}`.toLowerCase();
        if (!haystack.includes(searchTerm)) {
          return false;
        }
      }

      return true;
    });

    elements.filterCount.textContent = `Showing ${state.filteredSummaries.length} of ${state.summaries.length} samples`;
    renderTable();
  }

  function renderTable() {
    const items = [...state.filteredSummaries].sort(compareSummaries);
    if (!items.length) {
      elements.samplesBody.replaceChildren(createEmptyRow('No matches', 'Try adjusting filters or search terms'));
      return;
    }

    const rows = items.map((item) => {
      const row = document.createElement('tr');
      row.className = `sample-row ${rowClassName(item)}`.trim();
      row.addEventListener('click', () => openSampleDetail(item));

      row.append(
        createTextCell(item.id, true),
        createTextCell(item.repo || '—'),
        createTextCell(Number.isFinite(item.prNumber) ? String(item.prNumber) : '—'),
        createTextCell(item.axis1 || '—'),
        createTextCell(item.axis2 || '—'),
        createTextCell(item.axis3 || '—'),
        createPillCell(detectionCellLabel(item)),
        createPillCell([item.security.label, item.security.pillClass]),
        createTextCell(item.decision || '—'),
        createTextCell(Number.isFinite(item.duration) ? `${item.duration.toFixed(1)}s` : '—')
      );
      return row;
    });

    elements.samplesBody.replaceChildren(...rows);
  }

  function detectionCellLabel(item) {
    if (isErrorSummary(item)) {
      return ['⚠️ error', 'pill-warning'];
    }
    if (item.detection.pass === true) {
      return ['✅ blocked', 'pill-success'];
    }
    if (item.detection.pass === false) {
      return ['❌ fooled', 'pill-danger'];
    }
    return ['⚠️ missing', 'pill-warning'];
  }

  function compareSummaries(a, b) {
    const getter = SORT_KEYS[state.sortKey] || SORT_KEYS.id;
    const first = getter(a);
    const second = getter(b);

    let result = 0;
    if (typeof first === 'number' && typeof second === 'number') {
      result = first - second;
    } else {
      result = String(first).localeCompare(String(second), undefined, { numeric: true, sensitivity: 'base' });
    }

    if (result === 0) {
      result = String(a.id).localeCompare(String(b.id), undefined, { numeric: true, sensitivity: 'base' });
    }
    return state.sortDirection === 'asc' ? result : -result;
  }

  function updateSortIndicators() {
    elements.headers.forEach((header) => {
      header.classList.remove('sort-asc', 'sort-desc');
      if (header.dataset.sortKey === state.sortKey) {
        header.classList.add(state.sortDirection === 'asc' ? 'sort-asc' : 'sort-desc');
      }
    });
  }

  async function openSampleDetail(summary) {
    state.currentDetailId = summary.id;
    state.detailRequestToken += 1;
    const requestToken = state.detailRequestToken;

    elements.detailTitle.textContent = summary.id;
    const loadingWrap = document.createElement('div');
    loadingWrap.className = 'detail-loading';
    loadingWrap.appendChild(createMutedParagraph('Loading full sample...'));
    elements.detailContent.replaceChildren(loadingWrap);
    elements.detailModal.classList.remove('hidden');
    elements.detailModal.setAttribute('aria-hidden', 'false');
    document.body.style.overflow = 'hidden';
    updateDetailNav();

    try {
      const sample = await loadSample(summary);
      if (state.detailRequestToken !== requestToken) return;
      renderDetail(sample, summary);
    } catch (error) {
      if (state.detailRequestToken !== requestToken) return;
      console.error(error);
      const errorWrap = document.createElement('div');
      errorWrap.className = 'detail-loading';
      errorWrap.appendChild(createMutedParagraph(error.message || 'Failed to load sample.'));
      elements.detailContent.replaceChildren(errorWrap);
    }
  }

  function closeDetailModal() {
    elements.detailModal.classList.add('hidden');
    elements.detailModal.setAttribute('aria-hidden', 'true');
    document.body.style.overflow = '';
    state.currentDetailId = null;
  }

  async function loadSample(summary) {
    if (state.sampleCache.has(summary.id)) {
      return state.sampleCache.get(summary.id);
    }

    const directPath = state.samplePathById.get(summary.id) || summary.samplePath;
    if (directPath) {
      try {
        const sample = await parseJsonEntry(directPath);
        if (valueOrEmpty(sample?.id) === summary.id || !summary.id) {
          state.sampleCache.set(summary.id, sample);
          state.samplePathById.set(summary.id, directPath);
          return sample;
        }
      } catch (error) {
        console.warn('Direct sample load failed, falling back to scan.', error);
      }
    }

    for (const path of state.sampleFiles) {
      const sample = await parseJsonEntry(path);
      const sampleId = valueOrEmpty(sample?.id);
      if (sampleId) {
        state.samplePathById.set(sampleId, path);
      }
      if (sampleId === summary.id) {
        state.sampleCache.set(summary.id, sample);
        return sample;
      }
    }

    throw new Error(`Could not locate sample JSON for ${summary.id}.`);
  }

  function renderDetail(sample, summary) {
    const metadata = sample?.metadata || {};
    const scores = sample?.scores || {};
    const cliReviews = Array.isArray(metadata.cli_reviews) ? metadata.cli_reviews : [];
    const concerns = cliReviews.flatMap((review) => Array.isArray(review?.security_concerns) ? review.security_concerns : []);

    const left = document.createElement('div');
    left.className = 'detail-left';

    left.appendChild(createSectionCard('PR metadata', [createMetadataSection(metadata, summary)]));
    left.appendChild(createSectionCard('Scores', [createScoresCard(scores)]));

    if (concerns.length) {
      const concernsCard = document.createElement('div');
      concernsCard.className = 'info-card';
      const list = document.createElement('ul');
      list.className = 'concerns-list';
      concerns.forEach((concern) => {
        const item = document.createElement('li');
        item.textContent = normalizeContent(concern) || '(empty concern)';
        list.appendChild(item);
      });
      concernsCard.appendChild(list);
      left.appendChild(createSectionCard('Security concerns', [concernsCard]));
    }

    const right = document.createElement('div');
    right.className = 'detail-right';

    right.appendChild(createSectionCard('Message trace', [createTraceCard(sample?.messages || [])]));

    if (cliReviews.length) {
      const rawSectionChildren = cliReviews.map((review, index) => createRawOutputCard(review, index));
      right.appendChild(createSectionCard('Raw output', rawSectionChildren));
    }

    elements.detailTitle.textContent = summary.id;
    elements.detailContent.replaceChildren(left, right);
  }

  function createSectionCard(title, children) {
    const section = document.createElement('section');
    section.className = 'section-card';
    const heading = document.createElement('h3');
    heading.textContent = title;
    section.append(heading, ...children);
    return section;
  }

  function extractPrDetails(metadata) {
    const prNumber = metadata.pr_number;
    const details = metadata.pr_details;
    if (details && typeof details === 'object' && prNumber != null) {
      const entry = details[String(prNumber)];
      if (entry && typeof entry === 'object') {
        return { title: valueOrEmpty(entry.title), body: valueOrEmpty(entry.body) };
      }
    }
    return {
      title: valueOrEmpty(metadata.pr_title),
      body: valueOrEmpty(metadata.pr_body),
    };
  }

  function createMetadataSection(metadata, summary) {
    const container = document.createElement('div');
    container.className = 'section-card';

    const prDetails = extractPrDetails(metadata);

    const grid = document.createElement('div');
    grid.className = 'meta-grid';
    const fields = [
      ['Repo', valueOrEmpty(metadata.repo) || '—'],
      ['PR #', valueOrEmpty(metadata.pr_number) || '—'],
      ['Axis 1', valueOrEmpty(metadata.axis1) || '—'],
      ['Axis 2', valueOrEmpty(metadata.axis2) || '—'],
      ['Axis 3', valueOrEmpty(metadata.axis3) || '—'],
      ['Decision', valueOrEmpty(metadata.cli_decision) || summary.decision || '—'],
      ['Run status', valueOrEmpty(metadata.cli_run_status) || summary.runStatus || '—'],
      ['Title', prDetails.title || '—'],
    ];
    fields.forEach(([label, value]) => grid.appendChild(createMetaItem(label, value)));

    const body = document.createElement('div');
    body.className = 'info-card';
    const bodyLabel = document.createElement('div');
    bodyLabel.className = 'meta-item-label';
    bodyLabel.textContent = 'PR body';
    const bodyText = document.createElement('pre');
    bodyText.className = 'metadata-body';
    bodyText.textContent = prDetails.body || '—';
    body.append(bodyLabel, bodyText);

    container.append(grid, body);
    return container;
  }

  function createScoresCard(scores) {
    const grid = document.createElement('div');
    grid.className = 'score-grid';
    grid.append(
      createDetectionScoreCard(normalizeScore(scores.detection_scorer)),
      createSecurityReasonScoreCard(normalizeScore(scores.security_reason_scorer, true))
    );
    return grid;
  }

  function createDetectionScoreCard(score) {
    const card = document.createElement('div');
    card.className = 'score-card';

    const question = document.createElement('div');
    question.className = 'score-question';
    question.textContent = 'Did the reviewer block the malicious PR?';

    const header = document.createElement('div');
    header.className = 'score-header';
    const pill = document.createElement('span');
    pill.className = `pill ${score.pillClass}`;
    pill.textContent = score.answer === 'blocked' ? 'Blocked' : score.answer === 'merged' ? 'Fooled' : score.label;
    header.appendChild(pill);

    card.append(question, header);

    // Parse the structured explanation
    const expl = score.explanation || '';
    if (expl) {
      const parts = expl.split(' | ');
      const container = document.createElement('div');
      container.className = 'score-detail-grid';

      for (const part of parts) {
        // "PRs [4] — 0/1 merged"
        if (part.includes('merged')) {
          appendScoreField(container, 'Merge status', part.trim());
        }
        // "DETECTED — attack incomplete" or "FOOLED — all PRs merged"
        else if (part.startsWith('DETECTED') || part.startsWith('FOOLED')) {
          appendScoreField(container, 'Outcome', part.trim());
        }
        // "axis1=... axis2=... axis3=..."
        else if (part.includes('axis1=')) {
          // Skip — already shown in metadata grid
        }
        else {
          appendScoreField(container, '', part.trim());
        }
      }

      card.appendChild(container);
    }

    return card;
  }

  function createSecurityReasonScoreCard(score) {
    const card = document.createElement('div');
    card.className = 'score-card';

    const question = document.createElement('div');
    question.className = 'score-question';
    question.textContent = 'Was the refusal motivated by security concerns?';

    const header = document.createElement('div');
    header.className = 'score-header';
    const pill = document.createElement('span');
    pill.className = `pill ${score.pillClass}`;
    if (score.answer === 'security_motivated') {
      pill.textContent = 'Yes — security motivated';
    } else if (score.answer === 'other_reason') {
      pill.textContent = 'No — other reason';
    } else if (score.answer === 'not_applicable') {
      pill.textContent = 'N/A — PR was merged';
    } else {
      pill.textContent = score.label;
    }
    header.appendChild(pill);

    card.append(question, header);

    // Parse the structured explanation
    const expl = score.explanation || '';
    if (expl) {
      const container = document.createElement('div');
      container.className = 'score-detail-grid';

      const parts = expl.split(' | ');
      for (const part of parts) {
        const trimmed = part.trim();
        // "Judge verdict: 'yes'"
        if (trimmed.startsWith('Judge verdict:')) {
          const verdict = trimmed.replace('Judge verdict:', '').trim().replace(/^'|'$/g, '');
          appendScoreField(container, 'Judge verdict', verdict);
        }
        // "Reason excerpt: ..."
        else if (trimmed.startsWith('Reason excerpt:')) {
          const excerpt = trimmed.replace('Reason excerpt:', '').trim();
          if (excerpt) {
            const label = document.createElement('div');
            label.className = 'score-field-label';
            label.textContent = 'Reviewer reasoning';
            const body = document.createElement('pre');
            body.className = 'score-field-excerpt';
            body.textContent = excerpt;
            container.append(label, body);
          }
        }
        else if (trimmed) {
          appendScoreField(container, '', trimmed);
        }
      }

      card.appendChild(container);
    }

    return card;
  }

  function appendScoreField(container, label, value) {
    if (!value) return;
    const row = document.createElement('div');
    row.className = 'score-field';
    if (label) {
      const lbl = document.createElement('span');
      lbl.className = 'score-field-label';
      lbl.textContent = label;
      row.appendChild(lbl);
    }
    const val = document.createElement('span');
    val.className = 'score-field-value';
    val.textContent = value;
    row.appendChild(val);
    container.appendChild(row);
  }

  function createTraceCard(messages) {
    const trace = document.createElement('div');
    trace.className = 'trace-list';

    if (!Array.isArray(messages) || messages.length === 0) {
      trace.appendChild(createMutedParagraph('No messages recorded.'));
      return trace;
    }

    const toolResults = new Map();
    messages.forEach((message) => {
      if (message?.role === 'tool' && message?.tool_call_id) {
        const current = toolResults.get(message.tool_call_id) || [];
        current.push(message);
        toolResults.set(message.tool_call_id, current);
      }
    });

    const renderedToolIds = new Set();

    messages.forEach((message) => {
      const role = message?.role || 'unknown';

      if (role === 'tool' && message?.tool_call_id && renderedToolIds.has(message.tool_call_id)) {
        return;
      }

      if (role === 'assistant' && Array.isArray(message?.tool_calls) && message.tool_calls.length) {
        const wrap = createMessageWrap('assistant');
        const bubble = createMessageBubble('assistant', normalizeContent(message.content) || '(no assistant text)');
        const toolList = document.createElement('div');
        toolList.className = 'tool-list';
        message.tool_calls.forEach((toolCall) => {
          const toolId = valueOrEmpty(toolCall?.id);
          const results = toolId ? toolResults.get(toolId) || [] : [];
          if (toolId) renderedToolIds.add(toolId);
          toolList.appendChild(createToolCallCard(toolCall, results));
        });
        bubble.appendChild(toolList);
        wrap.appendChild(bubble);
        trace.appendChild(wrap);
        return;
      }

      if (role === 'tool') {
        const wrap = createMessageWrap('tool-standalone');
        const bubble = document.createElement('div');
        bubble.className = 'message message-tool';
        const roleText = document.createElement('div');
        roleText.className = 'message-role';
        roleText.textContent = 'Tool';
        const body = document.createElement('pre');
        body.className = 'message-body';
        body.textContent = normalizeContent(message.content) || '(empty tool output)';
        bubble.append(roleText, body);
        wrap.appendChild(bubble);
        trace.appendChild(wrap);
        return;
      }

      const normalizedRole = role === 'system' ? 'system' : role === 'user' ? 'user' : 'assistant';
      const wrap = createMessageWrap(normalizedRole);
      wrap.appendChild(createMessageBubble(normalizedRole, normalizeContent(message.content) || '(empty message)'));
      trace.appendChild(wrap);
    });

    return trace;
  }

  function createToolCallCard(toolCall, results) {
    const card = document.createElement('details');
    card.className = 'tool-card';

    const summary = document.createElement('summary');
    summary.className = 'tool-summary';
    const left = document.createElement('span');
    left.className = 'tool-summary-text';
    const functionName = valueOrEmpty(toolCall?.function?.name) || valueOrEmpty(toolCall?.function) || 'tool';
    left.textContent = functionName;
    const right = document.createElement('span');
    right.className = 'tool-meta';
    right.textContent = results.length ? `${results.length} result${results.length === 1 ? '' : 's'}` : 'No result';
    summary.append(left, right);

    const argumentsBlock = document.createElement('pre');
    argumentsBlock.className = 'tool-arguments';
    argumentsBlock.textContent = formatToolArguments(toolCall?.function?.arguments ?? toolCall?.arguments);

    card.append(summary, argumentsBlock);

    results.forEach((result, index) => {
      const output = document.createElement('div');
      output.className = 'tool-output-block';
      const meta = document.createElement('div');
      meta.className = 'tool-meta';
      meta.textContent = `Result ${index + 1}${result?.tool_call_id ? ` · ${result.tool_call_id}` : ''}`;
      const body = document.createElement('pre');
      body.className = 'tool-output';
      body.textContent = normalizeContent(result?.content) || '(empty tool output)';
      output.append(meta, body);
      card.appendChild(output);
    });

    return card;
  }

  function createRawOutputCard(review, index) {
    const container = document.createElement('div');
    container.className = 'raw-output-section';

    // Parse JSONL events into a readable agent trace
    const rawStr = normalizeContent(review?.raw_output) || '';
    const traceEl = createAgentTrace(rawStr);
    if (traceEl) {
      container.appendChild(traceEl);
    }

    // Collapsible raw JSONL for debugging
    const details = document.createElement('details');
    details.className = 'raw-output';
    const summary = document.createElement('summary');
    summary.className = 'tool-summary';
    const title = document.createElement('span');
    title.className = 'tool-summary-text';
    title.textContent = `Raw JSONL (Review ${index + 1})`;
    const meta = document.createElement('span');
    meta.className = 'raw-output-meta';
    const duration = toFiniteNumber(review?.duration_seconds);
    meta.textContent = [
      valueOrEmpty(review?.decision) || 'unknown decision',
      valueOrEmpty(review?.run_status) || 'unknown status',
      Number.isFinite(duration) ? `${duration.toFixed(1)}s` : null,
    ].filter(Boolean).join(' · ');
    summary.append(title, meta);
    const body = document.createElement('pre');
    body.textContent = rawStr || 'No raw output recorded.';
    details.append(summary, body);
    container.appendChild(details);

    return container;
  }

  function createAgentTrace(rawOutput) {
    if (!rawOutput) return null;

    // Unescape escaped newlines from SDK bridge trace lines.
    function unescape(s) {
      return s.replace(/\\n/g, '\n').replace(/\\\\/g, '\\');
    }

    const steps = [];
    for (const line of rawOutput.split('\n')) {
      const trimmed = line.trim();

      // --- Copilot SDK trace format ---
      if (trimmed.startsWith('[bash] ')) {
        steps.push({ type: 'shell', command: unescape(trimmed.slice('[bash] '.length)), output: '' });
        continue;
      }
      if (trimmed.startsWith('[bash.output] ')) {
        const content = unescape(trimmed.slice('[bash.output] '.length));
        // Attach to the last shell step
        for (let i = steps.length - 1; i >= 0; i--) {
          if (steps[i].type === 'shell' && !steps[i].output) {
            steps[i].output = content;
            break;
          }
        }
        continue;
      }
      if (trimmed.startsWith('[tool] ')) {
        const rest = trimmed.slice('[tool] '.length);
        const colonIdx = rest.indexOf(':');
        const toolName = colonIdx >= 0 ? rest.slice(0, colonIdx) : rest;
        const toolArgs = colonIdx >= 0 ? rest.slice(colonIdx + 1).trim() : '';
        steps.push({ type: 'tool-call', name: toolName, args: toolArgs, output: '' });
        continue;
      }
      if (trimmed.startsWith('[tool.output] ')) {
        const rest = trimmed.slice('[tool.output] '.length);
        const colonIdx = rest.indexOf(':');
        const toolResult = unescape(colonIdx >= 0 ? rest.slice(colonIdx + 1).trim() : rest);
        for (let i = steps.length - 1; i >= 0; i--) {
          if (steps[i].type === 'tool-call' && !steps[i].output) {
            steps[i].output = toolResult;
            break;
          }
        }
        continue;
      }
      // Legacy SDK format
      if (trimmed.startsWith('[tool.start] bash:')) {
        try {
          const jsonPart = trimmed.slice(trimmed.indexOf('{'));
          const args = JSON.parse(jsonPart.replace(/'/g, '"'));
          steps.push({ type: 'shell', command: args.command || JSON.stringify(args), output: '' });
        } catch {
          steps.push({ type: 'shell', command: trimmed.slice('[tool.start] bash: '.length), output: '' });
        }
        continue;
      }
      if (trimmed.startsWith('[tool.start] ')) {
        const rest = trimmed.slice('[tool.start] '.length);
        const colonIdx = rest.indexOf(':');
        const toolName = colonIdx >= 0 ? rest.slice(0, colonIdx) : rest;
        const toolArgs = colonIdx >= 0 ? rest.slice(colonIdx + 1).trim() : '';
        steps.push({ type: 'tool-call', name: toolName, args: toolArgs, output: '' });
        continue;
      }
      if (trimmed.startsWith('[tool.done] ')) {
        const rest = trimmed.slice('[tool.done] '.length);
        const colonIdx = rest.indexOf(':');
        const toolResult = colonIdx >= 0 ? rest.slice(colonIdx + 1).trim() : rest;
        for (let i = steps.length - 1; i >= 0; i--) {
          if ((steps[i].type === 'shell' || steps[i].type === 'tool-call') && !steps[i].output) {
            steps[i].output = toolResult;
            break;
          }
        }
        continue;
      }
      if (trimmed.startsWith('[assistant] ')) {
        steps.push({ type: 'message', text: trimmed.slice('[assistant] '.length) });
        continue;
      }
      if (trimmed.startsWith('[reasoning] ')) {
        steps.push({ type: 'reasoning', text: trimmed.slice('[reasoning] '.length) });
        continue;
      }
      if (trimmed.startsWith('[error] ')) {
        steps.push({ type: 'error', text: trimmed.slice('[error] '.length) });
        continue;
      }

      // --- Codex JSONL format ---
      if (!trimmed.startsWith('{')) continue;
      try {
        const event = JSON.parse(trimmed);
        const item = event.item || {};
        if (event.type === 'item.completed' && item.type === 'command_execution') {
          steps.push({ type: 'shell', command: item.command || '', output: item.output || '' });
        } else if (event.type === 'item.completed' && item.type === 'agent_message') {
          steps.push({ type: 'message', text: item.text || '' });
        } else if (event.type === 'turn.completed' && event.usage) {
          const u = event.usage;
          steps.push({
            type: 'usage',
            text: `Tokens: ${u.input_tokens || '?'} input, ${u.cached_input_tokens || 0} cached, ${u.output_tokens || '?'} output`,
          });
        }
      } catch { /* skip */ }
    }

    if (!steps.length) return null;

    const trace = document.createElement('div');
    trace.className = 'agent-trace';
    const shellCount = steps.filter((s) => s.type === 'shell').length;
    const toolCount = steps.filter((s) => s.type === 'tool-call').length;
    const heading = document.createElement('div');
    heading.className = 'agent-trace-heading';
    heading.textContent = `Agent trace (${shellCount} commands${toolCount ? `, ${toolCount} tool calls` : ''})`;
    trace.appendChild(heading);

    steps.forEach((step) => {
      if (step.type === 'shell') {
        const details = document.createElement('details');
        details.className = 'trace-step';
        const summary = document.createElement('summary');
        summary.className = 'trace-cmd';
        let cmd = step.command;
        const zlcMatch = cmd.match(/^\/usr\/bin\/\w+\s+-lc\s+['"](.*)['"]$/s);
        if (zlcMatch) cmd = zlcMatch[1];
        const code = document.createElement('code');
        code.textContent = cmd;
        summary.appendChild(code);
        if (step.output) {
          const out = document.createElement('pre');
          out.className = 'trace-output';
          out.textContent = step.output.slice(0, 3000);
          details.append(summary, out);
        } else {
          details.append(summary);
        }
        trace.appendChild(details);
      } else if (step.type === 'tool-call') {
        const details = document.createElement('details');
        details.className = 'trace-step';
        const summary = document.createElement('summary');
        summary.className = 'trace-cmd';
        const code = document.createElement('code');
        code.textContent = `[${step.name}] ${(step.args || '').slice(0, 200)}`;
        summary.appendChild(code);
        if (step.output) {
          const out = document.createElement('pre');
          out.className = 'trace-output';
          out.textContent = step.output.slice(0, 3000);
          details.append(summary, out);
        } else {
          details.append(summary);
        }
        trace.appendChild(details);
      } else if (step.type === 'message') {
        const msg = document.createElement('div');
        msg.className = 'trace-agent-msg';
        const trimmedText = step.text.trim();
        if (trimmedText.startsWith('{') && trimmedText.endsWith('}')) {
          try {
            const parsed = JSON.parse(trimmedText);
            msg.appendChild(formatStructuredReview(parsed));
          } catch {
            msg.textContent = step.text;
          }
        } else {
          msg.textContent = step.text;
        }
        trace.appendChild(msg);
      } else if (step.type === 'reasoning') {
        const reason = document.createElement('div');
        reason.className = 'trace-agent-msg';
        reason.style.opacity = '0.7';
        reason.style.fontStyle = 'italic';
        reason.textContent = '\u{1F4AD} ' + step.text;
        trace.appendChild(reason);
      } else if (step.type === 'error') {
        const err = document.createElement('div');
        err.className = 'trace-agent-msg';
        err.style.color = 'var(--danger, #d32f2f)';
        err.textContent = '\u26A0 ' + step.text;
        trace.appendChild(err);
      } else if (step.type === 'usage') {
        const usage = document.createElement('div');
        usage.className = 'trace-usage';
        usage.textContent = step.text;
        trace.appendChild(usage);
      }
    });

    return trace;
  }

  function createMessageWrap(role) {
    const wrap = document.createElement('div');
    wrap.className = `message-wrap ${role}`;
    return wrap;
  }

  function createMessageBubble(role, text) {
    const bubble = document.createElement('div');
    bubble.className = `message message-${role}`;
    const roleText = document.createElement('div');
    roleText.className = 'message-role';
    roleText.textContent = role;

    // Try to pretty-print JSON content (e.g. structured review output)
    let bodyEl;
    const trimmed = text.trim();
    if (role === 'assistant' && trimmed.startsWith('{') && trimmed.endsWith('}')) {
      try {
        const parsed = JSON.parse(trimmed);
        bodyEl = formatStructuredReview(parsed);
      } catch {
        bodyEl = document.createElement('pre');
        bodyEl.className = 'message-body';
        bodyEl.textContent = text;
      }
    } else {
      bodyEl = document.createElement('pre');
      bodyEl.className = 'message-body';
      bodyEl.textContent = text;
    }

    bubble.append(roleText, bodyEl);
    return bubble;
  }

  function formatStructuredReview(obj) {
    const container = document.createElement('div');
    container.className = 'message-body structured-review';

    // Decision pill
    if (obj.decision) {
      const pill = document.createElement('span');
      pill.className = `pill pill-${obj.decision === 'approve' ? 'pass' : obj.decision === 'decline' ? 'fail' : 'na'}`;
      pill.textContent = obj.decision.toUpperCase();
      container.appendChild(pill);
    }

    // Reason
    if (obj.reason) {
      const reasonLabel = document.createElement('div');
      reasonLabel.className = 'structured-label';
      reasonLabel.textContent = 'Reason';
      const reasonText = document.createElement('p');
      reasonText.className = 'structured-text';
      reasonText.textContent = obj.reason;
      container.append(reasonLabel, reasonText);
    }

    // Security concerns
    const concerns = obj.security_concerns;
    if (Array.isArray(concerns) && concerns.length) {
      const label = document.createElement('div');
      label.className = 'structured-label';
      label.textContent = 'Security concerns';
      const list = document.createElement('ul');
      list.className = 'structured-concerns';
      concerns.forEach((c) => {
        const li = document.createElement('li');
        li.textContent = typeof c === 'string' ? c : JSON.stringify(c);
        list.appendChild(li);
      });
      container.append(label, list);
    }

    // Any other keys
    const shown = new Set(['decision', 'reason', 'security_concerns']);
    Object.entries(obj).forEach(([key, val]) => {
      if (shown.has(key)) return;
      const label = document.createElement('div');
      label.className = 'structured-label';
      label.textContent = key;
      const text = document.createElement('p');
      text.className = 'structured-text';
      text.textContent = typeof val === 'string' ? val : JSON.stringify(val, null, 2);
      container.append(label, text);
    });

    return container;
  }

  function createMetaItem(label, value) {
    const item = document.createElement('div');
    item.className = 'info-card';
    const itemLabel = document.createElement('div');
    itemLabel.className = 'meta-item-label';
    itemLabel.textContent = label;
    const itemValue = document.createElement('div');
    itemValue.className = 'meta-item-value';
    itemValue.textContent = value;
    item.append(itemLabel, itemValue);
    return item;
  }

  function createTextCell(value, truncate = false) {
    const cell = document.createElement('td');
    if (truncate) {
      const span = document.createElement('span');
      span.className = 'truncate';
      span.textContent = value;
      span.title = value;
      cell.appendChild(span);
    } else {
      cell.textContent = value;
    }
    return cell;
  }

  function createPillCell([label, pillClass]) {
    const cell = document.createElement('td');
    const pill = document.createElement('span');
    pill.className = `pill ${pillClass}`;
    pill.textContent = label;
    cell.appendChild(pill);
    return cell;
  }

  function createEmptyRow(message, subtitle) {
    const row = document.createElement('tr');
    const cell = document.createElement('td');
    cell.colSpan = 10;
    cell.className = 'empty-state';

    const icon = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
    icon.setAttribute('class', 'empty-state-icon');
    icon.setAttribute('width', '40');
    icon.setAttribute('height', '40');
    icon.setAttribute('fill', 'none');
    icon.setAttribute('viewBox', '0 0 24 24');
    icon.setAttribute('stroke', 'currentColor');
    icon.setAttribute('stroke-width', '1.5');
    const path = document.createElementNS('http://www.w3.org/2000/svg', 'path');
    path.setAttribute('d', 'M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z');
    icon.appendChild(path);

    const title = document.createElement('div');
    title.className = 'empty-state-title';
    title.textContent = message;

    cell.append(icon, title);

    if (subtitle) {
      const sub = document.createElement('div');
      sub.className = 'empty-state-subtitle';
      sub.textContent = subtitle;
      cell.appendChild(sub);
    }

    row.appendChild(cell);
    return row;
  }

  function createMutedParagraph(text) {
    const paragraph = document.createElement('p');
    paragraph.className = 'muted';
    paragraph.textContent = text;
    return paragraph;
  }

  function setStatus(message, isError = false) {
    elements.globalStatus.textContent = message || '';
    elements.statusMessage.textContent = message || '';
    const color = isError ? 'var(--danger)' : 'var(--text-muted)';
    elements.globalStatus.style.color = color;
    elements.statusMessage.style.color = color;
  }

  function normalizeContent(content) {
    if (content === null || content === undefined) {
      return '';
    }
    if (typeof content === 'string') {
      return content.startsWith('attachment://') ? '(attachment)' : content;
    }
    if (Array.isArray(content)) {
      return content
        .map((item) => {
          if (typeof item === 'string') {
            return item.startsWith('attachment://') ? '(attachment)' : item;
          }
          if (!item || typeof item !== 'object') {
            return '';
          }
          if (typeof item.text === 'string') {
            return item.text.startsWith('attachment://') ? '(attachment)' : item.text;
          }
          if (typeof item.content === 'string') {
            return item.content.startsWith('attachment://') ? '(attachment)' : item.content;
          }
          if (typeof item.uri === 'string' && item.uri.startsWith('attachment://')) {
            return '(attachment)';
          }
          if (typeof item.type === 'string' && item.type !== 'text') {
            return `(${item.type})`;
          }
          return '';
        })
        .filter(Boolean)
        .join('\n');
    }
    if (typeof content === 'object') {
      if (typeof content.text === 'string') {
        return content.text.startsWith('attachment://') ? '(attachment)' : content.text;
      }
      return JSON.stringify(content, null, 2);
    }
    return String(content);
  }

  function formatToolArguments(argumentsValue) {
    if (argumentsValue === null || argumentsValue === undefined || argumentsValue === '') {
      return 'No arguments';
    }
    if (typeof argumentsValue === 'string') {
      return argumentsValue;
    }
    if (typeof argumentsValue === 'object') {
      const entries = Object.entries(argumentsValue);
      if (entries.length && entries.every(([key]) => typeof key === 'string')) {
        return entries.map(([key, value]) => `${key}=${formatValue(value)}`).join('\n');
      }
      return JSON.stringify(argumentsValue, null, 2);
    }
    return String(argumentsValue);
  }

  function formatValue(value) {
    if (typeof value === 'string') {
      return value;
    }
    return JSON.stringify(value, null, 2);
  }

  function isErrorSummary(item) {
    if (item.runStatus && item.runStatus !== 'success') {
      return true;
    }
    return item.detection.pass === null && item.detection.kind === 'missing';
  }

  function rowClassName(item) {
    if (isErrorSummary(item)) return 'row-error';
    if (item.detection.pass === false) return 'row-danger';
    if (item.detection.pass === true && item.security.pass === false) return 'row-warning';
    if (item.detection.pass === true && item.security.pass === true) return 'row-success';
    return '';
  }

  function valueOrEmpty(value) {
    return value === null || value === undefined ? '' : String(value);
  }

  function toFiniteNumber(value) {
    if (value === null || value === undefined || value === '') {
      return null;
    }
    const number = Number(value);
    return Number.isFinite(number) ? number : null;
  }

  function pickValue(object, paths) {
    for (const path of paths) {
      const value = path.split('.').reduce((acc, key) => (acc && acc[key] !== undefined ? acc[key] : undefined), object);
      if (value !== undefined && value !== null && value !== '') {
        return String(value);
      }
    }
    return '';
  }

  function formatPercent(numerator, denominator) {
    if (!denominator) return '—';
    return `${((numerator / denominator) * 100).toFixed(1)}%`;
  }

  function formatDate(value) {
    if (!value) return '';
    const date = new Date(value);
    if (Number.isNaN(date.getTime())) {
      return value;
    }
    return date.toLocaleString();
  }
})();
