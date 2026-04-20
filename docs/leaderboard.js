// Leaderboard Data and Visualizations

let leaderboardData = {};
let charts = {};

async function loadData() {
  try {
    const response = await fetch("leaderboard_data.json");
    leaderboardData = await response.json();
    initializeUI();
    renderAllCharts();
  } catch (error) {
    console.error("Error loading leaderboard data:", error);
  }
}

function initializeUI() {
  const harnessSelect = document.getElementById("harness-filter");
  const cweSelect = document.getElementById("cwe-filter");
  const modelSelect = document.getElementById("model-filter");

  // Populate harness filter
  if (harnessSelect && leaderboardData.harnesses) {
    const defaultOption = document.createElement("option");
    defaultOption.value = "all";
    defaultOption.textContent = "All Harnesses";
    harnessSelect.appendChild(defaultOption);

    leaderboardData.harnesses.forEach((harness) => {
      const option = document.createElement("option");
      option.value = harness;
      option.textContent = harness;
      harnessSelect.appendChild(option);
    });
  }

  // Populate CWE filter
  if (cweSelect && leaderboardData.cwes) {
    const defaultOption = document.createElement("option");
    defaultOption.value = "all";
    defaultOption.textContent = "All CWE Types";
    cweSelect.appendChild(defaultOption);

    leaderboardData.cwes.forEach((cwe) => {
      const option = document.createElement("option");
      option.value = cwe;
      option.textContent = cwe;
      cweSelect.appendChild(option);
    });
  }

  // Populate model filter
  if (modelSelect && leaderboardData.models) {
    const defaultOption = document.createElement("option");
    defaultOption.value = "all";
    defaultOption.textContent = "All Models";
    modelSelect.appendChild(defaultOption);

    leaderboardData.models.forEach((model) => {
      const option = document.createElement("option");
      option.value = model;
      option.textContent = model;
      modelSelect.appendChild(option);
    });
  }
}

function getFilteredData() {
  const harnessFilter = document.getElementById("harness-filter")?.value || "all";
  const cweFilter = document.getElementById("cwe-filter")?.value || "all";
  const modelFilter = document.getElementById("model-filter")?.value || "all";

  return leaderboardData.data_points.filter((point) => {
    const harnessMatch = harnessFilter === "all" || point.harness === harnessFilter;
    const cweMatch = cweFilter === "all" || point.cwe === cweFilter;
    const modelMatch = modelFilter === "all" || point.model === modelFilter;
    return harnessMatch && cweMatch && modelMatch;
  });
}

function renderAllCharts() {
  renderTimeSeriesChart();
  renderBarChart();
  renderAxisTable();
}

function renderTimeSeriesChart() {
  const filteredData = getFilteredData();

  // Prepare time-series data
  const timeSeriesData = {};
  filteredData.forEach((point) => {
    const key = `${point.model} (${point.harness})`;
    if (!timeSeriesData[key]) {
      timeSeriesData[key] = [];
    }
    timeSeriesData[key].push({
      date: point.created,
      score: point.score || 0,
      cwe: point.cwe,
    });
  });

  // Sort by date
  Object.keys(timeSeriesData).forEach((key) => {
    timeSeriesData[key].sort((a, b) => new Date(a.date) - new Date(b.date));
  });

  const ctx = document.getElementById("timeSeriesChart");
  if (!ctx) return;

  const colors = [
    "rgba(255, 99, 132, 0.6)",
    "rgba(54, 162, 235, 0.6)",
    "rgba(75, 192, 192, 0.6)",
    "rgba(255, 206, 86, 0.6)",
    "rgba(153, 102, 255, 0.6)",
    "rgba(255, 159, 64, 0.6)",
  ];

  const datasets = Object.entries(timeSeriesData).map(([label, data], index) => ({
    label: label,
    data: data.map((d) => ({
      x: new Date(d.date).toLocaleDateString(),
      y: d.score,
    })),
    borderColor: colors[index % colors.length],
    backgroundColor: colors[index % colors.length],
    tension: 0.3,
    fill: false,
  }));

  if (charts.timeSeries) charts.timeSeries.destroy();

  charts.timeSeries = new Chart(ctx, {
    type: "line",
    data: { datasets: datasets },
    options: {
      responsive: true,
      plugins: {
        title: { display: true, text: "Score Over Time" },
        legend: { display: true, position: "top" },
      },
      scales: {
        y: {
          beginAtZero: true,
          max: 1,
          title: { display: true, text: "Score" },
        },
        x: {
          title: { display: true, text: "Date" },
        },
      },
    },
  });
}

function renderBarChart() {
  const filteredData = getFilteredData();
  const cweFilter = document.getElementById("cwe-filter")?.value || "all";

  const ctx = document.getElementById("barChart");
  if (!ctx) return;

  // Get all models and CWEs in filtered data
  const models = [...new Set(filteredData.map((p) => p.model))].sort();
  const cwes = cweFilter === "all"
    ? [...new Set(filteredData.map((p) => p.cwe))].sort()
    : [cweFilter];

  // Aggregate by model and CWE
  const modelCweScores = {};
  models.forEach((model) => {
    modelCweScores[model] = {};
    cwes.forEach((cwe) => {
      modelCweScores[model][cwe] = [];
    });
  });

  filteredData.forEach((point) => {
    if (modelCweScores[point.model] && modelCweScores[point.model][point.cwe]) {
      modelCweScores[point.model][point.cwe].push(point.score || 0);
    }
  });

  // Model colors - consistent across all CWEs
  const modelColors = {
    "gpt-5.2": "rgba(255, 99, 132, 0.6)",
    "claude-opus": "rgba(54, 162, 235, 0.6)",
    "claude-sonnet": "rgba(75, 192, 192, 0.6)",
    "gpt-4": "rgba(255, 206, 86, 0.6)",
    "gemini": "rgba(153, 102, 255, 0.6)",
    "llama": "rgba(255, 159, 64, 0.6)",
  };

  // Create datasets - one per model
  const datasets = models.map((model, idx) => {
    const data = cwes.map((cwe) => {
      const scores = modelCweScores[model][cwe];
      return scores.length > 0 ? scores.reduce((a, b) => a + b) / scores.length : 0;
    });
    const color = modelColors[model] || `rgba(${100 + idx * 50}, ${100 + idx * 30}, ${100 + idx * 20}, 0.6)`;
    return {
      label: model,
      data: data,
      backgroundColor: color,
      borderColor: color.replace("0.6", "1"),
      borderWidth: 1,
    };
  });

  if (charts.bar) charts.bar.destroy();

  const title = cweFilter === "all"
    ? "Model Comparison - All CWEs"
    : `Model Comparison - ${cweFilter.toUpperCase()}`;

  charts.bar = new Chart(ctx, {
    type: "bar",
    data: {
      labels: cwes.map((c) => c.toUpperCase()),
      datasets: datasets,
    },
    options: {
      responsive: true,
      indexAxis: "x",
      plugins: {
        title: {
          display: true,
          text: title,
        },
        legend: { display: true, position: "top" },
      },
      scales: {
        y: {
          beginAtZero: true,
          max: 1,
          title: { display: true, text: "Accuracy" },
        },
      },
    },
  });
}

function renderDeceptionPatternsChart() {
  const filteredData = getFilteredData();

  // Aggregate axis2 data by deception pattern
  const deceptionScores = {};
  filteredData.forEach((point) => {
    if (point.axes && point.axes.axis2) {
      for (const [pattern, score] of Object.entries(point.axes.axis2)) {
        if (!deceptionScores[pattern]) {
          deceptionScores[pattern] = [];
        }
        deceptionScores[pattern].push(score);
      }
    }
  });

  // Calculate averages
  const patterns = Object.keys(deceptionScores).sort();
  const data = patterns.map((pattern) => {
    const scores = deceptionScores[pattern];
    return scores.length > 0 ? scores.reduce((a, b) => a + b) / scores.length : 0;
  });

  const ctx = document.getElementById("deceptionChart");
  if (!ctx) return;

  const colors = data.map((score) =>
    score > 0.8 ? "rgba(75, 192, 75, 0.6)" : score > 0.6 ? "rgba(255, 193, 7, 0.6)" : "rgba(244, 67, 54, 0.6)"
  );

  if (charts.deception) charts.deception.destroy();

  charts.deception = new Chart(ctx, {
    type: "bar",
    data: {
      labels: patterns,
      datasets: [
        {
          label: "Accuracy by Deception Pattern",
          data: data,
          backgroundColor: colors,
          borderColor: colors.map((c) => c.replace("0.6", "1")),
          borderWidth: 2,
        },
      ],
    },
    options: {
      responsive: true,
      indexAxis: "x",
      plugins: {
        title: {
          display: true,
          text: "Model Performance by Deception Pattern",
        },
        legend: { display: false },
      },
      scales: {
        y: {
          beginAtZero: true,
          max: 1,
          title: { display: true, text: "Accuracy" },
        },
      },
    },
  });
}

function renderRadarChart() {
  const filteredData = getFilteredData();

  // Get unique models
  const models = [...new Set(filteredData.map((p) => p.model))];

  if (models.length === 0) return;

  // Aggregate axis3 data by model from axes field
  const modelAxis3Scores = {};
  models.forEach((model) => {
    modelAxis3Scores[model] = {};
  });

  filteredData.forEach((point) => {
    if (point.axes && point.axes.axis3) {
      const axis3Data = point.axes.axis3;
      for (const [attackType, score] of Object.entries(axis3Data)) {
        if (!modelAxis3Scores[point.model][attackType]) {
          modelAxis3Scores[point.model][attackType] = [];
        }
        modelAxis3Scores[point.model][attackType].push(score);
      }
    }
  });

  // Get unique axis3 attack types across all models
  const axis3Types = [...new Set(
    Object.values(modelAxis3Scores).flatMap(obj => Object.keys(obj))
  )].sort();

  if (axis3Types.length === 0) return;

  const ctx = document.getElementById("radarChart");
  if (!ctx) return;

  const colors = [
    "rgba(255, 99, 132, 0.2)",
    "rgba(54, 162, 235, 0.2)",
    "rgba(75, 192, 192, 0.2)",
    "rgba(255, 206, 86, 0.2)",
    "rgba(153, 102, 255, 0.2)",
    "rgba(255, 159, 64, 0.2)",
  ];

  const datasets = models.slice(0, 6).map((model, idx) => ({
    label: model,
    data: axis3Types.map((attackType) => {
      const scores = modelAxis3Scores[model][attackType] || [];
      return scores.length > 0 ? scores.reduce((a, b) => a + b) / scores.length : 0;
    }),
    borderColor: colors[idx].replace("0.2", "1"),
    backgroundColor: colors[idx],
    borderWidth: 2,
  }));

  if (charts.radar) charts.radar.destroy();

  charts.radar = new Chart(ctx, {
    type: "radar",
    data: {
      labels: axis3Types,
      datasets: datasets,
    },
    options: {
      responsive: true,
      plugins: {
        title: {
          display: true,
          text: "Model Performance by Attack Type",
        },
        legend: { display: true, position: "top" },
      },
      scales: {
        r: {
          beginAtZero: true,
          max: 1,
          title: { display: true, text: "Accuracy" },
        },
      },
    },
  });
}

function renderAxisTable() {
  const modelSelect = document.getElementById("model-filter");
  const axisTableContainer = document.getElementById("axisTableContainer");

  if (!modelSelect || !axisTableContainer) return;

  const selectedModel = modelSelect.value;
  if (selectedModel === "all") {
    axisTableContainer.innerHTML = '<div class="has-text-grey-light" style="padding: 2rem; text-align: center;"><p>Select a model to see axis breakdown details</p></div>';
    axisTableContainer.style.display = "block";
    return;
  }

  axisTableContainer.style.display = "block";

  const filteredData = getFilteredData();
  if (filteredData.length === 0) {
    axisTableContainer.innerHTML = '<div class="has-text-grey-light" style="padding: 2rem; text-align: center;"><p>No data available for selected filters</p></div>';
    return;
  }

  // Aggregate axis data for filtered model
  const axisBreakdown = {
    axis1: {},
    axis2: {},
    axis3: {},
  };

  filteredData.forEach((point) => {
    if (point.axes) {
      for (const [axis, values] of Object.entries(point.axes)) {
        for (const [axisVal, score] of Object.entries(values)) {
          if (!axisBreakdown[axis][axisVal]) {
            axisBreakdown[axis][axisVal] = [];
          }
          axisBreakdown[axis][axisVal].push(score);
        }
      }
    }
  });

  // Calculate averages
  for (const axis of Object.keys(axisBreakdown)) {
    for (const val of Object.keys(axisBreakdown[axis])) {
      const scores = axisBreakdown[axis][val];
      axisBreakdown[axis][val] = scores.reduce((a, b) => a + b) / scores.length;
    }
  }

  // Build two side-by-side tables
  let html = `<div class="columns">`;

  // Axis2 (Deception Patterns) table
  html += `<div class="column">
    <div class="table-container">
      <h3 class="title is-5">Deception Patterns</h3>
      <table class="table is-striped is-hoverable">
        <thead><tr><th>Pattern</th><th>Accuracy</th></tr></thead>
        <tbody>`;

  const axis2Entries = Object.entries(axisBreakdown["axis2"])
    .sort((a, b) => b[1] - a[1]);

  for (const [value, score] of axis2Entries) {
    const scoreColor =
      score > 0.8 ? "has-text-success" : score > 0.6 ? "has-text-warning" : "has-text-danger";
    html += `<tr>
      <td><code>${value}</code></td>
      <td class="${scoreColor}"><strong>${(score * 100).toFixed(1)}%</strong></td>
    </tr>`;
  }

  html += `</tbody></table></div></div>`;

  // Axis3 (Attack Types) table
  html += `<div class="column">
    <div class="table-container">
      <h3 class="title is-5">Attack Types</h3>
      <table class="table is-striped is-hoverable">
        <thead><tr><th>Attack Type</th><th>Accuracy</th></tr></thead>
        <tbody>`;

  const axis3Entries = Object.entries(axisBreakdown["axis3"])
    .sort((a, b) => b[1] - a[1]);

  for (const [value, score] of axis3Entries) {
    const scoreColor =
      score > 0.8 ? "has-text-success" : score > 0.6 ? "has-text-warning" : "has-text-danger";
    html += `<tr>
      <td><code>${value}</code></td>
      <td class="${scoreColor}"><strong>${(score * 100).toFixed(1)}%</strong></td>
    </tr>`;
  }

  html += `</tbody></table></div></div></div>`;
  axisTableContainer.innerHTML = html;
}

// Event listeners
document.addEventListener("DOMContentLoaded", () => {
  loadData();

  const harnessSelect = document.getElementById("harness-filter");
  const cweSelect = document.getElementById("cwe-filter");
  const modelSelect = document.getElementById("model-filter");

  if (harnessSelect) {
    harnessSelect.addEventListener("change", renderAllCharts);
  }
  if (cweSelect) {
    cweSelect.addEventListener("change", renderAllCharts);
  }
  if (modelSelect) {
    modelSelect.addEventListener("change", renderAllCharts);
  }
});
