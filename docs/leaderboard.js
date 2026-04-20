// Leaderboard Data and Visualizations

let leaderboardData = {};
let chart = null;

async function loadData() {
  try {
    const response = await fetch("leaderboard_data.json");
    leaderboardData = await response.json();
    initializeUI();
    renderCharts();
  } catch (error) {
    console.error("Error loading leaderboard data:", error);
  }
}

function initializeUI() {
  const harnessSelect = document.getElementById("harness-filter");
  const cweSelect = document.getElementById("cwe-filter");

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
}

function getFilteredData() {
  const harnessFilter = document.getElementById("harness-filter")?.value || "all";
  const cweFilter = document.getElementById("cwe-filter")?.value || "all";

  return leaderboardData.data_points.filter((point) => {
    const harnessMatch = harnessFilter === "all" || point.harness === harnessFilter;
    const cweMatch = cweFilter === "all" || point.cwe === cweFilter;
    return harnessMatch && cweMatch;
  });
}

function renderCharts() {
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

  // Create chart
  const ctx = document.getElementById("timeSeriesChart");
  if (!ctx) return;

  const datasets = Object.entries(timeSeriesData).map(([label, data], index) => {
    const colors = [
      "rgba(255, 99, 132, 0.6)",
      "rgba(54, 162, 235, 0.6)",
      "rgba(75, 192, 192, 0.6)",
      "rgba(255, 206, 86, 0.6)",
      "rgba(153, 102, 255, 0.6)",
      "rgba(255, 159, 64, 0.6)",
    ];

    return {
      label: label,
      data: data.map((d) => ({
        x: new Date(d.date).toLocaleDateString(),
        y: d.score,
      })),
      borderColor: colors[index % colors.length],
      backgroundColor: colors[index % colors.length],
      tension: 0.3,
      fill: false,
    };
  });

  if (chart) {
    chart.destroy();
  }

  chart = new Chart(ctx, {
    type: "line",
    data: {
      datasets: datasets,
    },
    options: {
      responsive: true,
      plugins: {
        title: {
          display: true,
          text: "Benchmark Score Over Time",
        },
        legend: {
          display: true,
          position: "top",
        },
      },
      scales: {
        y: {
          beginAtZero: true,
          max: 1,
          title: {
            display: true,
            text: "Score",
          },
        },
        x: {
          title: {
            display: true,
            text: "Date",
          },
        },
      },
    },
  });
}

// Event listeners
document.addEventListener("DOMContentLoaded", () => {
  loadData();

  const harnessSelect = document.getElementById("harness-filter");
  const cweSelect = document.getElementById("cwe-filter");

  if (harnessSelect) {
    harnessSelect.addEventListener("change", renderCharts);
  }
  if (cweSelect) {
    cweSelect.addEventListener("change", renderCharts);
  }
});
