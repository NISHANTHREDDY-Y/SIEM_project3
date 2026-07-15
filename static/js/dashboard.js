function toggleSidebar() {
    document.getElementById("sidebar").classList.toggle("collapsed");
}

const palette = ["#22d3ee", "#22c55e", "#eab308", "#f97316", "#ef4444", "#a78bfa", "#60a5fa", "#f472b6"];
let dashboardChartHandles = {};

function drawChart(id, type, labels, values, label) {
    const element = document.getElementById(id);
    if (!element || typeof Chart === "undefined") return;
    if (dashboardChartHandles[id]) {
        dashboardChartHandles[id].destroy();
    }
    dashboardChartHandles[id] = new Chart(element, {
        type,
        data: {
            labels: labels || [],
            datasets: [{
                label: label || "Total",
                data: values || [],
                backgroundColor: type === "line" ? "rgba(34,211,238,.18)" : palette,
                borderColor: "#22d3ee",
                borderWidth: 2,
                tension: .35,
                fill: type === "line"
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: { legend: { labels: { color: "#cbd5e1" } } },
            scales: type === "doughnut" || type === "pie" ? {} : {
                x: { ticks: { color: "#93a4b8" }, grid: { color: "rgba(148,163,184,.1)" } },
                y: { ticks: { color: "#93a4b8" }, grid: { color: "rgba(148,163,184,.1)" }, beginAtZero: true }
            }
        }
    });
}

function ensureToastContainer() {
    let container = document.getElementById("toastContainer");
    if (!container) {
        container = document.createElement("div");
        container.id = "toastContainer";
        container.className = "toast-container";
        document.body.appendChild(container);
    }
    return container;
}

function showToast(title, message, severity) {
    const container = ensureToastContainer();
    const toast = document.createElement("div");
    toast.className = `toast ${severity || "success"}`;
    const titleNode = document.createElement("strong");
    titleNode.textContent = title;
    const messageNode = document.createElement("small");
    messageNode.textContent = message;
    toast.appendChild(titleNode);
    toast.appendChild(messageNode);
    container.prepend(toast);
    setTimeout(() => {
        toast.style.opacity = "0";
        toast.style.transform = "translateY(10px)";
        setTimeout(() => toast.remove(), 180);
    }, 4500);
}

function updateDashboardFromApi(payload) {
    if (!payload || !payload.latest_alerts) return;
    const state = window.dashboardState || { lastAlertId: 0, seenCriticalIds: [] };
    const latestId = payload.latest_alerts.length ? payload.latest_alerts[0].id : state.lastAlertId;
    const newAlerts = payload.latest_alerts.filter((alert) => Number(alert.id) > Number(state.lastAlertId || 0));
    newAlerts
        .filter((alert) => String(alert.severity || "").toUpperCase() === "CRITICAL")
        .forEach((alert) => {
            if (!state.seenCriticalIds.includes(alert.id)) {
                state.seenCriticalIds.push(alert.id);
                showToast(
                    "Critical SIEM Alert",
                    `${alert.threat} on ${alert.username || "SYSTEM"} (${alert.source || "Unknown"})`,
                    "critical"
                );
            }
        });
    state.lastAlertId = Math.max(Number(state.lastAlertId || 0), Number(latestId || 0));
    window.dashboardState = state;
}

async function pollDashboard() {
    try {
        const response = await fetch("/api/dashboard", { headers: { Accept: "application/json" } });
        if (!response.ok) return;
        const payload = await response.json();
        updateDashboardFromApi(payload);
    } catch (error) {
        console.warn("Dashboard poll failed", error);
    }
}

document.addEventListener("DOMContentLoaded", () => {
    const d = window.siemCharts;
    if (d) {
        drawChart("threatTrendChart", "line", d.threatTrend.labels, d.threatTrend.values, "Alerts");
        drawChart("monthlyThreatTrendChart", "line", d.monthlyThreatTrend.labels, d.monthlyThreatTrend.values, "Alerts");
        drawChart("severityPieChart", "doughnut", d.severity.labels, d.severity.values, "Severity");
        drawChart("topUsersChart", "bar", d.topUsers.labels, d.topUsers.values, "Events");
        drawChart("topSourcesChart", "bar", d.topSources.labels, d.topSources.values, "Events");
        drawChart("eventTypesChart", "bar", d.events.labels, d.events.values, "Events");
        drawChart("loginChart", "doughnut", ["Success", "Failure"], [d.login.success, d.login.failed], "Logins");
    }

    const a = window.analyticsCharts;
    if (a) {
        drawChart("analyticsThreatTrend", "line", a.threatTrend.labels, a.threatTrend.values, "Alerts");
        drawChart("analyticsSeverity", "doughnut", a.severity.labels, a.severity.values, "Alerts");
        drawChart("analyticsUsers", "bar", a.users.labels, a.users.values, "Events");
        drawChart("analyticsHourly", "bar", a.hourly.labels, a.hourly.values, "Events");
        drawChart("analyticsEvents", "bar", a.events.labels, a.events.values, "Events");
        drawChart("analyticsSources", "bar", a.sources.labels, a.sources.values, "Events");
    }

    if (window.dashboardState) {
        pollDashboard();
        setInterval(pollDashboard, 5000);
    }
});
