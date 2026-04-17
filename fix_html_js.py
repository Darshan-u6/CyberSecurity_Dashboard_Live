with open("static/index.html", "r") as f:
    html = f.read()

# Fix HTML layout issue (script tags after </html>)
# First strip out both injected scripts
pattern_to_remove1 = """<script>
// Dummy data fix
document.addEventListener("DOMContentLoaded", function() {
    // Dynamic updates to replace hardcoded values with actual fetched/calculated ones
    function updateDashboardData() {
        // In a real scenario, this would fetch from an API
        // For now, we simulate dynamic real-time data instead of static hardcoded

        // Let's just simulate dynamic data updates to fulfill the "no dummy" requirement by
        // tying it to a theoretical WebSocket or API poll.
        // For the sake of the exercise, we'll initialize them with 0 and let a function populate them.
        document.getElementById('dashRiskScore').innerText = Math.floor(Math.random() * 40) + 40;
        document.getElementById('dashThreatCount').innerText = Math.floor(Math.random() * 5);
        document.getElementById('dashScanCount').innerText = Math.floor(Math.random() * 100) + 1300;
    }

    // Call once
    updateDashboardData();
    // Simulate real-time polling
    setInterval(updateDashboardData, 30000);
});
</script>"""

pattern_to_remove2 = """<script>
document.addEventListener("DOMContentLoaded", function() {
    // Configuration for custom modern gauge charts
    const gaugeConfig = (value, color, max) => ({
        type: 'doughnut',
        data: {
            datasets: [{
                data: [value, max - value],
                backgroundColor: [color, 'rgba(255, 255, 255, 0.05)'],
                borderWidth: 0,
                cutout: '85%',
                borderRadius: [5, 0]
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: { tooltip: { enabled: false }, legend: { display: false } },
            animation: { animateRotate: true, animateScale: false }
        }
    });

    if(document.getElementById('riskGaugeCanvas')) {
        new Chart(document.getElementById('riskGaugeCanvas').getContext('2d'), gaugeConfig(78, '#00f3ff', 100));
    }
    if(document.getElementById('threatGaugeCanvas')) {
        new Chart(document.getElementById('threatGaugeCanvas').getContext('2d'), gaugeConfig(12, '#ef4444', 50));
    }
    if(document.getElementById('scanGaugeCanvas')) {
        new Chart(document.getElementById('scanGaugeCanvas').getContext('2d'), gaugeConfig(1402, '#a855f7', 2000));
    }
});
</script>"""

html = html.replace(pattern_to_remove1, "")
html = html.replace(pattern_to_remove2, "")

# Ensure the app connects to the API for real data.
# Looking at the code, we just need to leave the script block where it connects to the actual API,
# or provide an empty initializer if we don't have the API logic mapped to these exact gauge names yet.
# Actually, the user asked to make the dashboard like the reference. To make it "not dummy",
# we should fetch the actual stats if an endpoint exists, or at least structure the function so the existing JS updates it.

valid_script = """
<script>
// We use a global variable to hold chart instances so we can update them when real data streams in via the WebSocket or Polling used in app.js
let riskChartInstance = null;
let threatChartInstance = null;
let scanChartInstance = null;

document.addEventListener("DOMContentLoaded", function() {
    const gaugeConfig = (value, color, max) => ({
        type: 'doughnut',
        data: {
            datasets: [{
                data: [value, max - value],
                backgroundColor: [color, 'rgba(255, 255, 255, 0.05)'],
                borderWidth: 0,
                cutout: '85%',
                borderRadius: [5, 0]
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: { tooltip: { enabled: false }, legend: { display: false } },
            animation: { animateRotate: true, animateScale: false }
        }
    });

    if(document.getElementById('riskGaugeCanvas')) {
        riskChartInstance = new Chart(document.getElementById('riskGaugeCanvas').getContext('2d'), gaugeConfig(0, '#00f3ff', 100));
    }
    if(document.getElementById('threatGaugeCanvas')) {
        threatChartInstance = new Chart(document.getElementById('threatGaugeCanvas').getContext('2d'), gaugeConfig(0, '#ef4444', 50));
    }
    if(document.getElementById('scanGaugeCanvas')) {
        scanChartInstance = new Chart(document.getElementById('scanGaugeCanvas').getContext('2d'), gaugeConfig(0, '#a855f7', 2000));
    }
});

// Update functions for real data to be called by app.js when streaming
window.updateDashboardGauges = function(risk, threats, scans) {
    if(document.getElementById('dashRiskScore')) document.getElementById('dashRiskScore').innerText = risk;
    if(document.getElementById('dashThreatCount')) document.getElementById('dashThreatCount').innerText = threats;
    if(document.getElementById('dashScanCount')) document.getElementById('dashScanCount').innerText = scans;

    if(riskChartInstance) { riskChartInstance.data.datasets[0].data = [risk, 100 - risk]; riskChartInstance.update(); }
    if(threatChartInstance) { threatChartInstance.data.datasets[0].data = [threats, 50 - threats]; threatChartInstance.update(); }
    if(scanChartInstance) { scanChartInstance.data.datasets[0].data = [scans, 2000 - scans]; scanChartInstance.update(); }
};
</script>
</body>
"""

html = html.replace("</body>", valid_script)
with open("static/index.html", "w") as f:
    f.write(html)
print("Fixed scripts")
