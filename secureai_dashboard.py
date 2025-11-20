from flask import Flask, jsonify, render_template_string
import random
import threading
import webbrowser
import time

app = Flask(__name__)

# -----------------------------
#   MOCK SECURITY ENGINE
# -----------------------------
SECURITY_STATE = {
    "ids_alerts": 0,
    "phishing_count": 0,
    "insider_threats": 0
}

def security_engine():
    """Simulates continuous security updates."""
    while True:
        SECURITY_STATE["ids_alerts"] = random.randint(0, 20)
        SECURITY_STATE["phishing_count"] = random.randint(0, 10)
        SECURITY_STATE["insider_threats"] = random.randint(0, 5)
        time.sleep(3)

# Start background engine
t = threading.Thread(target=security_engine, daemon=True)
t.start()

# ---------------------------------
#           API ENDPOINT
# ---------------------------------
@app.route("/api/status")
def status():
    return jsonify(SECURITY_STATE)

# ---------------------------------
#         DASHBOARD UI (HTML)
# ---------------------------------
DASHBOARD_HTML = """
<!DOCTYPE html>
<html>
<head>
    <title>SecureAI Dashboard</title>
    <style>
        body {
            font-family: Arial;
            background: #0d1117;
            color: white;
            text-align: center;
            padding-top: 40px;
        }
        .card {
            display: inline-block;
            width: 300px;
            padding: 20px;
            margin: 20px;
            border-radius: 12px;
            background: #161b22;
            box-shadow: 0px 0px 12px rgba(0,0,0,0.4);
        }
        .number {
            font-size: 48px;
            font-weight: bold;
            color: #00eaff;
        }
    </style>
</head>
<body>

    <h1>🔐 SecureAI Defense Dashboard</h1>
    <h3>Real-Time Cybersecurity Monitoring</h3>

    <div class="card">
        <h2>IDS Alerts</h2>
        <div id="ids_alerts" class="number">loading...</div>
    </div>

    <div class="card">
        <h2>Phishing Attempts</h2>
        <div id="phishing_count" class="number">loading...</div>
    </div>

    <div class="card">
        <h2>Insider Threats</h2>
        <div id="insider_threats" class="number">loading...</div>
    </div>

<script>
function refreshData() {
    fetch("/api/status")
        .then(response => response.json())
        .then(data => {
            document.getElementById("ids_alerts").innerText = data.ids_alerts;
            document.getElementById("phishing_count").innerText = data.phishing_count;
            document.getElementById("insider_threats").innerText = data.insider_threats;
        })
        .catch(err => console.error("API Error:", err));
}

setInterval(refreshData, 1500);
refreshData();
</script>

</body>
</html>
"""

@app.route("/")
def home():
    return render_template_string(DASHBOARD_HTML)

# ---------------------------------
#      AUTO-OPEN BROWSER
# ---------------------------------
def open_browser():
    webbrowser.open("http://127.0.0.1:5000")

if __name__ == "__main__":
    threading.Timer(1, open_browser).start()
    app.run(debug=False, port=5000)
