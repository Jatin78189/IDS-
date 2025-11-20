from flask import Flask, jsonify
import random

app = Flask(__name__)

# -----------------------------
#  3D Dashboard HTML (INLINE)
# -----------------------------
HTML_PAGE = """
<!DOCTYPE html>
<html>
<head>
    <title>SecureAI 3D Dashboard</title>
    <style>
        body {
            margin: 0;
            background: #000;
            overflow: hidden;
            font-family: Arial, sans-serif;
            color: white;
            text-align: center;
        }

        h1 {
            margin-top: 20px;
            text-shadow: 0 0 20px cyan;
        }

        .panel {
            width: 300px;
            padding: 20px;
            background: rgba(0,0,0,0.5);
            border: 2px solid cyan;
            border-radius: 20px;
            box-shadow: 0 0 20px cyan;
            margin: 20px auto;
        }
    </style>

    <!-- 3D background -->
    <script src="https://cdnjs.cloudflare.com/ajax/libs/three.js/r121/three.min.js"></script>
</head>

<body>
    <h1>⚡ SecureAI 3D Dashboard</h1>

    <div class="panel">
        <h2>Status</h2>
        <p id="ids">IDS Alerts: loading...</p>
        <p id="phish">Phishing Count: loading...</p>
        <p id="insider">Insider Threats: loading...</p>
    </div>

    <script>
        // 3D animation
        let scene = new THREE.Scene();
        let camera = new THREE.PerspectiveCamera(75, window.innerWidth/window.innerHeight, 0.1, 1000);
        let renderer = new THREE.WebGLRenderer();
        renderer.setSize(window.innerWidth, window.innerHeight);
        document.body.appendChild(renderer.domElement);

        let geometry = new THREE.TorusKnotGeometry(10, 3, 200, 30);
        let material = new THREE.MeshBasicMaterial({ color: 0x00ffff, wireframe: true });
        let torusKnot = new THREE.Mesh(geometry, material);
        scene.add(torusKnot);

        camera.position.z = 40;

        function animate() {
            requestAnimationFrame(animate);
            torusKnot.rotation.x += 0.01;
            torusKnot.rotation.y += 0.01;
            renderer.render(scene, camera);
        }
        animate();

        // Fetch API data every 2 seconds
        setInterval(() => {
            fetch('/api/status')
            .then(res => res.json())
            .then(data => {
                document.getElementById("ids").innerText = "IDS Alerts: " + data.ids_alerts;
                document.getElementById("phish").innerText = "Phishing Count: " + data.phishing;
                document.getElementById("insider").innerText = "Insider Threats: " + data.insider;
            });
        }, 2000);
    </script>
</body>
</html>
"""

# -----------------------------
#  API ENDPOINTS
# -----------------------------
@app.route("/")
def home():
    return HTML_PAGE

@app.route("/api/status")
def status():
    return jsonify({
        "ids_alerts": random.randint(0, 5),
        "phishing": random.randint(0, 10),
        "insider": random.randint(0, 3),
    })

# -----------------------------
#  Run Server
# -----------------------------
if __name__ == "__main__":
    print("🚀 SecureAI 3D Dashboard running at: http://127.0.0.1:5000")
    app.run(debug=True)
