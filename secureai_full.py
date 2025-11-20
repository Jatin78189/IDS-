# secureai_full.py (NO FACE RECOGNITION VERSION)
"""
SecureAI - single-file demo combining:
1. IDS (signature + anomaly)
2. Phishing / spam detection (NLP)
3. Spear-phish detection (text patterns)
4. 2FA (TOTP) demo
5. UBA - insider threat detection (IsolationForest)
6. Flask dashboard
7. Zero-day + false-positive illustration
8. Multi-layer identity verification demo (OTP only)
-----------------------------------------------------
Usage:
  python secureai_full.py --setup      # create demo data + train models
  python secureai_full.py --serve      # start dashboard
  python secureai_full.py --otp        # run OTP demo
"""

import os, sys, argparse, random, time
from pathlib import Path
import pandas as pd, numpy as np, joblib

# ML imports
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline

# Flask dashboard
from flask import Flask, jsonify, render_template_string

# OTP
try:
    import pyotp
except Exception:
    pyotp = None

ROOT = Path.cwd()
DATA = ROOT / "data"
MODELS = ROOT / "models"
DATA.mkdir(exist_ok=True)
MODELS.mkdir(exist_ok=True)

# -----------------------------------------------------
# 1) CREATE DEMO DATA
# -----------------------------------------------------
def create_demo_data():
    print("Creating demo data...")

    # IDS dataset
    ids_csv = DATA / "ids_demo.csv"
    if not ids_csv.exists():
        n = 500
        rng = np.random.RandomState(42)
        df = pd.DataFrame({
            "pkt_len": rng.normal(500, 100, n).astype(int).clip(40,1500),
            "src_port": rng.randint(1024, 65535, n),
            "dst_port": rng.choice([80,443,22,21,8080,3306,3389], n),
            "protocol": rng.choice([6,17], n),
            "tcp_flags": rng.randint(0,64,n),
            "duration": np.abs(rng.normal(1.0, 0.5, n)),
        })
        df["label"] = "normal"
        attacks = rng.choice(n, size=40, replace=False)
        df.loc[attacks, "pkt_len"] = rng.normal(1200,100,len(attacks)).astype(int)
        df.loc[attacks, "dst_port"] = rng.choice([4444,9999,12345], len(attacks))
        df.loc[attacks, "label"] = "attack"
        df.to_csv(ids_csv, index=False)
        print("  - IDS data created")

    # Email dataset
    emails_csv = DATA / "emails_demo.csv"
    if not emails_csv.exists():
        rows=[]
        safe = [
            ("Meeting","Schedule attached."),
            ("Invoice","Your invoice is attached."),
            ("Greetings","Hope you are well."),
        ]
        phish = [
            ("Account Suspended","Click here: http://fake.login"),
            ("Verify Now","Suspicious activity detected."),
        ]
        spear = [
            ("HR Request for John","Send your bank details."),
        ]
        for i in range(300):
            if i < 180:
                s,b = random.choice(safe); lab="safe"
            elif i < 240:
                s,b = random.choice(phish); lab="phishing"
            elif i < 270:
                s,b = random.choice(spear); lab="spear_phish"
            else:
                s,b=("Offer","Buy now!"); lab="spam"
            rows.append({"subject":s,"body":b,"label":lab})
        pd.DataFrame(rows).to_csv(emails_csv, index=False)
        print("  - Emails data created")

    # UBA: user behavior
    uba_csv = DATA / "user_logs_demo.csv"
    if not uba_csv.exists():
        rng = np.random.RandomState(1)
        users=["alice","bob","charlie","dave","eve"]
        rows=[]
        for u in users:
            for day in range(30):
                actions = rng.poisson(3)
                for a in range(actions):
                    rows.append({
                        "user_id":u,
                        "timestamp":f"2025-11-{(day%28)+1:02d} {rng.randint(6,23):02d}:00:00",
                        "action_type":rng.choice(["login","open","dl","ul"]),
                        "success_flag":rng.choice([0,1],p=[0.05,0.95])
                    })
        # Eve anomalies
        for i in range(10):
            rows.append({
                "user_id":"eve",
                "timestamp":f"2025-11-{i+1:02d} 02:00:00",
                "action_type":"download",
                "success_flag":1
            })
        pd.DataFrame(rows).to_csv(uba_csv, index=False)
        print("  - UBA data created")

    print("All demo data created.")

# -----------------------------------------------------
# 2) TRAIN MODELS
# -----------------------------------------------------
def train_all_models():
    print("Training models...")

    # IDS
    df = pd.read_csv(DATA / "ids_demo.csv")
    feat = ["pkt_len","src_port","dst_port","protocol","tcp_flags","duration"]
    X = df[feat]
    y = (df["label"]=="attack").astype(int)
    X_tr, X_te, y_tr, y_te = train_test_split(X,y,test_size=0.3)
    rf = RandomForestClassifier(n_estimators=100)
    rf.fit(X_tr, y_tr)
    iso = IsolationForest(contamination=0.05)
    iso.fit(X_tr)
    joblib.dump(rf, MODELS / "ids_rf.joblib")
    joblib.dump(iso, MODELS / "ids_iso.joblib")
    print("  - IDS models saved")

    # Phishing model
    emails = pd.read_csv(DATA / "emails_demo.csv")
    emails["text"] = emails["subject"] + " " + emails["body"]
    X = emails["text"]; y = emails["label"]
    X_tr, X_te, y_tr, y_te = train_test_split(X,y,test_size=0.25)
    pipe = Pipeline([("tfidf",TfidfVectorizer()),("clf",LogisticRegression(max_iter=1000))])
    pipe.fit(X_tr, y_tr)
    joblib.dump(pipe, MODELS / "phish.joblib")
    print("  - Phishing model saved")

    # UBA Isolation Forest
    udf = pd.read_csv(DATA / "user_logs_demo.csv", parse_dates=["timestamp"])
    udf["hour"] = udf["timestamp"].dt.hour
    agg = udf.groupby("user_id").agg({"action_type":"count","hour":["mean","std"]}).fillna(0)
    agg.columns=["count","mean","std"]
    uba_model = IsolationForest(contamination=0.05)
    uba_model.fit(agg.values)
    joblib.dump(uba_model, MODELS / "uba.joblib")
    agg.to_csv(MODELS / "uba_baseline.csv")
    print("  - UBA model saved")

    print("Training complete.")

# -----------------------------------------------------
# 3) DASHBOARD
# -----------------------------------------------------
def start_dashboard():
    app = Flask("SecureAI-Dashboard")

    rf = joblib.load(MODELS / "ids_rf.joblib")
    iso = joblib.load(MODELS / "ids_iso.joblib")
    phish = joblib.load(MODELS / "phish.joblib")
    uba = joblib.load(MODELS / "uba.joblib")
    uba_base = pd.read_csv(MODELS / "uba_baseline.csv", index_col=0)

    TEMPLATE = """
    <h1>SecureAI Dashboard</h1>
    <div>IDS Alerts: <b id='ids'>loading...</b></div>
    <div>Phishing Count: <b id='phish'>loading...</b></div>
    <div>Insider Threats: <b id='uba'>loading...</b></div>
    <script>
    async function load(){
       let r = await fetch("/api/status");
       let d = await r.json();
       ids.innerText=d.ids;
       phish.innerText=d.phish;
       uba.innerText=d.uba;
    }
    setInterval(load,2000); load();
    </script>
    """

    @app.route("/")
    def index():
        return TEMPLATE

    @app.route("/api/status")
    def status():
        out = {"ids":0,"phish":0,"uba":0}

        # IDS
        df = pd.read_csv(DATA / "ids_demo.csv").tail(10)
        feat=["pkt_len","src_port","dst_port","protocol","tcp_flags","duration"]
        preds_rf = rf.predict(df[feat])
        preds_iso = iso.predict(df[feat])
        alerts = sum(1 for r,i in zip(preds_rf,preds_iso) if r==1 or i==-1)
        out["ids"] = alerts

        # Phishing
        emails = pd.read_csv(DATA / "emails_demo.csv").tail(20)
        texts = (emails["subject"]+" "+emails["body"]).tolist()
        preds = phish.predict(texts)
        out["phish"] = dict(pd.Series(preds).value_counts())

        # UBA
        udf = pd.read_csv(DATA / "user_logs_demo.csv", parse_dates=["timestamp"])
        udf["hour"] = udf["timestamp"].dt.hour
        agg = udf.groupby("user_id").agg({"action_type":"count","hour":["mean","std"]}).fillna(0)
        agg.columns=["count","mean","std"]
        anomalies=0
        for row in agg.values:
            p = uba.predict([row])[0]
            if p==-1: anomalies+=1
        out["uba"] = anomalies

        return jsonify(out)

    print("Dashboard running at http://127.0.0.1:5000")
    app.run()

# -----------------------------------------------------
# 4) OTP (2FA) DEMO
# -----------------------------------------------------
def otp_demo():
    if pyotp is None:
        print("Install pyotp to use OTP demo: pip install pyotp")
        return

    secret = pyotp.random_base32()
    totp = pyotp.TOTP(secret)
    print("Secret:", secret)
    print("OTP:", totp.now())
    code = input("Enter OTP: ")

    if totp.verify(code):
        print("Correct! Access Granted ✔")
    else:
        print("Incorrect OTP ❌")

# -----------------------------------------------------
# MAIN LOGIC
# -----------------------------------------------------
def main():
    p = argparse.ArgumentParser()
    p.add_argument("--setup", action="store_true")
    p.add_argument("--serve", action="store_true")
    p.add_argument("--otp", action="store_true")
    args = p.parse_args()

    if args.setup:
        create_demo_data()
        train_all_models()
        return

    if args.serve:
        start_dashboard()
        return

    if args.otp:
        otp_demo()
        return

    print("Usage:")
    print("  python secureai_full.py --setup")
    print("  python secureai_full.py --serve")
    print("  python secureai_full.py --otp")

if __name__ == "__main__":
    main()
