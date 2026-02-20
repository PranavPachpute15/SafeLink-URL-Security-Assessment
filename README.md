# 🛡️ SafeLink — Hybrid AI-Powered URL Security Assessment Platform

> A production-grade cybersecurity tool combining **rule-based heuristics** and **Isolation Forest anomaly detection** to assess URLs across 5 security dimensions, with educational insights and personalized scan history.

---

## 📐 Architecture Overview

```
User Input (URL)
       │
       ▼
┌─────────────────────────────────────────────────────────────────┐
│                    FEATURE EXTRACTION ENGINE                     │
│                                                                  │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐          │
│  │ P1: URL      │  │ P2: Domain   │  │ P3: SSL/HTTPS│          │
│  │ Structure    │  │ Analysis     │  │ Validity     │          │
│  │ Analysis     │  │ (WHOIS)      │  │              │          │
│  └──────────────┘  └──────────────┘  └──────────────┘          │
│  ┌──────────────┐  ┌──────────────┐                             │
│  │ P4: Blacklist│  │ P5: Redirect │                             │
│  │ Check        │  │ Chain        │                             │
│  └──────────────┘  └──────────────┘                             │
└─────────────────────────┬───────────────────────────────────────┘
                          │  15-dim Feature Vector
              ┌───────────┴────────────┐
              │                        │
              ▼                        ▼
   ┌──────────────────┐    ┌──────────────────────┐
   │  RULE-BASED      │    │  ISOLATION FOREST     │
   │  HEURISTIC       │    │  ANOMALY DETECTION    │
   │  ENGINE          │    │  (sklearn)            │
   │                  │    │                       │
   │  Rule Score      │    │  ML Anomaly Score     │
   │  (0–100)         │    │  (0–100)              │
   └────────┬─────────┘    └──────────┬────────────┘
            │                         │
            └──────────┬──────────────┘
                       │
                       ▼
         ┌─────────────────────────┐
         │   HYBRID RISK SCORE     │
         │                         │
         │  Score = 0.6×Rule       │
         │        + 0.4×ML         │
         │                         │
         │  🟢 Safe (0–39)         │
         │  🟡 Suspicious (40–69)  │
         │  🔴 High Risk (70–100)  │
         └────────────┬────────────┘
                      │
          ┌───────────┴───────────┐
          │                       │
          ▼                       ▼
  ┌───────────────┐     ┌─────────────────────┐
  │  EDUCATIONAL  │     │  MySQL DATABASE      │
  │  EXPLANATION  │     │  (scan_history)      │
  │  ENGINE       │     │  Personalized        │
  └───────────────┘     │  Historical Tracking │
                        └─────────────────────┘
```

---

## 🗂️ File Structure

```
safelink/
├── app.py              ← Main Streamlit application (UI + routing)
├── scanner.py          ← 5-parameter URL security scanner
├── ml_model.py         ← Isolation Forest training & scoring engine
├── educational.py      ← Cybersecurity education content & insight generator
├── database.py         ← MySQL operations (users, scan history)
├── requirements.txt    ← Python dependencies
├── setup.sql           ← Database schema (auto-created on first run)
└── README.md           ← This file
```

---

## ⚙️ Setup Instructions

### Prerequisites
- Python 3.10+
- MySQL 8.0+ (running locally or remote)
- Google Colab or local machine

---

### Step 1 — Clone / Download

```bash
# Download all files to a folder named 'safelink'
mkdir safelink && cd safelink
```

---

### Step 2 — Install Dependencies

```bash
pip install -r requirements.txt
```

**For Google Colab:**
```python
!pip install streamlit scikit-learn pandas numpy mysql-connector-python \
             bcrypt requests tldextract python-whois pyngrok
```

---

### Step 3 — Configure MySQL

Open `database.py` and update the `DB_CONFIG`:

```python
DB_CONFIG = {
    "host":     "localhost",      # Your MySQL host
    "user":     "root",           # Your MySQL username
    "password": "your_password",  # Your MySQL password
    "database": "safelink_db",
    "port":     3306,
}
```

The database and tables are **auto-created** on first run. You can also run `setup.sql` manually:

```sql
mysql -u root -p < setup.sql
```

---

### Step 4 — Run the Application

**Local:**
```bash
streamlit run app.py
```

**Google Colab:**
```python
# Install pyngrok for tunneling
!pip install pyngrok

from pyngrok import ngrok
import subprocess, time, threading

def run_streamlit():
    subprocess.run(["streamlit", "run", "app.py",
                    "--server.port=8501",
                    "--server.headless=true"])

thread = threading.Thread(target=run_streamlit, daemon=True)
thread.start()
time.sleep(3)

tunnel = ngrok.connect(8501)
print(f"SafeLink URL: {tunnel.public_url}")
```

---

## 🔬 Security Parameters Explained

| # | Parameter | Method | Features Extracted |
|---|-----------|--------|--------------------|
| 1 | **URL Structure Analysis** | Regex + heuristics | length, subdomains, hyphens, encoded chars, phishing keywords, IP in URL, special chars |
| 2 | **Domain Analysis** | WHOIS lookup | domain age, registrar, creation date, expiry |
| 3 | **SSL/HTTPS Validity** | TLS socket check | certificate issuer, expiry days, self-signed detection |
| 4 | **Blacklist Check** | Hash-based DB lookup | blacklist match, threat source |
| 5 | **Redirect Chain Analysis** | HTTP session follow | hop count, cross-domain detection, HTTP↓HTTPS downgrade |

---

## 🤖 ML Model Details

| Property | Value |
|----------|-------|
| Algorithm | Isolation Forest (sklearn) |
| Training samples | 2,000 synthetic URLs |
| Feature dimensions | 15 |
| Contamination | 20% (estimated malicious rate) |
| n_estimators | 200 trees |
| Hybrid formula | `0.6 × Rule Score + 0.4 × ML Score` |
| Model persistence | `safelink_model.pkl` + `safelink_scaler.pkl` |

---

## 🗄️ Database Schema

### `users` table
| Column | Type | Description |
|--------|------|-------------|
| id | INT | Primary key |
| username | VARCHAR(50) | Unique username |
| email | VARCHAR(120) | Unique email |
| password_hash | VARCHAR(255) | bcrypt hash (12 rounds) |
| scan_count | INT | Lifetime scans performed |
| created_at | DATETIME | Registration timestamp |
| last_login | DATETIME | Last authentication |

### `scan_history` table
| Column | Type | Description |
|--------|------|-------------|
| user_id | INT | FK → users.id |
| url | TEXT | Full scanned URL |
| risk_score | FLOAT | Final hybrid score (0-100) |
| threat_level | VARCHAR | Safe / Suspicious / High Risk |
| rule_score | FLOAT | Rule-based sub-score |
| ml_anomaly_score | FLOAT | Isolation Forest sub-score |
| domain_age_days | INT | WHOIS-derived age |
| has_https / has_valid_ssl | BOOL | SSL indicators |
| is_blacklisted | BOOL | Blacklist match |
| redirect_count | INT | HTTP redirect hops |
| feature_vector | JSON | Full 15-dim ML input |
| triggered_rules | JSON | Activated rule descriptions |
| educational_tips | JSON | Insight titles shown |
| redirect_chain | JSON | Full hop-by-hop chain |

---

## 🔐 Security Design

- **Password hashing**: bcrypt with 12 rounds (industry standard)
- **Session management**: Streamlit session_state (server-side)
- **DB ownership**: All queries include `user_id` check (no cross-user data leakage)
- **SQL injection prevention**: Parameterized queries throughout
- **SSL validation**: Performed independently from HTTP requests

---

## 🚀 Future Extensions

| Feature | Description |
|---------|-------------|
| Google Safe Browsing API | Real-time blacklist via GSB v4 |
| VirusTotal Integration | 70+ AV engine comparison |
| Browser Extension | Chrome/Firefox SafeLink plugin |
| REST API | FastAPI wrapper for enterprise integration |
| Email Scanner | Detect phishing links in email bodies |
| QR Code Scanner | Decode and analyze QR code URLs |
| Threat Feed | Real-time IOC feeds (MISP, PhishTank) |
| Cloud Deployment | Docker + AWS/GCP deployment |

---

## 📊 Benchmark Comparison

| Feature | SafeLink | Google Safe Browsing | VirusTotal |
|---------|----------|---------------------|------------|
| Explainable Score | ✅ | ❌ | ❌ |
| AI Anomaly Detection | ✅ | ❌ | ❌ |
| Zero-day Detection | ✅ (ML) | ❌ | Partial |
| Educational Insights | ✅ | ❌ | ❌ |
| Personalized History | ✅ | ❌ | ❌ |
| Hybrid Scoring | ✅ | ❌ | ❌ |
| Free / Open | ✅ | API (limited) | API (limited) |

---

## 👥 System Workflow

```
1. User Registration/Login → bcrypt auth → MySQL session
2. URL Input → Normalization → Validation
3. Feature Extraction → 5 parameters → 15-dim vector
4. Rule Engine → Deterministic scoring → Weighted penalties
5. Isolation Forest → Anomaly score → is_anomaly flag
6. Hybrid Score → Threat classification (Safe/Suspicious/High Risk)
7. Educational Engine → Dynamic insights → User-friendly explanations
8. MySQL Storage → scan_history with user_id FK
9. Dashboard → Risk gauge + Feature breakdown + History chart
```

---

*SafeLink v1.0 — Hybrid AI URL Security Assessment Platform*
*Built with: Streamlit · scikit-learn · MySQL · Python*
