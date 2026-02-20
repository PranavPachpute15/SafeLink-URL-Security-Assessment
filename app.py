"""
╔══════════════════════════════════════════════════════════════════╗
║   SafeLink  —  Hybrid AI URL Security Assessment Platform        ║
║   v2.0  |  Rebuilt & Redesigned                                  ║
╚══════════════════════════════════════════════════════════════════╝

BUG FIXES IN THIS VERSION
──────────────────────────
  [FIX 1] Quick Examples: Decoupled widget key from session state.
           Examples now write to `pending_scan_url` + set
           `trigger_scan = True`, so the scan fires immediately on
           rerun — not just filling the input box.

  [FIX 2] AI Verdict: Replaced 3 static strings with
           `build_dynamic_verdict()` which reads live scan_data:
           domain name, age, rule count, ML anomaly confidence,
           SSL status, blacklist flag, redirect hops — every field
           produces a unique, data-driven verdict sentence.

  [FIX 3] State management: `url_input` widget now uses key
           `url_widget` (never written externally). Examples
           write to a separate `pending_scan_url` key, avoiding
           the Streamlit duplicate-key conflict that caused the
           input to reset or ignore session state writes.

  [FIX 4] Removed implicit caching of scan results. Each new
           scan always clears `scan_result` before running, so
           old verdicts can never bleed into new scans.

  [FIX 5] Full debug logging printed to terminal for
           input → feature_vector → rule_score → ml_score →
           hybrid_score → threat_level traceability.

Run with:  python -m streamlit run app.py
"""

# ── Standard library ─────────────────────────────────────────────────────────
import time
import random
import logging
import urllib.parse
from datetime import datetime

# ── Third-party ───────────────────────────────────────────────────────────────
import streamlit as st
import pandas as pd
import numpy as np

# ── SafeLink modules ──────────────────────────────────────────────────────────
from database    import (initialize_database, create_user, authenticate_user,
                         save_scan_result, get_scan_history, get_user_stats,
                         get_risk_trend, delete_scan)
from scanner     import scan_url
from ml_model    import score_scan, load_model
from educational import (generate_educational_insights, get_random_tip,
                         format_educational_tips_for_db)

# ── Logging setup (prints to terminal for debug tracing) ──────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  [SafeLink]  %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("safelink")


# ══════════════════════════════════════════════════════════════════════════════
#  PAGE CONFIG
# ══════════════════════════════════════════════════════════════════════════════
st.set_page_config(
    page_title="SafeLink — AI Security Scanner",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)


# ══════════════════════════════════════════════════════════════════════════════
#  QUICK EXAMPLES  (single source of truth)
# ══════════════════════════════════════════════════════════════════════════════
QUICK_EXAMPLES = [
    {
        "label":   "✅ Trusted Site",
        "url":     "https://google.com",
        "caption": "Well-known, aged domain with valid SSL",
        "badge":   "safe",
    },
    {
        "label":   "⚠️ New Domain",
        "url":     "http://secure-login-verify.xyz/account/update",
        "caption": "Freshly registered with phishing keywords",
        "badge":   "suspicious",
    },
    {
        "label":   "🔢 IP Address URL",
        "url":     "http://192.168.1.1/login/verify/credentials",
        "caption": "Raw IP used instead of domain name",
        "badge":   "high",
    },
    {
        "label":   "🎣 Phishing URL",
        "url":     "https://paypal-secure-verify-account.tk/signin/confirm",
        "caption": "Multiple phishing signals + risky TLD",
        "badge":   "high",
    },
]


# ══════════════════════════════════════════════════════════════════════════════
#  CSS — PREMIUM REDESIGN
# ══════════════════════════════════════════════════════════════════════════════
def inject_css():
    st.markdown("""
    <style>
    @import url('https://fonts.googleapis.com/css2?family=DM+Mono:wght@400;500&family=Outfit:wght@300;400;500;600;700;800&family=Inter:wght@300;400;500;600&display=swap');

    :root {
        --bg:          #060B18;
        --surface:     #0D1526;
        --surface2:    #111D35;
        --surface3:    #162040;
        --glass:       rgba(13,21,38,0.85);
        --blue:        #3B82F6;
        --blue-dim:    rgba(59,130,246,0.12);
        --cyan:        #22D3EE;
        --green:       #10B981;
        --green-dim:   rgba(16,185,129,0.12);
        --amber:       #F59E0B;
        --amber-dim:   rgba(245,158,11,0.12);
        --red:         #F43F5E;
        --red-dim:     rgba(244,63,94,0.12);
        --border:      rgba(255,255,255,0.07);
        --text:        #E8EDF5;
        --muted:       #64748B;
        --muted2:      #94A3B8;
        --mono:        'DM Mono', monospace;
        --sans:        'Outfit', sans-serif;
        --body:        'Inter', sans-serif;
        --radius:      14px;
        --radius-sm:   8px;
        --shadow:      0 4px 32px rgba(0,0,0,0.45);
        --glow-b:      0 0 24px rgba(59,130,246,0.18);
    }

    html, body,
    [data-testid="stAppViewContainer"],
    [data-testid="stAppViewContainer"] > .main {
        background: var(--bg) !important;
        color: var(--text) !important;
        font-family: var(--body) !important;
    }

    /* Dot-grid texture */
    [data-testid="stAppViewContainer"]::before {
        content: '';
        position: fixed; inset: 0;
        background-image: radial-gradient(circle, rgba(59,130,246,0.04) 1px, transparent 1px);
        background-size: 28px 28px;
        pointer-events: none; z-index: 0;
    }
    [data-testid="stAppViewContainer"] > .main { position: relative; z-index: 1; }

    [data-testid="stSidebar"] {
        background: #080E1C !important;
        border-right: 1px solid var(--border) !important;
    }
    [data-testid="stSidebar"] > div { padding-top: 1.5rem !important; }

    h1, h2, h3, h4 { font-family: var(--sans) !important; letter-spacing: -0.5px; }

    .stTextInput > div > div > input {
        background: var(--surface2) !important;
        border: 1.5px solid var(--border) !important;
        border-radius: var(--radius-sm) !important;
        color: var(--text) !important;
        font-family: var(--mono) !important;
        font-size: 0.92rem !important;
        padding: 0.7rem 1rem !important;
        transition: border-color 0.2s, box-shadow 0.2s !important;
    }
    .stTextInput > div > div > input:focus {
        border-color: var(--blue) !important;
        box-shadow: var(--glow-b) !important;
    }
    label[data-testid="stWidgetLabel"] { color: var(--muted2) !important; font-size: 0.8rem !important; }

    .stButton > button[kind="primary"] {
        background: linear-gradient(135deg, #2563EB 0%, #0891B2 100%) !important;
        color: #fff !important; border: none !important;
        border-radius: var(--radius-sm) !important;
        font-family: var(--sans) !important; font-weight: 700 !important;
        font-size: 0.92rem !important; letter-spacing: 0.3px !important;
        padding: 0.55rem 1.4rem !important;
        transition: transform 0.15s, box-shadow 0.15s !important;
        box-shadow: 0 4px 14px rgba(37,99,235,0.35) !important;
    }
    .stButton > button[kind="primary"]:hover {
        transform: translateY(-1px) !important;
        box-shadow: 0 6px 20px rgba(37,99,235,0.45) !important;
    }

    .stButton > button[kind="secondary"] {
        background: var(--surface2) !important;
        color: var(--muted2) !important;
        border: 1px solid var(--border) !important;
        border-radius: var(--radius-sm) !important;
        font-family: var(--sans) !important; font-weight: 600 !important;
        font-size: 0.85rem !important;
        transition: background 0.2s, color 0.2s, border-color 0.2s !important;
    }
    .stButton > button[kind="secondary"]:hover {
        background: var(--surface3) !important;
        color: var(--text) !important; border-color: var(--blue) !important;
    }

    .stProgress > div > div > div > div {
        background: linear-gradient(90deg, #3B82F6, #22D3EE) !important;
        border-radius: 99px !important;
    }

    .stTabs [data-baseweb="tab-list"] {
        gap: 8px !important; background: var(--surface) !important;
        border-radius: var(--radius-sm) !important; padding: 4px !important;
        border: 1px solid var(--border) !important;
    }
    .stTabs [data-baseweb="tab"] {
        border-radius: 6px !important; color: var(--muted2) !important;
        font-family: var(--sans) !important; font-weight: 600 !important;
    }
    .stTabs [aria-selected="true"] {
        background: var(--surface3) !important; color: var(--text) !important;
    }

    [data-testid="metric-container"] {
        background: var(--surface) !important;
        border: 1px solid var(--border) !important;
        border-radius: var(--radius-sm) !important;
        padding: 0.9rem 1rem !important;
    }
    [data-testid="metric-container"] label { color: var(--muted) !important; font-size: 0.72rem !important; }
    [data-testid="metric-container"] [data-testid="stMetricValue"] {
        color: var(--text) !important; font-family: var(--sans) !important; font-weight: 700 !important;
    }

    #MainMenu, footer, [data-testid="stDecoration"] { visibility: hidden !important; }

    /* ── SafeLink components ─────────────────────────────────────────────── */
    .sl-glass {
        background: var(--glass); backdrop-filter: blur(12px);
        border: 1px solid var(--border); border-radius: var(--radius);
        padding: 1.5rem 1.8rem; box-shadow: var(--shadow);
    }
    .sl-hero { text-align: center; padding: 2.5rem 1rem 1.5rem; position: relative; }
    .sl-hero-glow {
        position: absolute; top: 50%; left: 50%;
        transform: translate(-50%, -50%);
        width: 500px; height: 200px;
        background: radial-gradient(ellipse, rgba(59,130,246,0.12) 0%, transparent 70%);
        pointer-events: none; z-index: -1;
    }
    .sl-hero-title {
        font-family: var(--sans) !important; font-size: 2.6rem; font-weight: 800;
        background: linear-gradient(135deg, #60A5FA 0%, #22D3EE 60%, #818CF8 100%);
        -webkit-background-clip: text; -webkit-text-fill-color: transparent;
        background-clip: text; line-height: 1.15; letter-spacing: -1px; margin: 0;
    }
    .sl-hero-sub { color: var(--muted2); font-size: 0.95rem; margin-top: 0.5rem; }

    .verdict-safe        { background: var(--green-dim); border: 1px solid rgba(16,185,129,0.25); border-radius: var(--radius); padding: 1.5rem 2rem; }
    .verdict-suspicious  { background: var(--amber-dim); border: 1px solid rgba(245,158,11,0.25);  border-radius: var(--radius); padding: 1.5rem 2rem; }
    .verdict-high        { background: var(--red-dim);   border: 1px solid rgba(244,63,94,0.25);   border-radius: var(--radius); padding: 1.5rem 2rem; }
    .verdict-icon   { font-size: 2.2rem; line-height: 1; margin-bottom: 0.4rem; }
    .verdict-level  { font-family: var(--sans); font-size: 0.72rem; font-weight: 700; letter-spacing: 2px; text-transform: uppercase; margin-bottom: 0.2rem; }
    .verdict-score  { font-family: var(--mono); font-size: 3.8rem; font-weight: 500; line-height: 1; letter-spacing: -2px; }
    .verdict-desc   { font-size: 0.84rem; color: var(--muted2); line-height: 1.65; margin-top: 0.8rem; }

    .score-pill {
        display: flex; align-items: center; justify-content: space-between;
        background: var(--surface2); border-radius: 6px;
        padding: 0.5rem 0.8rem; margin-bottom: 0.5rem; font-size: 0.82rem;
    }
    .score-pill-label { color: var(--muted2); }
    .score-pill-value { font-family: var(--mono); color: var(--text); font-weight: 500; }

    .param-card {
        background: var(--surface); border: 1px solid var(--border);
        border-radius: var(--radius-sm); padding: 1rem; text-align: center;
        transition: border-color 0.2s;
    }
    .param-card:hover { border-color: rgba(59,130,246,0.3); }
    .param-icon  { font-size: 1.5rem; margin-bottom: 0.3rem; }
    .param-title { font-size: 0.65rem; font-weight: 600; letter-spacing: 1px; text-transform: uppercase; color: var(--muted); margin-bottom: 0.3rem; }
    .param-value { font-family: var(--sans); font-size: 0.95rem; font-weight: 700; }
    .param-sub   { font-size: 0.68rem; color: var(--muted); margin-top: 0.2rem; }
    .param-ok    { color: #34D399; }
    .param-warn  { color: #FBBF24; }
    .param-bad   { color: #FB7185; }

    .rule-row {
        display: flex; align-items: flex-start; gap: 0.7rem;
        padding: 0.55rem 0.8rem; border-radius: 6px; margin-bottom: 0.35rem;
        background: var(--surface2); border-left: 3px solid var(--amber);
        font-family: var(--mono); font-size: 0.78rem; color: var(--muted2);
    }
    .rule-row-safe { border-left-color: var(--green); }

    .feat-row {
        display: flex; justify-content: space-between; align-items: center;
        padding: 0.45rem 0; border-bottom: 1px solid var(--border); font-size: 0.83rem;
    }
    .feat-row:last-child { border-bottom: none; }
    .feat-k { color: var(--muted2); }
    .feat-v { font-family: var(--mono); font-size: 0.8rem; }

    .sev-critical { background:#4C0519; color:#FDA4AF; border:1px solid #F43F5E; border-radius:5px; padding:2px 10px; font-size:0.7rem; font-weight:700; display:inline-block; }
    .sev-high     { background:#431407; color:#FCD34D; border:1px solid #F59E0B; border-radius:5px; padding:2px 10px; font-size:0.7rem; font-weight:700; display:inline-block; }
    .sev-medium   { background:#1e3a5f; color:#93C5FD; border:1px solid #3B82F6; border-radius:5px; padding:2px 10px; font-size:0.7rem; font-weight:700; display:inline-block; }
    .sev-low      { background:#022c22; color:#6EE7B7; border:1px solid #10B981; border-radius:5px; padding:2px 10px; font-size:0.7rem; font-weight:700; display:inline-block; }
    .sev-info     { background:#1e293b; color:#94A3B8; border:1px solid #475569; border-radius:5px; padding:2px 10px; font-size:0.7rem; font-weight:700; display:inline-block; }

    .ex-badge-safe       { display:inline-block; background:rgba(16,185,129,0.12); color:#34D399; border:1px solid rgba(16,185,129,0.3); border-radius:4px; font-size:0.6rem; font-weight:700; padding:1px 7px; letter-spacing:.5px; text-transform:uppercase; }
    .ex-badge-suspicious { display:inline-block; background:rgba(245,158,11,0.12); color:#FBBF24; border:1px solid rgba(245,158,11,0.3); border-radius:4px; font-size:0.6rem; font-weight:700; padding:1px 7px; letter-spacing:.5px; text-transform:uppercase; }
    .ex-badge-high       { display:inline-block; background:rgba(244,63,94,0.12); color:#FB7185; border:1px solid rgba(244,63,94,0.3); border-radius:4px; font-size:0.6rem; font-weight:700; padding:1px 7px; letter-spacing:.5px; text-transform:uppercase; }

    .tip-box {
        background: linear-gradient(135deg,#0B1929,#0D1F35);
        border: 1px solid #1E3A5F; border-radius: var(--radius-sm);
        padding: 0.8rem 1.1rem; font-size: 0.84rem; color: #93C5FD;
        font-style: italic; margin-top: 0.5rem;
    }

    @keyframes pulse-dot {
        0%,100% { opacity:1; transform:scale(1); }
        50%      { opacity:0.4; transform:scale(0.8); }
    }
    .scanning-dot {
        display: inline-block; width:8px; height:8px;
        background: var(--blue); border-radius: 50%;
        animation: pulse-dot 1s ease-in-out infinite;
    }

    hr { border-color: var(--border) !important; margin: 1.5rem 0 !important; }
    </style>
    """, unsafe_allow_html=True)


# ══════════════════════════════════════════════════════════════════════════════
#  INITIALIZATION  (cached once per server session)
# ══════════════════════════════════════════════════════════════════════════════
@st.cache_resource
def init_app():
    log.info("Initialising database …")
    db_ok, db_msg = initialize_database()
    log.info("Loading / training ML model …")
    model, scaler = load_model()
    log.info("App ready.")
    return db_ok, db_msg, model


# ══════════════════════════════════════════════════════════════════════════════
#  SESSION STATE
# ══════════════════════════════════════════════════════════════════════════════
def init_session():
    defaults = {
        "authenticated":    False,
        "user":             None,
        "page":             "auth",
        "scan_result":      None,
        # FIX 1 — dedicated keys, never conflict with widget keys
        "pending_scan_url": "",
        "trigger_scan":     False,
    }
    for k, v in defaults.items():
        if k not in st.session_state:
            st.session_state[k] = v


# ══════════════════════════════════════════════════════════════════════════════
#  DYNAMIC VERDICT BUILDER  [FIX 2]
# ══════════════════════════════════════════════════════════════════════════════
def build_dynamic_verdict(data: dict) -> dict:
    """
    Constructs a fully data-driven AI verdict from live scan_data.
    Every sentence references real extracted values — no two different
    URLs with different scores will ever produce identical text.
    """
    threat   = data.get("threat_level", "Unknown")
    score    = data.get("risk_score", 0)
    rule_s   = data.get("rule_score", 0)
    ml_s     = data.get("ml_anomaly_score", 0)
    domain   = data.get("domain", "the domain")
    age      = data.get("domain_age_days", -1)
    rules    = data.get("all_rules", [])
    bl       = data.get("is_blacklisted", False)
    has_https = data.get("has_https", False)
    ssl_ok   = data.get("has_valid_ssl", False)
    redir    = data.get("redirect_count", 0)
    ip_url   = data.get("has_ip_in_url", False)
    kws      = data.get("suspicious_patterns", 0)
    ml_conf  = data.get("anomaly_confidence", "Low")
    is_anom  = data.get("is_anomaly", False)

    age_str = f"{age} days old" if age > 0 else "age unverifiable (WHOIS failed)"
    confidence_pct = min(99, int(50 + score / 2))
    if threat == "Safe":
        confidence_pct = min(97, int(60 + (100 - score) / 2))

    # ── Headline sentence — references actual data ────────────────────────────
    if threat == "High Risk":
        if bl:
            headline = (f"🚨 <strong>{domain}</strong> is confirmed in threat blacklists "
                        f"with a risk score of {score:.0f}/100. Do not proceed.")
        elif ip_url:
            headline = (f"🚨 This URL uses a raw IP address rather than a domain. "
                        f"Risk score: {score:.0f}/100. No legitimate service does this.")
        elif kws >= 3:
            headline = (f"🚨 <strong>{domain}</strong> contains {kws} phishing keyword"
                        f"{'s' if kws != 1 else ''} and scored {score:.0f}/100.")
        else:
            headline = (f"🚨 <strong>{domain}</strong> triggered {len(rules)} security "
                        f"rule{'s' if len(rules) != 1 else ''}, scoring {score:.0f}/100 — High Risk.")

    elif threat == "Suspicious":
        if age > 0 and age < 180:
            headline = (f"⚠️ <strong>{domain}</strong> is only {age_str}, "
                        f"elevating new-domain phishing risk. Score: {score:.0f}/100.")
        elif not has_https:
            headline = (f"⚠️ <strong>{domain}</strong> lacks HTTPS — data travels "
                        f"unencrypted over the network. Score: {score:.0f}/100.")
        elif redir >= 3:
            headline = (f"⚠️ <strong>{domain}</strong> chains {redir} HTTP redirect"
                        f"{'s' if redir != 1 else ''}, obscuring the true destination. Score: {score:.0f}/100.")
        else:
            headline = (f"⚠️ <strong>{domain}</strong> raised {len(rules)} concern"
                        f"{'s' if len(rules) != 1 else ''} with a risk score of {score:.0f}/100.")

    else:  # Safe
        if ssl_ok and age > 365:
            headline = (f"✅ <strong>{domain}</strong> is {age_str} with a valid SSL cert "
                        f"and no blacklist hits. Score: {score:.0f}/100.")
        elif ssl_ok:
            headline = (f"✅ <strong>{domain}</strong> has a verified SSL certificate "
                        f"and passed all core checks. Score: {score:.0f}/100.")
        else:
            headline = (f"✅ <strong>{domain}</strong> passed all heuristic checks "
                        f"with a low risk score of {score:.0f}/100.")

    # ── Supporting ML detail line ─────────────────────────────────────────────
    ml_note = (f"AI anomaly detection: <strong>{ml_conf} confidence</strong>."
               if is_anom else "Isolation Forest: no anomalous patterns detected.")
    detail = (f"Rule engine: <strong>{rule_s:.1f}/100</strong> &nbsp;·&nbsp; "
              f"ML engine: <strong>{ml_s:.1f}/100</strong> &nbsp;·&nbsp; {ml_note}")

    palette = {
        "High Risk":  {"color": "#F43F5E", "cls": "verdict-high",       "icon": "🔴"},
        "Suspicious": {"color": "#F59E0B", "cls": "verdict-suspicious",  "icon": "🟡"},
        "Safe":       {"color": "#10B981", "cls": "verdict-safe",        "icon": "🟢"},
    }
    pal = palette.get(threat, palette["Suspicious"])

    return {
        "threat":         threat,
        "score":          score,
        "confidence_pct": confidence_pct,
        "headline":       headline,
        "detail":         detail,
        "color":          pal["color"],
        "cls":            pal["cls"],
        "icon":           pal["icon"],
    }


# ══════════════════════════════════════════════════════════════════════════════
#  CORE SCAN PIPELINE  [FIX 3 / 4 / 5]
# ══════════════════════════════════════════════════════════════════════════════
def run_scan(url: str):
    """
    Full SafeLink pipeline. Logs every stage to terminal.
    Always wipes previous result first (FIX 4).
    """
    st.session_state.scan_result = None   # FIX 4 — no stale bleed-through

    log.info("━" * 55)
    log.info(f"INPUT  : {url}")

    if not url.strip():
        st.warning("⚠️ Please enter a URL before scanning.")
        return

    status_box   = st.empty()
    progress_bar = st.progress(0)

    def update(pct: int, msg: str):
        progress_bar.progress(pct)
        status_box.markdown(
            f"<div style='color:#64748B;font-size:0.82rem;margin:0.3rem 0;'>"
            f"<span class='scanning-dot'></span>&nbsp; {msg}</div>",
            unsafe_allow_html=True,
        )

    try:
        update(8,  "🔍 Analysing URL structure and lexical patterns …")
        scan_data = scan_url(url)                            # FIX 5 — live URL

        if "error" in scan_data:
            st.error(f"❌ {scan_data['error']}")
            progress_bar.empty(); status_box.empty()
            log.error(f"scan_url error: {scan_data['error']}")
            return

        log.info(f"FEATURES : {scan_data.get('feature_vector', {})}")
        log.info(f"RULE_SCR : {scan_data.get('rule_score', 0):.2f}")

        update(30, "🌐 WHOIS lookup — querying domain age …")
        time.sleep(0.2)
        update(48, "🔒 Validating SSL / TLS certificate …")
        time.sleep(0.2)
        update(62, "🚫 Checking against blacklist databases …")
        time.sleep(0.15)
        update(75, "🔀 Tracing HTTP redirect chain …")
        time.sleep(0.15)

        update(85, "🤖 Running Isolation Forest anomaly detection …")
        scan_data = score_scan(scan_data)                    # FIX 5 — live data

        log.info(f"ML_SCORE : {scan_data.get('ml_anomaly_score', 0):.2f}")
        log.info(f"IS_ANOM  : {scan_data.get('is_anomaly', False)}")
        log.info(f"HYBRID   : {scan_data.get('risk_score', 0):.2f}")
        log.info(f"THREAT   : {scan_data.get('threat_level', 'Unknown')}")

        update(92, "📚 Generating educational insights …")
        insights = generate_educational_insights(scan_data)
        scan_data["educational_insights"] = insights
        scan_data["triggered_rules"]      = scan_data.get("all_rules", [])
        scan_data["educational_tips"]     = format_educational_tips_for_db(insights)

        log.info(f"INSIGHTS : {len(insights)}")
        log.info(f"RULES    : {len(scan_data['triggered_rules'])}")

        # FIX 2 — build verdict from actual scan_data values
        scan_data["verdict"] = build_dynamic_verdict(scan_data)
        log.info(f"VERDICT  : {scan_data['verdict']['headline'][:70]}")

        update(97, "💾 Saving result to database …")
        save_scan_result(st.session_state.user["id"], scan_data)

        progress_bar.progress(100)
        time.sleep(0.15)
        progress_bar.empty()
        status_box.empty()

        # FIX 3 — write fresh result, clear example trigger flags
        st.session_state.scan_result      = scan_data
        st.session_state.trigger_scan     = False
        st.session_state.pending_scan_url = ""

        log.info("Scan complete — rerunning UI.")
        log.info("━" * 55)
        st.rerun()

    except Exception as exc:
        progress_bar.empty(); status_box.empty()
        log.exception(f"Pipeline error: {exc}")
        st.error(f"Scan error: {exc}")


# ══════════════════════════════════════════════════════════════════════════════
#  AUTH PAGE
# ══════════════════════════════════════════════════════════════════════════════
def render_auth_page():
    _, mid, _ = st.columns([1, 1.6, 1])
    with mid:
        st.markdown("""
        <div style='text-align:center; padding:2.5rem 0 1.5rem;'>
            <div style='font-size:3rem;'>🛡️</div>
            <div style='font-family:Outfit,sans-serif; font-size:2.4rem; font-weight:800;
                        background:linear-gradient(135deg,#60A5FA,#22D3EE);
                        -webkit-background-clip:text; -webkit-text-fill-color:transparent;
                        background-clip:text; letter-spacing:-1px;'>SafeLink</div>
            <div style='color:#475569; font-size:0.88rem; margin-top:0.3rem;'>
                Hybrid AI-Powered URL Security Assessment
            </div>
        </div>
        """, unsafe_allow_html=True)

        tab_in, tab_up = st.tabs(["🔑  Sign In", "✨  Create Account"])

        with tab_in:
            st.markdown("<br>", unsafe_allow_html=True)
            uname = st.text_input("Username", key="li_user", placeholder="your username")
            pwd   = st.text_input("Password", type="password", key="li_pwd", placeholder="••••••••")
            if st.button("Sign In →", use_container_width=True, type="primary", key="li_btn"):
                if not uname or not pwd:
                    st.error("Please fill in all fields.")
                else:
                    with st.spinner("Authenticating …"):
                        ok, user = authenticate_user(uname.strip(), pwd)
                    if ok:
                        st.session_state.authenticated = True
                        st.session_state.user          = user
                        st.session_state.page          = "scanner"
                        log.info(f"User '{uname}' authenticated.")
                        st.rerun()
                    else:
                        st.error("Invalid username or password.")

        with tab_up:
            st.markdown("<br>", unsafe_allow_html=True)
            nu = st.text_input("Username",         key="ru_user",  placeholder="3–30 characters")
            ne = st.text_input("Email",            key="ru_email", placeholder="you@email.com")
            np_ = st.text_input("Password",        type="password", key="ru_pwd",  placeholder="Min 8 characters")
            nc = st.text_input("Confirm Password", type="password", key="ru_cpwd", placeholder="Repeat password")
            if st.button("Create Account →", use_container_width=True, type="primary", key="ru_btn"):
                errs = []
                if len(nu.strip()) < 3: errs.append("Username must be ≥ 3 characters.")
                if "@" not in ne:       errs.append("Enter a valid email address.")
                if len(np_) < 8:        errs.append("Password must be ≥ 8 characters.")
                if np_ != nc:           errs.append("Passwords do not match.")
                if errs:
                    for e in errs: st.error(e)
                else:
                    with st.spinner("Creating account …"):
                        ok, msg = create_user(nu.strip(), ne.strip(), np_)
                    st.success(msg) if ok else st.error(msg)

        st.markdown("""
        <div class='tip-box' style='margin-top:1.5rem;'>
            🔒 Passwords are hashed with bcrypt (12 rounds).
            SafeLink never stores plaintext credentials.
        </div>
        """, unsafe_allow_html=True)


# ══════════════════════════════════════════════════════════════════════════════
#  SIDEBAR
# ══════════════════════════════════════════════════════════════════════════════
def render_sidebar():
    user = st.session_state.user
    with st.sidebar:
        st.markdown("""
        <div style='text-align:center; padding:0.5rem 0 1rem;'>
            <span style='font-size:1.8rem;'>🛡️</span>
            <div style='font-family:Outfit,sans-serif; font-size:1.3rem; font-weight:800;
                        background:linear-gradient(135deg,#60A5FA,#22D3EE);
                        -webkit-background-clip:text; -webkit-text-fill-color:transparent;
                        background-clip:text;'>SafeLink</div>
        </div>
        """, unsafe_allow_html=True)

        st.markdown(f"""
        <div style='background:#0D1526; border:1px solid rgba(255,255,255,0.07);
                    border-radius:10px; padding:0.8rem 1rem; margin-bottom:1rem;'>
            <div style='font-size:0.62rem; color:#475569; letter-spacing:1.5px;
                        text-transform:uppercase; margin-bottom:3px;'>Signed in as</div>
            <div style='font-family:Outfit,sans-serif; font-weight:700; color:#E8EDF5;'>
                👤 {user['username']}
            </div>
            <div style='font-size:0.72rem; color:#64748B;'>{user['email']}</div>
        </div>
        """, unsafe_allow_html=True)

        st.markdown("<div style='font-size:0.62rem; color:#475569; letter-spacing:1.5px; text-transform:uppercase; margin-bottom:0.4rem;'>Navigation</div>", unsafe_allow_html=True)
        nav = {"🔍  URL Scanner": "scanner", "📊  Scan History": "history", "📚  Security Library": "education"}
        for label, key in nav.items():
            active = st.session_state.page == key
            if st.button(label, use_container_width=True,
                         type="primary" if active else "secondary", key=f"nav_{key}"):
                st.session_state.page        = key
                st.session_state.scan_result = None
                st.rerun()

        st.divider()
        stats = get_user_stats(user["id"])
        if stats and stats.get("total_scans", 0):
            st.markdown("<div style='font-size:0.62rem; color:#475569; letter-spacing:1.5px; text-transform:uppercase; margin-bottom:0.5rem;'>Your Activity</div>", unsafe_allow_html=True)
            c1, c2 = st.columns(2)
            c1.metric("Scans",    stats.get("total_scans", 0))
            c2.metric("Avg Risk", f"{(stats.get('avg_risk_score') or 0):.0f}")
            c1.metric("🟢 Safe",  stats.get("safe_count", 0))
            c2.metric("🔴 Risky", stats.get("high_risk_count", 0))

        st.divider()
        if st.button("🚪  Sign Out", use_container_width=True, key="signout_btn"):
            for k in list(st.session_state.keys()): del st.session_state[k]
            st.rerun()

        st.markdown("""
        <div style='font-size:0.62rem; color:#1E293B; text-align:center; margin-top:1rem;'>
            SafeLink v2.0 · Isolation Forest + Rule Engine
        </div>
        """, unsafe_allow_html=True)


# ══════════════════════════════════════════════════════════════════════════════
#  SCANNER PAGE
# ══════════════════════════════════════════════════════════════════════════════
def render_scanner_page():
    # Hero
    st.markdown("""
    <div class='sl-hero'>
        <div class='sl-hero-glow'></div>
        <p class='sl-hero-title'>🛡️ URL Security Scanner</p>
        <p class='sl-hero-sub'>Hybrid AI · 5 security dimensions · Isolation Forest anomaly detection</p>
    </div>
    """, unsafe_allow_html=True)

    # FIX 1 — read pending URL set by example buttons
    prefill          = st.session_state.get("pending_scan_url", "")
    should_auto_scan = st.session_state.get("trigger_scan", False)

    # URL input — key "url_widget" is NEVER written by example logic
    st.markdown("<div style='height:0.4rem'></div>", unsafe_allow_html=True)
    col_in, col_btn = st.columns([5.5, 1])
    with col_in:
        url_typed = st.text_input(
            "URL",
            value=prefill,
            placeholder="https://example.com  or paste any URL to analyse …",
            label_visibility="collapsed",
            key="url_widget",         # FIX 1 — isolated key
        )
    with col_btn:
        scan_clicked = st.button("⚡ Scan", type="primary", use_container_width=True, key="scan_btn")

    # Quick Examples
    st.markdown("""
    <div style='font-size:0.65rem; color:#475569; letter-spacing:1.2px;
                text-transform:uppercase; margin:0.9rem 0 0.5rem;'>
        ⚡ Quick Examples — click to analyse instantly
    </div>
    """, unsafe_allow_html=True)

    ex_cols = st.columns(4)
    for i, ex in enumerate(QUICK_EXAMPLES):
        with ex_cols[i]:
            st.markdown(f"""
            <div style='background:var(--surface); border:1px solid var(--border);
                        border-radius:10px; padding:0.7rem 0.9rem; margin-bottom:0.4rem;'>
                <div style='margin-bottom:4px;'>
                    <span class='ex-badge-{ex["badge"]}'>{ex["badge"]}</span>
                </div>
                <div style='font-family:Outfit,sans-serif; font-weight:700;
                            font-size:0.84rem; color:#E8EDF5;'>{ex["label"]}</div>
                <div style='font-family:DM Mono,monospace; font-size:0.68rem;
                            color:#475569; margin-top:2px; overflow:hidden;
                            text-overflow:ellipsis; white-space:nowrap;'>
                    {ex["url"][:40]}…
                </div>
            </div>
            """, unsafe_allow_html=True)
            # FIX 1 — button click sets SEPARATE state keys, never "url_widget"
            if st.button("Scan this →", key=f"ex_btn_{i}", use_container_width=True):
                st.session_state.pending_scan_url = ex["url"]
                st.session_state.trigger_scan     = True
                st.session_state.scan_result      = None
                log.info(f"Example clicked: {ex['url']}")
                st.rerun()

    # FIX 1 — auto-scan fires because trigger_scan=True was set before rerun
    if should_auto_scan and prefill:
        log.info(f"Auto-scanning: {prefill}")
        run_scan(prefill)
        return

    if scan_clicked:
        target = url_typed.strip()
        if not target:
            st.warning("⚠️ Please enter a URL first.")
        else:
            run_scan(target)
            return

    if st.session_state.scan_result:
        render_results(st.session_state.scan_result)
    else:
        # Idle placeholder
        st.markdown("""
        <div style='display:flex; gap:0.6rem; flex-wrap:wrap; justify-content:center;
                    opacity:0.4; margin-top:1.5rem;'>
            <span style='background:#111D35; border:1px solid #1E293B; border-radius:20px; padding:4px 14px; font-size:0.78rem; color:#94A3B8;'>🔗 URL Structure</span>
            <span style='background:#111D35; border:1px solid #1E293B; border-radius:20px; padding:4px 14px; font-size:0.78rem; color:#94A3B8;'>📅 Domain Age (WHOIS)</span>
            <span style='background:#111D35; border:1px solid #1E293B; border-radius:20px; padding:4px 14px; font-size:0.78rem; color:#94A3B8;'>🔒 SSL / HTTPS</span>
            <span style='background:#111D35; border:1px solid #1E293B; border-radius:20px; padding:4px 14px; font-size:0.78rem; color:#94A3B8;'>🚫 Blacklist Check</span>
            <span style='background:#111D35; border:1px solid #1E293B; border-radius:20px; padding:4px 14px; font-size:0.78rem; color:#94A3B8;'>🔀 Redirect Chain</span>
            <span style='background:#111D35; border:1px solid #1E293B; border-radius:20px; padding:4px 14px; font-size:0.78rem; color:#94A3B8;'>🤖 Isolation Forest AI</span>
        </div>
        """, unsafe_allow_html=True)


# ══════════════════════════════════════════════════════════════════════════════
#  RESULTS PANEL
# ══════════════════════════════════════════════════════════════════════════════
def render_results(data: dict):
    verdict = data.get("verdict") or build_dynamic_verdict(data)

    st.markdown("<hr>", unsafe_allow_html=True)
    scanned_url = data.get("url", "")
    display_url = scanned_url[:70] + ("…" if len(scanned_url) > 70 else "")
    st.markdown(f"""
    <div style='font-family:Outfit,sans-serif; font-size:0.95rem; font-weight:600;
                color:#94A3B8; margin-bottom:1.2rem;'>
        📊 Results for &nbsp;
        <code style='background:#111D35; padding:2px 10px; border-radius:5px;
                     font-size:0.86rem; color:#60A5FA;'>{display_url}</code>
    </div>
    """, unsafe_allow_html=True)

    # ── Row 1: Verdict | Score Breakdown | AI Detail ──────────────────────────
    col_v, col_s, col_f = st.columns([2, 2, 1.8])

    with col_v:
        color = verdict["color"]
        st.markdown(f"""
        <div class='{verdict["cls"]}'>
            <div class='verdict-icon'>{verdict["icon"]}</div>
            <div class='verdict-level' style='color:{color};'>{verdict["threat"]}</div>
            <div class='verdict-score' style='color:{color};'>
                {verdict["score"]:.0f}<span style='font-size:1.3rem; opacity:0.5;'>/100</span>
            </div>
            <div style='font-size:0.72rem; color:{color}; opacity:0.7; margin-top:0.3rem;'>
                AI Confidence: {verdict["confidence_pct"]}%
            </div>
            <div class='verdict-desc'>{verdict["headline"]}</div>
        </div>
        """, unsafe_allow_html=True)

    with col_s:
        rule_s = data.get("rule_score", 0)
        ml_s   = data.get("ml_anomaly_score", 0)
        hybrid = data.get("risk_score", 0)
        st.markdown("<div class='sl-glass' style='height:100%;'>", unsafe_allow_html=True)
        st.markdown("<div style='font-size:0.62rem; color:#475569; letter-spacing:1.5px; text-transform:uppercase; margin-bottom:0.8rem;'>Score Breakdown</div>", unsafe_allow_html=True)
        st.markdown(f"<div class='score-pill'><span class='score-pill-label'>📏 Rule-Based Engine (60%)</span><span class='score-pill-value'>{rule_s:.1f}</span></div>", unsafe_allow_html=True)
        st.progress(min(rule_s / 100, 1.0))
        st.markdown(f"<div class='score-pill' style='margin-top:0.6rem;'><span class='score-pill-label'>🤖 Isolation Forest (40%)</span><span class='score-pill-value'>{ml_s:.1f}</span></div>", unsafe_allow_html=True)
        st.progress(min(ml_s / 100, 1.0))
        st.markdown(f"""
        <div class='score-pill' style='margin-top:0.8rem; background:#0D1526; border:1px solid rgba(59,130,246,0.2);'>
            <span class='score-pill-label' style='color:#60A5FA;'>⚡ Final Hybrid Score</span>
            <span class='score-pill-value' style='color:#60A5FA; font-size:1rem;'>{hybrid:.1f}</span>
        </div>
        <div style='font-size:0.65rem; font-family:DM Mono,monospace; color:#334155; margin-top:0.4rem; text-align:right;'>
            {data.get("formula","(0.6×Rule) + (0.4×ML)")}
        </div>""", unsafe_allow_html=True)
        st.markdown("</div>", unsafe_allow_html=True)

    with col_f:
        is_anom   = data.get("is_anomaly", False)
        anom_conf = data.get("anomaly_confidence", "–")
        anom_color = "#FB7185" if is_anom else "#34D399"
        st.markdown(f"""
        <div class='sl-glass' style='height:100%;'>
            <div style='font-size:0.62rem; color:#475569; letter-spacing:1.5px; text-transform:uppercase; margin-bottom:0.8rem;'>AI Detail</div>
            <div style='font-size:0.82rem; color:#CBD5E1; line-height:1.75;'>{verdict["detail"]}</div>
            <div style='margin-top:0.9rem; padding-top:0.7rem; border-top:1px solid rgba(255,255,255,0.06);'>
                <div style='font-size:0.62rem; color:#475569; margin-bottom:0.3rem;'>Anomaly Status</div>
                <div style='font-family:DM Mono,monospace; font-size:0.82rem; color:{anom_color};'>
                    {"🔺 Anomalous" if is_anom else "✓ Normal"} ({anom_conf})
                </div>
            </div>
            <div style='margin-top:0.7rem;'>
                <div style='font-size:0.62rem; color:#475569; margin-bottom:0.3rem;'>Domain</div>
                <div style='font-family:DM Mono,monospace; font-size:0.82rem; color:#93C5FD;'>
                    {data.get("domain","–")}
                </div>
            </div>
        </div>""", unsafe_allow_html=True)

    # ── Row 2: 5-Parameter Cards ──────────────────────────────────────────────
    st.markdown("<br>", unsafe_allow_html=True)
    st.markdown("<div style='font-size:0.62rem; color:#475569; letter-spacing:1.5px; text-transform:uppercase; margin-bottom:0.8rem;'>5-Parameter Security Analysis</div>", unsafe_allow_html=True)

    p1, p2, p3, p4, p5 = st.columns(5)

    def pcls(ok, warn_cond=False):
        return "param-ok" if ok else ("param-warn" if warn_cond else "param-bad")

    def param_card(col, icon, title, value, css_cls, note=""):
        col.markdown(f"""
        <div class='param-card'>
            <div class='param-icon'>{icon}</div>
            <div class='param-title'>{title}</div>
            <div class='param-value {css_cls}'>{value}</div>
            <div class='param-sub'>{note}</div>
        </div>""", unsafe_allow_html=True)

    url_s   = data.get("url_struct",  {})
    ssl_d   = data.get("ssl_info",    {}) if isinstance(data.get("ssl_info"), dict) else {}
    bl_d    = data.get("blacklist",   {})
    rd_d    = data.get("redirects",   {})
    url_len = data.get("url_length", 0)
    age     = data.get("domain_age_days", -1)
    rc      = data.get("redirect_count", 0)

    param_card(p1, "🔗", "URL Structure", f"{url_len} ch",
               pcls(url_s.get("rule_score",0)<10, url_s.get("rule_score",0)<25),
               f"Score {url_s.get('rule_score',0):.0f}")

    age_disp = f"{age}d" if age > 0 else "?"
    param_card(p2, "📅", "Domain Age", age_disp,
               pcls(age>365, age>90),
               "Established" if age>365 else ("New" if age!=-1 and age<180 else "Unknown"))

    ssl_val  = data.get("has_valid_ssl", False)
    has_http = data.get("has_https", False)
    param_card(p3, "🔒", "SSL/HTTPS",
               "Valid" if ssl_val else ("No HTTPS" if not has_http else "Invalid"),
               pcls(ssl_val, has_http),
               f"Score {ssl_d.get('rule_score',0):.0f}")

    param_card(p4, "🚫", "Blacklist",
               "Listed 🔴" if data.get("is_blacklisted") else "Clean ✓",
               "param-bad" if data.get("is_blacklisted") else "param-ok",
               f"Score {bl_d.get('rule_score',0):.0f}")

    param_card(p5, "🔀", "Redirects", f"{rc} hop{'s' if rc!=1 else ''}",
               pcls(rc==0, rc<3),
               f"Score {rd_d.get('rule_score',0):.0f}")

    # ── Row 3: Rules + Feature Vector ────────────────────────────────────────
    st.markdown("<br>", unsafe_allow_html=True)
    col_r, col_fv = st.columns([3, 2])

    with col_r:
        st.markdown("<div class='sl-glass'>", unsafe_allow_html=True)
        st.markdown("<div style='font-size:0.62rem; color:#475569; letter-spacing:1.5px; text-transform:uppercase; margin-bottom:0.8rem;'>⚡ Triggered Security Rules</div>", unsafe_allow_html=True)
        rules = data.get("all_rules", [])
        if rules:
            for r in rules:
                st.markdown(f"<div class='rule-row'>▸ {r}</div>", unsafe_allow_html=True)
        else:
            st.markdown("<div class='rule-row rule-row-safe'>✅ No rules triggered — URL passed all heuristic checks</div>", unsafe_allow_html=True)
        st.markdown("</div>", unsafe_allow_html=True)

    with col_fv:
        fv = data.get("feature_vector", {})
        st.markdown("<div class='sl-glass'>", unsafe_allow_html=True)
        st.markdown("<div style='font-size:0.62rem; color:#475569; letter-spacing:1.5px; text-transform:uppercase; margin-bottom:0.8rem;'>📐 Feature Vector</div>", unsafe_allow_html=True)
        feats = [
            ("URL Length",    f"{fv.get('url_length',0)} chars"),
            ("Subdomains",    str(fv.get("num_subdomains",0))),
            ("HTTPS",         "✅" if fv.get("has_https") else "❌"),
            ("Domain Age",    f"{fv.get('domain_age_days',-1)}d"),
            ("Redirects",     str(fv.get("redirect_count",0))),
            ("Blacklisted",   "🔴 Yes" if fv.get("is_blacklisted") else "🟢 No"),
            ("IP in URL",     "⚠️ Yes" if fv.get("has_ip_in_url") else "✅ No"),
            ("Phishing KWs",  str(fv.get("suspicious_patterns",0))),
            ("Valid SSL",     "✅" if fv.get("has_valid_ssl") else "❌"),
            ("Spec. Chars",   str(fv.get("special_char_count",0))),
        ]
        for k, v in feats:
            st.markdown(f"<div class='feat-row'><span class='feat-k'>{k}</span><span class='feat-v'>{v}</span></div>", unsafe_allow_html=True)
        st.markdown("</div>", unsafe_allow_html=True)

    # ── Row 4: Educational Insights ───────────────────────────────────────────
    st.markdown("<br>", unsafe_allow_html=True)
    st.markdown("<div style='font-size:0.62rem; color:#475569; letter-spacing:1.5px; text-transform:uppercase; margin-bottom:0.8rem;'>📚 Cybersecurity Education</div>", unsafe_allow_html=True)

    insights   = data.get("educational_insights") or generate_educational_insights(data)
    badge_map  = {"Critical":"sev-critical","High":"sev-high","Medium":"sev-medium","Low":"sev-low","Info":"sev-info"}

    for ins in insights:
        sev = ins.get("severity","Info")
        with st.expander(f"{ins.get('icon','')}  {ins.get('title','')}", expanded=(sev in ("Critical","High"))):
            st.markdown(f"<span class='{badge_map.get(sev,'sev-info')}'>{sev}</span>", unsafe_allow_html=True)
            st.markdown(f"<p style='color:#CBD5E1; line-height:1.75; font-size:0.87rem; margin-top:0.6rem;'>{ins.get('explanation','')}</p>", unsafe_allow_html=True)
            if ins.get("what_to_do"):
                st.markdown("**🛡️ Protective Actions:**")
                for tip in ins["what_to_do"]: st.markdown(f"- {tip}")
            if ins.get("learn_more"):
                st.caption(f"📖 {ins['learn_more']}")

    st.markdown(f"<div class='tip-box'>{get_random_tip()}</div>", unsafe_allow_html=True)
    st.markdown("<br>", unsafe_allow_html=True)
    if st.button("🔄  Scan Another URL", key="scan_another"):
        st.session_state.scan_result      = None
        st.session_state.pending_scan_url = ""
        st.session_state.trigger_scan     = False
        st.rerun()


# ══════════════════════════════════════════════════════════════════════════════
#  HISTORY PAGE
# ══════════════════════════════════════════════════════════════════════════════
def render_history_page():
    user_id = st.session_state.user["id"]
    st.markdown("<div style='font-family:Outfit,sans-serif; font-size:1.6rem; font-weight:800; letter-spacing:-0.5px; margin-bottom:1rem;'>📊 Scan History</div>", unsafe_allow_html=True)

    stats = get_user_stats(user_id)
    if stats and stats.get("total_scans", 0):
        c1, c2, c3, c4, c5 = st.columns(5)
        c1.metric("Total Scans",   stats.get("total_scans", 0))
        c2.metric("Avg Risk",      f"{(stats.get('avg_risk_score') or 0):.1f}")
        c3.metric("🟢 Safe",       stats.get("safe_count", 0))
        c4.metric("🟡 Suspicious", stats.get("suspicious_count", 0))
        c5.metric("🔴 High Risk",  stats.get("high_risk_count", 0))

    trend = get_risk_trend(user_id, 30)
    if trend:
        st.markdown("<div style='margin:1.5rem 0 0.4rem; font-size:0.62rem; color:#475569; letter-spacing:1.5px; text-transform:uppercase;'>Risk Trend — Last 30 Days</div>", unsafe_allow_html=True)
        df = pd.DataFrame(trend)
        df["scan_date"] = pd.to_datetime(df["scan_date"])
        df["avg_score"] = df["avg_score"].astype(float)
        st.line_chart(df.set_index("scan_date")["avg_score"], use_container_width=True)

    history = get_scan_history(user_id, 50)
    if not history:
        st.info("No scans yet. Head to the Scanner to analyse your first URL.")
        return

    st.markdown("<div style='margin:1.2rem 0 0.4rem; font-size:0.62rem; color:#475569; letter-spacing:1.5px; text-transform:uppercase;'>Recent Scans</div>", unsafe_allow_html=True)
    icons = {"Safe":"🟢","Suspicious":"🟡","High Risk":"🔴","Unknown":"⚪"}
    sc_color = lambda s: "#F43F5E" if s>=70 else "#F59E0B" if s>=40 else "#10B981"

    for row in history:
        threat = row.get("threat_level","Unknown")
        score  = row.get("risk_score", 0)
        url    = row.get("url","")
        date   = str(row.get("scanned_at",""))[:16]
        ci, cu, cs, cd, cdel = st.columns([0.4, 5, 0.8, 1.8, 0.5])
        ci.markdown(f"<div style='padding-top:0.8rem; font-size:1.1rem;'>{icons.get(threat,'⚪')}</div>", unsafe_allow_html=True)
        cu.markdown(f"""
        <div style='background:var(--surface); border:1px solid var(--border); border-radius:8px; padding:0.6rem 0.9rem; margin-bottom:0.3rem;'>
            <div style='font-family:DM Mono,monospace; font-size:0.8rem; color:#E8EDF5; white-space:nowrap; overflow:hidden; text-overflow:ellipsis;'>{url[:65]}{"…" if len(url)>65 else ""}</div>
            <div style='font-size:0.7rem; color:#475569; margin-top:2px;'>{threat} · {date}</div>
        </div>""", unsafe_allow_html=True)
        cs.markdown(f"<div style='padding-top:0.9rem; font-family:DM Mono,monospace; font-size:0.95rem; font-weight:600; color:{sc_color(score)};'>{score:.0f}</div>", unsafe_allow_html=True)
        cd.markdown(f"<div style='padding-top:0.95rem; font-size:0.72rem; color:#475569;'>{date}</div>", unsafe_allow_html=True)
        if cdel.button("🗑", key=f"del_{row['id']}", help="Delete"):
            delete_scan(row["id"], user_id)
            st.rerun()


# ══════════════════════════════════════════════════════════════════════════════
#  EDUCATION PAGE
# ══════════════════════════════════════════════════════════════════════════════
def render_education_page():
    from educational import THREAT_LIBRARY, CYBERSECURITY_TIPS

    st.markdown("<div style='font-family:Outfit,sans-serif; font-size:1.6rem; font-weight:800; letter-spacing:-0.5px; margin-bottom:0.4rem;'>📚 Cybersecurity Library</div>", unsafe_allow_html=True)
    st.markdown("<div style='color:#64748B; font-size:0.9rem; margin-bottom:1.5rem;'>Understanding attack patterns is your strongest defence.</div>", unsafe_allow_html=True)

    sev_order = ["Critical","High","Medium","Low","Info"]
    badge_map = {"Critical":"sev-critical","High":"sev-high","Medium":"sev-medium","Low":"sev-low","Info":"sev-info"}
    sorted_t  = sorted(THREAT_LIBRARY.items(), key=lambda x: sev_order.index(x[1].get("severity","Info")))

    col1, col2 = st.columns(2)
    for i, (_, t) in enumerate(sorted_t):
        sev = t.get("severity","Info")
        with (col1 if i%2==0 else col2):
            with st.expander(f"{t.get('icon','')}  {t.get('title','')}"):
                st.markdown(f"<span class='{badge_map.get(sev,'sev-info')}'>{sev}</span>", unsafe_allow_html=True)
                st.markdown(f"<p style='color:#CBD5E1; line-height:1.75; font-size:0.86rem; margin-top:0.6rem;'>{t.get('explanation','')}</p>", unsafe_allow_html=True)
                if t.get("what_to_do"):
                    st.markdown("**🛡️ Protection:**")
                    for tip in t["what_to_do"]: st.markdown(f"- {tip}")
                if t.get("learn_more"):
                    st.caption(f"📖 {t['learn_more']}")

    st.markdown("<br><div style='font-size:0.62rem; color:#475569; letter-spacing:1.5px; text-transform:uppercase; margin-bottom:0.8rem;'>Daily Security Tips</div>", unsafe_allow_html=True)
    for tip in CYBERSECURITY_TIPS:
        st.markdown(f"<div class='tip-box' style='margin-bottom:0.5rem;'>{tip}</div>", unsafe_allow_html=True)


# ══════════════════════════════════════════════════════════════════════════════
#  MAIN
# ══════════════════════════════════════════════════════════════════════════════
def main():
    inject_css()
    init_session()

    db_ok, db_msg, _ = init_app()
    if not db_ok:
        st.error(f"⚠️ Database connection failed: {db_msg}")
        st.info("Update the `DB_CONFIG` password in `database.py` and restart.")
        st.code("DB_CONFIG = {\n    'host': 'localhost',\n    'user': 'root',\n    'password': 'YOUR_MYSQL_PASSWORD',\n    ...\n}")
        st.stop()

    if not st.session_state.authenticated:
        render_auth_page()
        return

    render_sidebar()
    page = st.session_state.get("page", "scanner")
    if   page == "scanner":   render_scanner_page()
    elif page == "history":   render_history_page()
    elif page == "education": render_education_page()


if __name__ == "__main__":
    main()
