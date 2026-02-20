"""
SafeLink - Machine Learning Engine
Isolation Forest anomaly detection for zero-day URL threat identification.
Combines ML anomaly score with rule-based score for final hybrid risk output.
"""

import os
import pickle
import numpy as np
import pandas as pd
from datetime import datetime

from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import MinMaxScaler


# ─── Configuration ────────────────────────────────────────────────────────────
MODEL_PATH    = "safelink_model.pkl"
SCALER_PATH   = "safelink_scaler.pkl"

FEATURE_NAMES = [
    "url_length",          # Raw URL character length
    "num_subdomains",      # Number of subdomain segments
    "has_https",           # HTTPS presence (0/1)
    "domain_age_days",     # Domain age (-1 = unknown)
    "redirect_count",      # Number of HTTP redirects
    "is_blacklisted",      # Blacklist match (0/1)
    "has_ip_in_url",       # IP-based URL (0/1)
    "suspicious_patterns", # Count of phishing keywords
    "has_valid_ssl",       # Valid SSL certificate (0/1)
    "special_char_count",  # Special chars (@, %, etc.)
    "num_hyphens",         # Hyphens in URL
    "path_depth",          # Directory depth of URL path
    "pct_encoded_count",   # Percent-encoded characters
    "has_at_symbol",       # @ in netloc (0/1)
    "is_url_shortener",    # URL shortener detected (0/1)
]

# Hybrid formula weights
RULE_WEIGHT = 0.60    # Rule-based score contributes 60%
ML_WEIGHT   = 0.40    # ML anomaly score contributes 40%


# ─── Synthetic Training Data ──────────────────────────────────────────────────
def _generate_training_data(n_samples: int = 2000) -> pd.DataFrame:
    """
    Generates a synthetic training corpus representing a realistic distribution
    of safe, suspicious, and malicious URLs for the Isolation Forest.

    In production, replace with a labeled real-world dataset.
    """
    rng = np.random.default_rng(42)

    # ── Safe URLs (60%) ───────────────────────────────────────────────────────
    n_safe = int(n_samples * 0.60)
    safe = pd.DataFrame({
        "url_length":          rng.integers(20, 60, n_safe),
        "num_subdomains":      rng.choice([0, 1], n_safe, p=[0.7, 0.3]),
        "has_https":           rng.choice([1, 1, 1, 0], n_safe),  # mostly HTTPS
        "domain_age_days":     rng.integers(365, 5000, n_safe),
        "redirect_count":      rng.choice([0, 1, 2], n_safe, p=[0.7, 0.2, 0.1]),
        "is_blacklisted":      np.zeros(n_safe),
        "has_ip_in_url":       np.zeros(n_safe),
        "suspicious_patterns": rng.integers(0, 2, n_safe),
        "has_valid_ssl":       rng.choice([1, 1, 1, 0], n_safe),
        "special_char_count":  rng.integers(0, 4, n_safe),
        "num_hyphens":         rng.integers(0, 2, n_safe),
        "path_depth":          rng.integers(0, 3, n_safe),
        "pct_encoded_count":   rng.integers(0, 2, n_safe),
        "has_at_symbol":       np.zeros(n_safe),
        "is_url_shortener":    np.zeros(n_safe),
    })

    # ── Suspicious URLs (25%) ─────────────────────────────────────────────────
    n_sus = int(n_samples * 0.25)
    suspicious = pd.DataFrame({
        "url_length":          rng.integers(60, 120, n_sus),
        "num_subdomains":      rng.integers(1, 3, n_sus),
        "has_https":           rng.choice([0, 1], n_sus, p=[0.5, 0.5]),
        "domain_age_days":     rng.integers(-1, 365, n_sus),
        "redirect_count":      rng.integers(1, 5, n_sus),
        "is_blacklisted":      np.zeros(n_sus),
        "has_ip_in_url":       rng.choice([0, 1], n_sus, p=[0.7, 0.3]),
        "suspicious_patterns": rng.integers(1, 4, n_sus),
        "has_valid_ssl":       rng.choice([0, 1], n_sus, p=[0.5, 0.5]),
        "special_char_count":  rng.integers(3, 8, n_sus),
        "num_hyphens":         rng.integers(2, 5, n_sus),
        "path_depth":          rng.integers(2, 6, n_sus),
        "pct_encoded_count":   rng.integers(1, 5, n_sus),
        "has_at_symbol":       rng.choice([0, 1], n_sus, p=[0.6, 0.4]),
        "is_url_shortener":    rng.choice([0, 1], n_sus, p=[0.5, 0.5]),
    })

    # ── Malicious URLs (15%) ──────────────────────────────────────────────────
    n_mal = n_samples - n_safe - n_sus
    malicious = pd.DataFrame({
        "url_length":          rng.integers(100, 300, n_mal),
        "num_subdomains":      rng.integers(3, 6, n_mal),
        "has_https":           rng.choice([0, 1], n_mal, p=[0.7, 0.3]),
        "domain_age_days":     rng.integers(-1, 60, n_mal),
        "redirect_count":      rng.integers(3, 10, n_mal),
        "is_blacklisted":      rng.choice([0, 1], n_mal, p=[0.3, 0.7]),
        "has_ip_in_url":       rng.choice([0, 1], n_mal, p=[0.3, 0.7]),
        "suspicious_patterns": rng.integers(4, 10, n_mal),
        "has_valid_ssl":       rng.choice([0, 1], n_mal, p=[0.8, 0.2]),
        "special_char_count":  rng.integers(5, 20, n_mal),
        "num_hyphens":         rng.integers(3, 10, n_mal),
        "path_depth":          rng.integers(4, 10, n_mal),
        "pct_encoded_count":   rng.integers(3, 15, n_mal),
        "has_at_symbol":       rng.choice([0, 1], n_mal, p=[0.4, 0.6]),
        "is_url_shortener":    rng.choice([0, 1], n_mal, p=[0.4, 0.6]),
    })

    df = pd.concat([safe, suspicious, malicious], ignore_index=True)
    # Shuffle
    return df.sample(frac=1, random_state=42).reset_index(drop=True)


# ─── Model Training ───────────────────────────────────────────────────────────
def train_model(n_samples: int = 2000) -> tuple:
    """
    Trains the Isolation Forest on synthetic URL data and persists to disk.
    Returns (model, scaler, training_info).
    """
    print("[SafeLink ML] Generating training corpus...")
    df     = _generate_training_data(n_samples)
    X      = df[FEATURE_NAMES].values

    # Scale features to [0, 1]
    scaler = MinMaxScaler()
    X_scaled = scaler.fit_transform(X)

    print(f"[SafeLink ML] Training Isolation Forest on {n_samples} samples...")
    model = IsolationForest(
        n_estimators=200,       # More trees → more stable anomaly scores
        max_samples="auto",
        contamination=0.20,     # Estimated 20% anomalous URLs in wild
        max_features=1.0,
        bootstrap=False,
        n_jobs=-1,
        random_state=42,
        warm_start=False,
    )
    model.fit(X_scaled)

    # Persist
    with open(MODEL_PATH,  "wb") as f:
        pickle.dump(model, f)
    with open(SCALER_PATH, "wb") as f:
        pickle.dump(scaler, f)

    training_info = {
        "trained_at":    datetime.now().isoformat(),
        "n_samples":     n_samples,
        "n_features":    len(FEATURE_NAMES),
        "contamination": 0.20,
        "n_estimators":  200,
    }
    print("[SafeLink ML] Model trained and saved.")
    return model, scaler, training_info


def load_model() -> tuple:
    """Load persisted model and scaler, training fresh if not found."""
    if os.path.exists(MODEL_PATH) and os.path.exists(SCALER_PATH):
        try:
            with open(MODEL_PATH,  "rb") as f:
                model  = pickle.load(f)
            with open(SCALER_PATH, "rb") as f:
                scaler = pickle.load(f)
            return model, scaler
        except Exception:
            pass
    # Train fresh if not found
    model, scaler, _ = train_model()
    return model, scaler


# ─── Scoring Engine ───────────────────────────────────────────────────────────
def _extract_feature_array(feature_vector: dict) -> np.ndarray:
    """Convert feature dict to ordered numpy array for model input."""
    return np.array([[feature_vector.get(f, 0) for f in FEATURE_NAMES]])


def compute_ml_anomaly_score(feature_vector: dict, model, scaler) -> dict:
    """
    Runs Isolation Forest inference and returns a normalized anomaly score [0–100].

    Isolation Forest returns:
      - score_samples(): raw anomaly score (negative log-likelihood)
      - decision_function(): offset from boundary (negative = anomalous)
    We invert and normalize to produce an intuitive 0→100 score
    where 100 = maximum anomaly (most suspicious).
    """
    X      = _extract_feature_array(feature_vector)
    X_norm = scaler.transform(X)

    raw_score = model.score_samples(X_norm)[0]     # Lower = more anomalous
    decision  = model.decision_function(X_norm)[0]  # Negative = anomaly

    # Normalize raw_score to [0, 100]
    # Isolation Forest scores typically range [-0.8, 0.2]
    # We map this so: safe(0.2) → 0, anomalous(-0.8) → 100
    SCORE_MIN, SCORE_MAX = -0.8, 0.2
    clamped = max(SCORE_MIN, min(SCORE_MAX, raw_score))
    ml_score_normalized = ((SCORE_MAX - clamped) / (SCORE_MAX - SCORE_MIN)) * 100
    ml_score_normalized = round(ml_score_normalized, 2)

    is_anomaly = decision < 0

    return {
        "ml_anomaly_score":      ml_score_normalized,
        "is_anomaly":            is_anomaly,
        "raw_if_score":          round(raw_score, 6),
        "if_decision":           round(decision, 6),
        "anomaly_confidence":    "High" if decision < -0.15 else "Medium" if decision < 0 else "Low",
    }


def compute_hybrid_risk_score(rule_score: float, ml_score: float, feature_vector: dict) -> dict:
    """
    Computes the final hybrid risk score using a weighted combination:
        hybrid = (RULE_WEIGHT × rule_score) + (ML_WEIGHT × ml_score)

    Additional adjustments:
      - Hard override for blacklisted URLs (minimum 80)
      - Hard override for IP-based URLs (minimum 60)
    """
    # Weighted hybrid
    hybrid = (RULE_WEIGHT * rule_score) + (ML_WEIGHT * ml_score)
    hybrid = round(min(hybrid, 100), 2)

    # Hard overrides
    if feature_vector.get("is_blacklisted", 0):
        hybrid = max(hybrid, 80.0)
    if feature_vector.get("has_ip_in_url", 0):
        hybrid = max(hybrid, 60.0)

    # Threat classification
    if hybrid >= 70:
        threat_level = "High Risk"
        threat_color = "#FF4444"
        threat_icon  = "🔴"
    elif hybrid >= 40:
        threat_level = "Suspicious"
        threat_color = "#FFA500"
        threat_icon  = "🟡"
    else:
        threat_level = "Safe"
        threat_color = "#00CC66"
        threat_icon  = "🟢"

    return {
        "risk_score":    hybrid,
        "threat_level":  threat_level,
        "threat_color":  threat_color,
        "threat_icon":   threat_icon,
        "rule_score":    round(rule_score, 2),
        "ml_score":      round(ml_score, 2),
        "rule_weight":   RULE_WEIGHT,
        "ml_weight":     ML_WEIGHT,
        "formula":       f"({RULE_WEIGHT}×{round(rule_score,1)}) + ({ML_WEIGHT}×{round(ml_score,1)}) = {hybrid}",
    }


# ─── Full Scoring Pipeline ────────────────────────────────────────────────────
def score_scan(scan_data: dict) -> dict:
    """
    Main entry point: accepts raw scan_data from scanner.py
    and returns completed scoring with ML anomaly + hybrid risk.
    """
    model, scaler = load_model()

    feature_vector = scan_data.get("feature_vector", {})
    rule_score     = scan_data.get("rule_score", 0)

    ml_result      = compute_ml_anomaly_score(feature_vector, model, scaler)
    ml_score       = ml_result["ml_anomaly_score"]

    hybrid_result  = compute_hybrid_risk_score(rule_score, ml_score, feature_vector)

    # Merge everything into scan_data
    scan_data.update(ml_result)
    scan_data.update(hybrid_result)
    scan_data["ml_anomaly_score"] = ml_score

    return scan_data
