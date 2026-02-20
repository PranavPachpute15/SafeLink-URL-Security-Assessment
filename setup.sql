-- ─────────────────────────────────────────────────────────────────────────────
-- SafeLink Database Schema
-- Run this SQL file in MySQL to set up the database manually
-- OR the database.py module will auto-create tables on first run
-- ─────────────────────────────────────────────────────────────────────────────

CREATE DATABASE IF NOT EXISTS safelink_db
    CHARACTER SET utf8mb4
    COLLATE utf8mb4_unicode_ci;

USE safelink_db;

-- ── users table ───────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS users (
    id            INT AUTO_INCREMENT PRIMARY KEY,
    username      VARCHAR(50)  NOT NULL UNIQUE,
    email         VARCHAR(120) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    created_at    DATETIME     DEFAULT CURRENT_TIMESTAMP,
    last_login    DATETIME     NULL,
    is_active     BOOLEAN      DEFAULT TRUE,
    scan_count    INT          DEFAULT 0,

    INDEX idx_username (username),
    INDEX idx_email    (email)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='User authentication and profile data';


-- ── scan_history table ────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS scan_history (
    id                  INT AUTO_INCREMENT PRIMARY KEY,
    user_id             INT          NOT NULL COMMENT 'FK to users.id',

    -- URL & Domain
    url                 TEXT         NOT NULL,
    domain              VARCHAR(255) NOT NULL,

    -- Risk Scores
    risk_score          FLOAT        NOT NULL COMMENT 'Final hybrid score (0-100)',
    threat_level        VARCHAR(20)  NOT NULL COMMENT 'Safe | Suspicious | High Risk',
    rule_score          FLOAT        DEFAULT 0 COMMENT 'Rule-based component (0-100)',
    ml_anomaly_score    FLOAT        DEFAULT 0 COMMENT 'Isolation Forest score (0-100)',

    -- ── 5 Core Security Parameter Features ──────────────────────────────────
    -- Parameter 1: URL Structure
    url_length          INT          DEFAULT 0,
    num_subdomains      INT          DEFAULT 0,
    has_ip_in_url       BOOLEAN      DEFAULT FALSE,
    suspicious_patterns INT          DEFAULT 0,
    special_char_count  INT          DEFAULT 0,

    -- Parameter 2: Domain Analysis
    domain_age_days     INT          DEFAULT -1 COMMENT '-1 = unknown',

    -- Parameter 3: SSL/HTTPS
    has_https           BOOLEAN      DEFAULT FALSE,
    has_valid_ssl       BOOLEAN      DEFAULT FALSE,

    -- Parameter 4: Blacklist
    is_blacklisted      BOOLEAN      DEFAULT FALSE,

    -- Parameter 5: Redirects
    redirect_count      INT          DEFAULT 0,

    -- ── JSON Detail Blobs ────────────────────────────────────────────────────
    feature_vector      JSON         NULL COMMENT 'Full 15-feature ML vector',
    triggered_rules     JSON         NULL COMMENT 'List of triggered rule strings',
    educational_tips    JSON         NULL COMMENT 'List of insight titles shown',
    redirect_chain      JSON         NULL COMMENT 'Full redirect hop chain',
    ssl_info            JSON         NULL COMMENT 'Certificate details',

    scanned_at          DATETIME     DEFAULT CURRENT_TIMESTAMP,

    -- Foreign key & indexes
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    INDEX idx_user_id    (user_id),
    INDEX idx_threat     (threat_level),
    INDEX idx_risk_score (risk_score),
    INDEX idx_scanned_at (scanned_at),
    INDEX idx_domain     (domain)

) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
  COMMENT='URL scan results with ML scores and security feature breakdown';


-- ── Example verification queries ──────────────────────────────────────────────
-- SELECT COUNT(*) FROM users;
-- SELECT url, risk_score, threat_level, scanned_at FROM scan_history ORDER BY scanned_at DESC LIMIT 10;
-- SELECT threat_level, COUNT(*) AS count, AVG(risk_score) AS avg_score FROM scan_history GROUP BY threat_level;
