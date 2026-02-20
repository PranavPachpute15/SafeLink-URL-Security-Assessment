"""
SafeLink - Database Operations Module
Handles MySQL connections, user management, and scan history storage.
"""

import mysql.connector
from mysql.connector import Error
import bcrypt
import json
from datetime import datetime
from contextlib import contextmanager


# ─── Database Configuration ───────────────────────────────────────────────────
DB_CONFIG = {
    "host": "localhost",
    "user": "root",
    "password": "pranav@/2005",          # Update with your MySQL password
    "database": "safelink_db",
    "port": 3306,
    "autocommit": False,
    "connection_timeout": 10,
    "get_warnings": True,
}


# ─── Connection Context Manager ───────────────────────────────────────────────
@contextmanager
def get_connection():
    """Context manager for MySQL connections with automatic cleanup."""
    conn = None
    try:
        conn = mysql.connector.connect(**DB_CONFIG)
        yield conn
    except Error as e:
        if conn:
            conn.rollback()
        raise e
    finally:
        if conn and conn.is_connected():
            conn.close()


# ─── Database Initialization ──────────────────────────────────────────────────
def initialize_database():
    """
    Creates the safelink_db database and all required tables if they don't exist.
    Should be called once at application startup.
    """
    # Connect without specifying the database first
    init_config = {k: v for k, v in DB_CONFIG.items() if k != "database"}
    try:
        conn = mysql.connector.connect(**init_config)
        cursor = conn.cursor()

        # Create database
        cursor.execute(
            "CREATE DATABASE IF NOT EXISTS safelink_db CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci"
        )
        cursor.execute("USE safelink_db")

        # ── users table ──────────────────────────────────────────────────────
        cursor.execute("""
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
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
        """)

        # ── scan_history table ────────────────────────────────────────────────
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS scan_history (
                id                  INT AUTO_INCREMENT PRIMARY KEY,
                user_id             INT          NOT NULL,
                url                 TEXT         NOT NULL,
                domain              VARCHAR(255) NOT NULL,
                risk_score          FLOAT        NOT NULL,
                threat_level        VARCHAR(20)  NOT NULL,
                rule_score          FLOAT        DEFAULT 0,
                ml_anomaly_score    FLOAT        DEFAULT 0,

                -- Feature columns (5 core parameters)
                url_length          INT          DEFAULT 0,
                num_subdomains      INT          DEFAULT 0,
                has_https           BOOLEAN      DEFAULT FALSE,
                domain_age_days     INT          DEFAULT -1,
                redirect_count      INT          DEFAULT 0,
                is_blacklisted      BOOLEAN      DEFAULT FALSE,
                has_ip_in_url       BOOLEAN      DEFAULT FALSE,
                suspicious_patterns INT          DEFAULT 0,
                has_valid_ssl       BOOLEAN      DEFAULT FALSE,
                special_char_count  INT          DEFAULT 0,

                -- JSON blobs for detailed breakdown
                feature_vector      JSON         NULL,
                triggered_rules     JSON         NULL,
                educational_tips    JSON         NULL,
                redirect_chain      JSON         NULL,
                ssl_info            JSON         NULL,

                scanned_at          DATETIME     DEFAULT CURRENT_TIMESTAMP,

                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
                INDEX idx_user_id    (user_id),
                INDEX idx_risk_score (risk_score),
                INDEX idx_scanned_at (scanned_at)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
        """)

        conn.commit()
        cursor.close()
        conn.close()
        return True, "Database initialized successfully."

    except Error as e:
        return False, f"Database initialization failed: {e}"


# ─── User Management ──────────────────────────────────────────────────────────
def create_user(username: str, email: str, password: str) -> tuple[bool, str]:
    """Register a new user with bcrypt-hashed password."""
    password_hash = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt(rounds=12)).decode("utf-8")
    try:
        with get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "INSERT INTO users (username, email, password_hash) VALUES (%s, %s, %s)",
                (username, email, password_hash),
            )
            conn.commit()
            cursor.close()
        return True, "Account created successfully."
    except mysql.connector.IntegrityError as e:
        if "username" in str(e):
            return False, "Username already exists."
        if "email" in str(e):
            return False, "Email already registered."
        return False, f"Registration error: {e}"
    except Error as e:
        return False, f"Database error: {e}"


def authenticate_user(username: str, password: str) -> tuple[bool, dict | None]:
    """Verify credentials and return user record on success."""
    try:
        with get_connection() as conn:
            cursor = conn.cursor(dictionary=True)
            cursor.execute(
                "SELECT * FROM users WHERE username = %s AND is_active = TRUE",
                (username,),
            )
            user = cursor.fetchone()
            cursor.close()

        if user and bcrypt.checkpw(password.encode("utf-8"), user["password_hash"].encode("utf-8")):
            _update_last_login(user["id"])
            return True, user
        return False, None
    except Error as e:
        return False, None


def _update_last_login(user_id: int):
    """Update last_login timestamp for a user."""
    try:
        with get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "UPDATE users SET last_login = %s WHERE id = %s",
                (datetime.now(), user_id),
            )
            conn.commit()
            cursor.close()
    except Error:
        pass


def get_user_stats(user_id: int) -> dict:
    """Fetch aggregate statistics for a user's scan history."""
    try:
        with get_connection() as conn:
            cursor = conn.cursor(dictionary=True)
            cursor.execute("""
                SELECT
                    COUNT(*)                          AS total_scans,
                    AVG(risk_score)                   AS avg_risk_score,
                    MAX(risk_score)                   AS max_risk_score,
                    SUM(CASE WHEN threat_level = 'Safe'      THEN 1 ELSE 0 END) AS safe_count,
                    SUM(CASE WHEN threat_level = 'Suspicious' THEN 1 ELSE 0 END) AS suspicious_count,
                    SUM(CASE WHEN threat_level = 'High Risk' THEN 1 ELSE 0 END) AS high_risk_count
                FROM scan_history
                WHERE user_id = %s
            """, (user_id,))
            stats = cursor.fetchone()
            cursor.close()
        return stats or {}
    except Error:
        return {}


# ─── Scan History ─────────────────────────────────────────────────────────────
def save_scan_result(user_id: int, scan_data: dict) -> tuple[bool, str]:
    """
    Persist a completed scan result to the database.
    scan_data keys mirror the scan_history table columns.
    """
    try:
        with get_connection() as conn:
            cursor = conn.cursor()

            # Serialize JSON fields
            def safe_json(val):
                return json.dumps(val) if val is not None else None

            cursor.execute("""
                INSERT INTO scan_history (
                    user_id, url, domain, risk_score, threat_level,
                    rule_score, ml_anomaly_score,
                    url_length, num_subdomains, has_https, domain_age_days,
                    redirect_count, is_blacklisted, has_ip_in_url,
                    suspicious_patterns, has_valid_ssl, special_char_count,
                    feature_vector, triggered_rules, educational_tips,
                    redirect_chain, ssl_info
                ) VALUES (
                    %s,%s,%s,%s,%s,
                    %s,%s,
                    %s,%s,%s,%s,
                    %s,%s,%s,
                    %s,%s,%s,
                    %s,%s,%s,
                    %s,%s
                )
            """, (
                user_id,
                scan_data.get("url", ""),
                scan_data.get("domain", ""),
                scan_data.get("risk_score", 0),
                scan_data.get("threat_level", "Unknown"),
                scan_data.get("rule_score", 0),
                scan_data.get("ml_anomaly_score", 0),
                scan_data.get("url_length", 0),
                scan_data.get("num_subdomains", 0),
                bool(scan_data.get("has_https", False)),
                scan_data.get("domain_age_days", -1),
                scan_data.get("redirect_count", 0),
                bool(scan_data.get("is_blacklisted", False)),
                bool(scan_data.get("has_ip_in_url", False)),
                scan_data.get("suspicious_patterns", 0),
                bool(scan_data.get("has_valid_ssl", False)),
                scan_data.get("special_char_count", 0),
                safe_json(scan_data.get("feature_vector")),
                safe_json(scan_data.get("triggered_rules")),
                safe_json(scan_data.get("educational_tips")),
                safe_json(scan_data.get("redirect_chain")),
                safe_json(scan_data.get("ssl_info")),
            ))

            # Increment user scan counter
            cursor.execute(
                "UPDATE users SET scan_count = scan_count + 1 WHERE id = %s",
                (user_id,),
            )
            conn.commit()
            cursor.close()
        return True, "Scan result saved."
    except Error as e:
        return False, f"Failed to save scan: {e}"


def get_scan_history(user_id: int, limit: int = 50) -> list[dict]:
    """Retrieve a user's recent scan history, newest first."""
    try:
        with get_connection() as conn:
            cursor = conn.cursor(dictionary=True)
            cursor.execute("""
                SELECT id, url, domain, risk_score, threat_level,
                       has_https, is_blacklisted, domain_age_days,
                       redirect_count, scanned_at,
                       triggered_rules, educational_tips
                FROM scan_history
                WHERE user_id = %s
                ORDER BY scanned_at DESC
                LIMIT %s
            """, (user_id, limit))
            rows = cursor.fetchall()
            cursor.close()

        # Deserialize JSON fields
        for row in rows:
            for field in ("triggered_rules", "educational_tips"):
                if row.get(field) and isinstance(row[field], str):
                    try:
                        row[field] = json.loads(row[field])
                    except json.JSONDecodeError:
                        row[field] = []
        return rows
    except Error:
        return []


def get_scan_detail(scan_id: int, user_id: int) -> dict | None:
    """Get full details for a single scan (ownership enforced)."""
    try:
        with get_connection() as conn:
            cursor = conn.cursor(dictionary=True)
            cursor.execute(
                "SELECT * FROM scan_history WHERE id = %s AND user_id = %s",
                (scan_id, user_id),
            )
            row = cursor.fetchone()
            cursor.close()

        if row:
            for field in ("feature_vector", "triggered_rules", "educational_tips",
                          "redirect_chain", "ssl_info"):
                if row.get(field) and isinstance(row[field], str):
                    try:
                        row[field] = json.loads(row[field])
                    except json.JSONDecodeError:
                        row[field] = {}
        return row
    except Error:
        return None


def delete_scan(scan_id: int, user_id: int) -> bool:
    """Delete a scan record (ownership enforced)."""
    try:
        with get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "DELETE FROM scan_history WHERE id = %s AND user_id = %s",
                (scan_id, user_id),
            )
            conn.commit()
            affected = cursor.rowcount
            cursor.close()
        return affected > 0
    except Error:
        return False


def get_risk_trend(user_id: int, days: int = 30) -> list[dict]:
    """Return daily average risk scores for trend charts."""
    try:
        with get_connection() as conn:
            cursor = conn.cursor(dictionary=True)
            cursor.execute("""
                SELECT
                    DATE(scanned_at)   AS scan_date,
                    AVG(risk_score)    AS avg_score,
                    COUNT(*)           AS scan_count,
                    MAX(risk_score)    AS max_score
                FROM scan_history
                WHERE user_id = %s
                  AND scanned_at >= DATE_SUB(NOW(), INTERVAL %s DAY)
                GROUP BY DATE(scanned_at)
                ORDER BY scan_date ASC
            """, (user_id, days))
            rows = cursor.fetchall()
            cursor.close()
        return rows
    except Error:
        return []
