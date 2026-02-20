"""
SafeLink - URL Security Scanner
Implements the 5-parameter hybrid security assessment engine.
Combines rule-based heuristics with Isolation Forest anomaly detection.
"""

import re
import ssl
import socket
import hashlib
import ipaddress
import urllib.parse
from datetime import datetime, timezone
from typing import Optional

import requests
import tldextract

# Optional: python-whois (gracefully handled if unavailable)
try:
    import whois as python_whois
    WHOIS_AVAILABLE = True
except ImportError:
    WHOIS_AVAILABLE = False


# ─── Constants & Blacklists ───────────────────────────────────────────────────
SUSPICIOUS_TLDS = {
    ".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".club",
    ".online", ".site", ".icu", ".pw", ".cc", ".biz", ".info",
    ".vip", ".fun", ".work", ".loan", ".win", ".bid",
}

PHISHING_KEYWORDS = [
    "login", "signin", "verify", "account", "secure", "update", "confirm",
    "banking", "paypal", "amazon", "google", "microsoft", "apple", "netflix",
    "password", "credential", "validate", "authenticate", "suspended",
    "unusual", "activity", "alert", "urgent", "click", "free", "win",
    "prize", "lottery", "crypto", "bitcoin", "wallet", "recovery",
]

BENIGN_DOMAINS = {
    "google.com", "youtube.com", "facebook.com", "twitter.com", "instagram.com",
    "linkedin.com", "github.com", "microsoft.com", "apple.com", "amazon.com",
    "wikipedia.org", "reddit.com", "stackoverflow.com", "medium.com",
    "cloudflare.com", "netflix.com", "spotify.com", "zoom.us", "slack.com",
}

# Minimal local blacklist for demo (extend with real threat feeds in production)
BLACKLISTED_DOMAINS_SAMPLE = {
    "malware-test.com", "phishing-example.net", "evil-site.tk",
    "fakepaypal-secure.com", "login-amazon-verify.xyz",
}

REQUEST_TIMEOUT = 8  # seconds
MAX_REDIRECTS    = 10


# ─── Parameter 1: URL Structure Analysis ─────────────────────────────────────
def analyze_url_structure(url: str) -> dict:
    """
    Examines lexical and structural properties of the URL string.
    Returns feature dict + list of triggered rule descriptions.
    """
    parsed   = urllib.parse.urlparse(url)
    hostname = parsed.hostname or ""
    path     = parsed.path or ""
    query    = parsed.query or ""
    fragment = parsed.fragment or ""
    full_url = url.lower()

    ext       = tldextract.extract(url)
    domain    = ext.domain
    suffix    = f".{ext.suffix}" if ext.suffix else ""
    subdomain = ext.subdomain

    # ── Lexical features ─────────────────────────────────────────────────────
    url_length          = len(url)
    num_dots            = url.count(".")
    num_hyphens         = url.count("-")
    num_underscores     = url.count("_")
    num_slashes         = url.count("/")
    num_query_params    = len(urllib.parse.parse_qs(query))
    special_char_count  = len(re.findall(r"[@%&=~#!$*]", url))
    num_digits_in_domain= len(re.findall(r"\d", hostname))
    path_depth          = path.strip("/").count("/") if path.strip("/") else 0

    # IP address check
    has_ip_in_url = False
    try:
        ipaddress.ip_address(hostname)
        has_ip_in_url = True
    except ValueError:
        if re.search(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", hostname):
            has_ip_in_url = True

    # Subdomain depth
    num_subdomains = len(subdomain.split(".")) if subdomain else 0

    # Phishing keyword detection
    matched_keywords = [kw for kw in PHISHING_KEYWORDS if kw in full_url]
    suspicious_patterns = len(matched_keywords)

    # Suspicious TLD
    has_suspicious_tld = suffix in SUSPICIOUS_TLDS

    # URL shortener detection
    url_shorteners = {"bit.ly", "t.co", "tinyurl.com", "goo.gl", "ow.ly",
                      "buff.ly", "is.gd", "rebrand.ly", "cutt.ly", "short.gy"}
    is_url_shortener = any(s in hostname for s in url_shorteners)

    # Encoded characters (obfuscation attempts)
    pct_encoded_count = len(re.findall(r"%[0-9a-fA-F]{2}", url))
    has_double_encoding = bool(re.search(r"%25[0-9a-fA-F]{2}", url))

    # At-sign in URL (credential embedding attempt)
    has_at_symbol = "@" in parsed.netloc

    # Punycode / IDN homograph
    has_punycode = "xn--" in hostname.lower()

    # ── Rule scoring ──────────────────────────────────────────────────────────
    rules_triggered = []
    rule_score = 0

    if url_length > 75:
        penalty = min(15, (url_length - 75) // 10 * 3)
        rule_score += penalty
        rules_triggered.append(f"Long URL ({url_length} chars) +{penalty}")

    if has_ip_in_url:
        rule_score += 25
        rules_triggered.append("IP address used instead of domain name +25")

    if num_subdomains >= 3:
        rule_score += 10
        rules_triggered.append(f"Excessive subdomains ({num_subdomains}) +10")
    elif num_subdomains == 2:
        rule_score += 5
        rules_triggered.append(f"Multiple subdomains ({num_subdomains}) +5")

    if suspicious_patterns >= 3:
        rule_score += 15
        rules_triggered.append(f"Multiple phishing keywords ({', '.join(matched_keywords[:3])}) +15")
    elif suspicious_patterns >= 1:
        rule_score += 8
        rules_triggered.append(f"Phishing keyword detected ({matched_keywords[0]}) +8")

    if has_suspicious_tld:
        rule_score += 12
        rules_triggered.append(f"High-risk TLD ({suffix}) +12")

    if num_hyphens >= 4:
        rule_score += 8
        rules_triggered.append(f"Excessive hyphens in domain ({num_hyphens}) +8")

    if special_char_count >= 5:
        rule_score += 7
        rules_triggered.append(f"Suspicious special characters ({special_char_count}) +7")

    if has_at_symbol:
        rule_score += 15
        rules_triggered.append("@ symbol in URL (credential obfuscation) +15")

    if pct_encoded_count >= 3:
        rule_score += 8
        rules_triggered.append(f"URL encoding obfuscation ({pct_encoded_count} encoded chars) +8")

    if has_double_encoding:
        rule_score += 12
        rules_triggered.append("Double URL encoding detected +12")

    if has_punycode:
        rule_score += 10
        rules_triggered.append("Punycode/IDN homograph attack risk +10")

    if is_url_shortener:
        rule_score += 10
        rules_triggered.append("URL shortener hides true destination +10")

    if num_digits_in_domain >= 4:
        rule_score += 5
        rules_triggered.append(f"Many digits in domain name ({num_digits_in_domain}) +5")

    return {
        "url_length":          url_length,
        "num_subdomains":      num_subdomains,
        "has_ip_in_url":       has_ip_in_url,
        "suspicious_patterns": suspicious_patterns,
        "special_char_count":  special_char_count,
        "num_hyphens":         num_hyphens,
        "num_dots":            num_dots,
        "path_depth":          path_depth,
        "pct_encoded_count":   pct_encoded_count,
        "has_at_symbol":       has_at_symbol,
        "has_punycode":        has_punycode,
        "is_url_shortener":    is_url_shortener,
        "has_suspicious_tld":  has_suspicious_tld,
        "matched_keywords":    matched_keywords,
        "num_query_params":    num_query_params,
        "rule_score":          min(rule_score, 50),
        "rules_triggered":     rules_triggered,
        "domain":              domain,
        "suffix":              suffix,
        "subdomain":           subdomain,
    }


# ─── Parameter 2: Domain Analysis (WHOIS & Age) ───────────────────────────────
def analyze_domain(url: str) -> dict:
    """
    Performs WHOIS lookup to assess domain age, registrar reputation, etc.
    Falls back gracefully if WHOIS data is unavailable.
    """
    ext        = tldextract.extract(url)
    registered = f"{ext.domain}.{ext.suffix}" if ext.suffix else ext.domain

    result = {
        "domain_age_days":    -1,
        "creation_date":      None,
        "expiry_date":        None,
        "registrar":          "Unknown",
        "country":            "Unknown",
        "is_newly_registered": True,
        "rule_score":         0,
        "rules_triggered":    [],
        "whois_available":    WHOIS_AVAILABLE,
    }

    # Check benign domain whitelist first
    if registered in BENIGN_DOMAINS:
        result["domain_age_days"]    = 5000
        result["is_newly_registered"] = False
        return result

    if not WHOIS_AVAILABLE:
        result["rule_score"]      = 8
        result["rules_triggered"] = ["WHOIS unavailable – domain age unverifiable +8"]
        return result

    try:
        w = python_whois.whois(registered)

        # Normalize creation date
        creation = w.creation_date
        if isinstance(creation, list):
            creation = creation[0]

        if creation:
            if hasattr(creation, "tzinfo") and creation.tzinfo:
                now = datetime.now(timezone.utc)
                creation = creation.replace(tzinfo=timezone.utc) if not creation.tzinfo else creation
            else:
                now = datetime.now()
            age_days = (now - creation).days
            result["domain_age_days"] = age_days
            result["creation_date"]   = str(creation)[:10]
            result["is_newly_registered"] = age_days < 180

        # Expiry
        expiry = w.expiration_date
        if isinstance(expiry, list):
            expiry = expiry[0]
        if expiry:
            result["expiry_date"] = str(expiry)[:10]

        result["registrar"] = str(w.registrar or "Unknown")[:80]
        result["country"]   = str(w.country or "Unknown")[:5]

    except Exception:
        result["rule_score"]      = 5
        result["rules_triggered"] = ["WHOIS lookup failed – treating as unverified +5"]
        return result

    # ── Rule scoring ──────────────────────────────────────────────────────────
    score = 0
    rules = []

    age = result["domain_age_days"]
    if age == -1:
        score += 10
        rules.append("Domain age unknown +10")
    elif age < 30:
        score += 20
        rules.append(f"Very new domain ({age} days old) – high phishing risk +20")
    elif age < 180:
        score += 12
        rules.append(f"Recently registered domain ({age} days old) +12")
    elif age < 365:
        score += 5
        rules.append(f"Relatively new domain ({age} days old) +5")

    result["rule_score"]      = min(score, 25)
    result["rules_triggered"] = rules
    return result


# ─── Parameter 3: SSL/HTTPS Validity ─────────────────────────────────────────
def analyze_ssl(url: str) -> dict:
    """
    Checks HTTPS presence and validates the SSL/TLS certificate.
    """
    parsed    = urllib.parse.urlparse(url)
    hostname  = parsed.hostname or ""
    has_https = parsed.scheme.lower() == "https"

    result = {
        "has_https":         has_https,
        "has_valid_ssl":     False,
        "ssl_issuer":        None,
        "ssl_subject":       None,
        "ssl_expiry":        None,
        "ssl_days_left":     None,
        "ssl_version":       None,
        "is_self_signed":    False,
        "rule_score":        0,
        "rules_triggered":   [],
        "ssl_info":          {},
    }

    if not has_https:
        result["rule_score"]      = 20
        result["rules_triggered"] = ["No HTTPS – data transmitted in plaintext +20"]
        return result

    if not hostname:
        result["rule_score"]      = 5
        result["rules_triggered"] = ["Could not determine hostname for SSL check +5"]
        return result

    try:
        ctx  = ssl.create_default_context()
        conn = ctx.wrap_socket(
            socket.create_connection((hostname, 443), timeout=REQUEST_TIMEOUT),
            server_hostname=hostname,
        )
        cert = conn.getpeercert()
        conn.close()

        # Expiry
        expire_str = cert.get("notAfter", "")
        if expire_str:
            expire_dt  = datetime.strptime(expire_str, "%b %d %H:%M:%S %Y %Z")
            days_left  = (expire_dt - datetime.utcnow()).days
            result["ssl_expiry"]    = expire_str[:11]
            result["ssl_days_left"] = days_left
        else:
            days_left = 999

        # Issuer / Subject
        issuer  = dict(x[0] for x in cert.get("issuer", []))
        subject = dict(x[0] for x in cert.get("subject", []))
        result["ssl_issuer"]  = issuer.get("organizationName", "Unknown")
        result["ssl_subject"] = subject.get("commonName", hostname)
        result["ssl_version"] = conn.version() if hasattr(conn, "version") else "TLS"

        # Self-signed check
        result["is_self_signed"] = issuer == subject
        result["has_valid_ssl"]  = True
        result["ssl_info"]       = {
            "issuer":    result["ssl_issuer"],
            "subject":   result["ssl_subject"],
            "expiry":    result["ssl_expiry"],
            "days_left": days_left,
        }

        # ── Rule scoring ──────────────────────────────────────────────────────
        score = 0
        rules = []

        if result["is_self_signed"]:
            score += 15
            rules.append("Self-signed SSL certificate (not trusted by CA) +15")

        if days_left < 0:
            score += 18
            rules.append(f"SSL certificate EXPIRED ({abs(days_left)} days ago) +18")
        elif days_left < 15:
            score += 10
            rules.append(f"SSL certificate expiring very soon ({days_left} days) +10")
        elif days_left < 30:
            score += 5
            rules.append(f"SSL certificate expiring soon ({days_left} days) +5")

        result["rule_score"]      = min(score, 20)
        result["rules_triggered"] = rules

    except ssl.SSLError as e:
        result["rule_score"]      = 18
        result["rules_triggered"] = [f"SSL validation failed: {str(e)[:60]} +18"]
    except (socket.timeout, socket.gaierror, ConnectionRefusedError) as e:
        result["rule_score"]      = 8
        result["rules_triggered"] = [f"Could not connect to host for SSL check +8"]
    except Exception as e:
        result["rule_score"]      = 5
        result["rules_triggered"] = [f"SSL check error: {str(e)[:50]} +5"]

    return result


# ─── Parameter 4: Blacklist Check ────────────────────────────────────────────
def check_blacklist(url: str) -> dict:
    """
    Checks the URL against known threat databases.
    Uses local sample list + optional Google Safe Browsing API stub.
    """
    ext        = tldextract.extract(url)
    registered = f"{ext.domain}.{ext.suffix}" if ext.suffix else ext.domain
    full_lower = url.lower()

    is_blacklisted    = False
    blacklist_sources = []

    # Local blacklist
    if registered in BLACKLISTED_DOMAINS_SAMPLE:
        is_blacklisted = True
        blacklist_sources.append("Local Threat Database")

    # Hash-based check (MD5 of domain, simulates GSB-style lookup)
    domain_hash = hashlib.md5(registered.encode()).hexdigest()
    # In production: submit hash prefix to Google Safe Browsing API v4
    # Here we simulate a deterministic "hit" for demo domains
    DEMO_MALICIOUS_HASHES = {"7f3a0f4d2b8c1e9a", "a1b2c3d4e5f67890"}
    if domain_hash[:16] in DEMO_MALICIOUS_HASHES:
        is_blacklisted = True
        blacklist_sources.append("Threat Hash Database")

    score = 0
    rules = []
    if is_blacklisted:
        score = 40
        rules.append(f"Domain flagged in blacklist ({', '.join(blacklist_sources)}) +40")

    return {
        "is_blacklisted":    is_blacklisted,
        "blacklist_sources": blacklist_sources,
        "rule_score":        score,
        "rules_triggered":   rules,
    }


# ─── Parameter 5: Redirect Chain Analysis ────────────────────────────────────
def analyze_redirects(url: str) -> dict:
    """
    Follows the redirect chain and analyzes each hop for anomalies.
    """
    result = {
        "redirect_count":       0,
        "redirect_chain":       [],
        "final_url":            url,
        "crosses_domains":      False,
        "has_suspicious_hops":  False,
        "rule_score":           0,
        "rules_triggered":      [],
    }

    try:
        session = requests.Session()
        session.max_redirects = MAX_REDIRECTS
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                          "AppleWebKit/537.36 Chrome/120 SafeLink-Scanner/1.0"
        }

        resp = session.get(
            url,
            allow_redirects=True,
            timeout=REQUEST_TIMEOUT,
            headers=headers,
            verify=False,  # We handle SSL separately
            stream=True,
        )
        # Close connection immediately (we only need headers)
        resp.close()

        chain = []
        for r in resp.history:
            chain.append({
                "url":         r.url,
                "status_code": r.status_code,
                "scheme":      urllib.parse.urlparse(r.url).scheme,
            })

        chain.append({
            "url":         resp.url,
            "status_code": resp.status_code,
            "scheme":      urllib.parse.urlparse(resp.url).scheme,
        })

        result["redirect_count"] = len(resp.history)
        result["redirect_chain"] = chain
        result["final_url"]      = resp.url

        # Cross-domain hop detection
        domains_visited = set()
        for hop in chain:
            ext = tldextract.extract(hop["url"])
            domains_visited.add(f"{ext.domain}.{ext.suffix}")
        result["crosses_domains"] = len(domains_visited) > 2

        # Suspicious hop: HTTP → HTTPS downgrade
        for i in range(len(chain) - 1):
            if chain[i]["scheme"] == "https" and chain[i + 1]["scheme"] == "http":
                result["has_suspicious_hops"] = True
                break

        # ── Rule scoring ──────────────────────────────────────────────────────
        score = 0
        rules = []

        rc = result["redirect_count"]
        if rc >= 5:
            score += 15
            rules.append(f"Excessive redirects ({rc} hops) +15")
        elif rc >= 3:
            score += 8
            rules.append(f"Multiple redirects ({rc} hops) +8")

        if result["crosses_domains"]:
            score += 10
            rules.append(f"Redirect chain crosses {len(domains_visited)} different domains +10")

        if result["has_suspicious_hops"]:
            score += 12
            rules.append("HTTPS → HTTP downgrade in redirect chain (security degradation) +12")

        result["rule_score"]      = min(score, 20)
        result["rules_triggered"] = rules

    except requests.exceptions.TooManyRedirects:
        result["redirect_count"]  = MAX_REDIRECTS
        result["rule_score"]      = 18
        result["rules_triggered"] = [f"Redirect loop detected (>{MAX_REDIRECTS} redirects) +18"]
    except requests.exceptions.SSLError:
        result["rule_score"]      = 5
        result["rules_triggered"] = ["SSL error during redirect follow +5"]
    except requests.exceptions.ConnectionError:
        result["rule_score"]      = 5
        result["rules_triggered"] = ["Could not connect to host for redirect analysis +5"]
    except requests.exceptions.Timeout:
        result["rule_score"]      = 3
        result["rules_triggered"] = ["Connection timed out during redirect check +3"]
    except Exception as e:
        result["rule_score"]      = 3
        result["rules_triggered"] = [f"Redirect analysis error: {str(e)[:50]} +3"]

    return result


# ─── Composite Scanner ────────────────────────────────────────────────────────
def scan_url(url: str) -> dict:
    """
    Orchestrates all 5 security parameter analyses and aggregates results.
    Returns a unified scan_data dict ready for ML scoring and DB storage.
    """
    # Normalize URL
    url = url.strip()
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    # Validate URL format
    parsed = urllib.parse.urlparse(url)
    if not parsed.netloc:
        return {"error": "Invalid URL format. Please include a valid domain."}

    ext    = tldextract.extract(url)
    domain = f"{ext.domain}.{ext.suffix}" if ext.suffix else ext.domain

    # ── Run all 5 parameter analyses ─────────────────────────────────────────
    url_struct = analyze_url_structure(url)
    domain_info = analyze_domain(url)
    ssl_info    = analyze_ssl(url)
    blacklist   = check_blacklist(url)
    redirects   = analyze_redirects(url)

    # ── Aggregate rule scores ─────────────────────────────────────────────────
    total_rule_score = (
        url_struct["rule_score"]   +
        domain_info["rule_score"]  +
        ssl_info["rule_score"]     +
        blacklist["rule_score"]    +
        redirects["rule_score"]
    )
    total_rule_score = min(total_rule_score, 100)

    # ── Build all triggered rules list ────────────────────────────────────────
    all_rules = (
        url_struct["rules_triggered"]  +
        domain_info["rules_triggered"] +
        ssl_info["rules_triggered"]    +
        blacklist["rules_triggered"]   +
        redirects["rules_triggered"]
    )

    # ── Feature vector for ML ─────────────────────────────────────────────────
    feature_vector = {
        "url_length":          url_struct["url_length"],
        "num_subdomains":      url_struct["num_subdomains"],
        "has_https":           int(ssl_info["has_https"]),
        "domain_age_days":     domain_info["domain_age_days"],
        "redirect_count":      redirects["redirect_count"],
        "is_blacklisted":      int(blacklist["is_blacklisted"]),
        "has_ip_in_url":       int(url_struct["has_ip_in_url"]),
        "suspicious_patterns": url_struct["suspicious_patterns"],
        "has_valid_ssl":       int(ssl_info["has_valid_ssl"]),
        "special_char_count":  url_struct["special_char_count"],
        "num_hyphens":         url_struct["num_hyphens"],
        "path_depth":          url_struct["path_depth"],
        "pct_encoded_count":   url_struct["pct_encoded_count"],
        "has_at_symbol":       int(url_struct["has_at_symbol"]),
        "is_url_shortener":    int(url_struct["is_url_shortener"]),
    }

    return {
        # Identifiers
        "url":    url,
        "domain": domain,

        # Parameter results
        "url_struct":   url_struct,
        "domain_info":  domain_info,
        "ssl_info":     ssl_info,
        "blacklist":    blacklist,
        "redirects":    redirects,

        # Scoring inputs
        "rule_score":     total_rule_score,
        "all_rules":      all_rules,
        "feature_vector": feature_vector,

        # Flat features (for DB storage)
        "url_length":          url_struct["url_length"],
        "num_subdomains":      url_struct["num_subdomains"],
        "has_https":           ssl_info["has_https"],
        "domain_age_days":     domain_info["domain_age_days"],
        "redirect_count":      redirects["redirect_count"],
        "is_blacklisted":      blacklist["is_blacklisted"],
        "has_ip_in_url":       url_struct["has_ip_in_url"],
        "suspicious_patterns": url_struct["suspicious_patterns"],
        "has_valid_ssl":       ssl_info["has_valid_ssl"],
        "special_char_count":  url_struct["special_char_count"],
        "redirect_chain":      redirects["redirect_chain"],
    }
