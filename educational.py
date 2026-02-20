"""
SafeLink - Educational Explanation Engine
Generates dynamic, user-friendly cybersecurity insights based on scan results.
"""

from typing import Any


# ─── Knowledge Base ───────────────────────────────────────────────────────────
THREAT_LIBRARY = {

    "ip_in_url": {
        "title":       "IP Address Used Instead of Domain Name",
        "severity":    "High",
        "icon":        "🔢",
        "explanation": (
            "Legitimate websites use memorable domain names (e.g., bank.com). "
            "When a URL uses a raw IP address like http://192.168.1.1/login, "
            "it's a classic sign of phishing or malware infrastructure. "
            "Attackers use IP addresses to avoid domain registration scrutiny "
            "and make their infrastructure harder to track and block."
        ),
        "what_to_do": [
            "Do NOT click on or visit this link.",
            "Report the URL to your organization's IT security team.",
            "If you accidentally visited it, run a malware scan immediately.",
        ],
        "learn_more": "OWASP Top 10: Injection & Phishing Techniques",
    },

    "no_https": {
        "title":       "No HTTPS (Unencrypted Connection)",
        "severity":    "High",
        "icon":        "🔓",
        "explanation": (
            "HTTPS (HyperText Transfer Protocol Secure) encrypts data between "
            "your browser and the website using TLS/SSL. Without HTTPS, "
            "all data — including passwords and credit card numbers — travels "
            "in plaintext and can be intercepted by anyone on the same network "
            "(a 'man-in-the-middle' attack). Modern browsers show a 'Not Secure' "
            "warning for HTTP sites."
        ),
        "what_to_do": [
            "Avoid entering any personal information on HTTP sites.",
            "Look for the padlock icon (🔒) in your browser address bar.",
            "Consider using a VPN if you must use an unsecured network.",
        ],
        "learn_more": "Let's Encrypt: Why HTTPS Matters",
    },

    "invalid_ssl": {
        "title":       "Invalid or Untrusted SSL Certificate",
        "severity":    "High",
        "icon":        "⚠️",
        "explanation": (
            "An SSL certificate authenticates a website's identity and enables "
            "encryption. Invalid certificates — expired, self-signed, or issued "
            "to a different domain — are major red flags. Phishing sites often "
            "use free, short-lived certificates or self-signed certs to display "
            "a padlock icon while still being fraudulent."
        ),
        "what_to_do": [
            "Do not bypass SSL certificate warnings in your browser.",
            "Check the certificate details by clicking the padlock icon.",
            "Verify you are on the correct domain and the cert is issued by a trusted CA.",
        ],
        "learn_more": "DigiCert: SSL Certificate Types Explained",
    },

    "new_domain": {
        "title":       "Newly Registered or Very Young Domain",
        "severity":    "Medium",
        "icon":        "🆕",
        "explanation": (
            "Studies by Palo Alto Unit 42 found that over 70% of malicious domains "
            "are registered less than 90 days before their first attack. "
            "Phishers register domains quickly, use them for a short campaign, "
            "then abandon them. A domain less than 6 months old warrants extra "
            "caution, especially if it mimics a well-known brand."
        ),
        "what_to_do": [
            "Search for the organization through a trusted search engine instead.",
            "Check the official website via your bookmarks or typed URL.",
            "Hover over links before clicking to preview the actual destination.",
        ],
        "learn_more": "CISA: Recognizing Phishing Emails and Websites",
    },

    "blacklisted": {
        "title":       "URL Found in Threat Blacklist",
        "severity":    "Critical",
        "icon":        "☠️",
        "explanation": (
            "This URL has been flagged by security researchers or automated "
            "threat intelligence systems as malicious. Blacklists aggregate "
            "reports from honeypots, spam traps, user reports, and automated "
            "crawlers. A blacklist match is one of the strongest indicators "
            "of a malicious site."
        ),
        "what_to_do": [
            "STOP — do not proceed to this URL under any circumstances.",
            "If clicked, change any passwords you may have entered.",
            "Run a full antivirus/malware scan on your device.",
            "Report the URL via Google Safe Browsing or VirusTotal.",
        ],
        "learn_more": "Google Safe Browsing: Protecting Users from Malware",
    },

    "excessive_redirects": {
        "title":       "Excessive or Suspicious Redirect Chain",
        "severity":    "Medium",
        "icon":        "🔀",
        "explanation": (
            "Redirect chains route your browser through multiple URLs before "
            "landing on the final destination. While some redirects are legitimate "
            "(e.g., link tracking), excessive or cross-domain redirects are "
            "commonly used in click fraud, ad injection, and phishing kits "
            "to obscure the true destination and bypass URL filters."
        ),
        "what_to_do": [
            "Use a URL expander (e.g., checkshorturl.com) to preview the final destination.",
            "Be wary of links from emails or social media with many redirects.",
            "Enable redirect blocking in your browser security settings.",
        ],
        "learn_more": "Cloudflare: How HTTP Redirects Work",
    },

    "phishing_keywords": {
        "title":       "Phishing Keywords Detected in URL",
        "severity":    "Medium",
        "icon":        "🎣",
        "explanation": (
            "Phishing URLs often contain urgency-triggering words like 'verify', "
            "'secure', 'account-update', 'login-confirm', or brand names to "
            "appear legitimate. Social engineering exploits psychological triggers "
            "— fear, urgency, authority — to make you act without thinking. "
            "URLs with multiple such keywords are statistically more likely to "
            "be phishing attempts."
        ),
        "what_to_do": [
            "Pause and think before clicking urgency-driven links.",
            "Go directly to the organization's official website instead.",
            "Contact the organization through official channels to verify.",
        ],
        "learn_more": "Anti-Phishing Working Group (APWG): Phishing Trends",
    },

    "suspicious_tld": {
        "title":       "High-Risk Top-Level Domain (TLD)",
        "severity":    "Medium",
        "icon":        "🌐",
        "explanation": (
            "Certain TLDs like .tk, .ml, .ga, .cf, and .gq are offered for free "
            "or at very low cost, making them attractive to cybercriminals. "
            "These domains account for a disproportionately high percentage of "
            "malware and phishing sites. While not all sites on these TLDs are "
            "malicious, they warrant heightened scrutiny."
        ),
        "what_to_do": [
            "Exercise extra caution with free/low-cost TLDs.",
            "Verify the site's legitimacy through independent research.",
            "Use a web of trust browser extension for additional protection.",
        ],
        "learn_more": "Spamhaus: Domain Blocklists and TLD Statistics",
    },

    "url_shortener": {
        "title":       "URL Shortener Hides True Destination",
        "severity":    "Low",
        "icon":        "🔗",
        "explanation": (
            "URL shorteners (bit.ly, t.co, tinyurl) compress long URLs into "
            "short codes, hiding the actual destination. While widely used for "
            "legitimate purposes, they're also used to disguise malicious links "
            "in social media, emails, and QR codes. You cannot assess the risk "
            "of a shortened URL without first revealing its destination."
        ),
        "what_to_do": [
            "Use a URL preview service before clicking shortened links.",
            "Hover over links in email clients that show full URL previews.",
            "If in doubt, don't click — search for the content directly.",
        ],
        "learn_more": "EFF: URL Shorteners and Privacy/Security Risks",
    },

    "punycode": {
        "title":       "Possible IDN Homograph Attack",
        "severity":    "High",
        "icon":        "🔤",
        "explanation": (
            "International Domain Names (IDN) allow non-ASCII characters in URLs. "
            "Attackers exploit look-alike characters (e.g., Cyrillic 'а' vs Latin 'a') "
            "to register domains that appear identical to legitimate ones. "
            "Punycode encoding (xn--) is used to represent these characters. "
            "Example: pаypаl.com (with Cyrillic 'а') could look identical to paypal.com."
        ),
        "what_to_do": [
            "Enable IDN display settings in your browser to see the true domain.",
            "Type important URLs manually rather than clicking links.",
            "Install a browser extension that highlights homograph attacks.",
        ],
        "learn_more": "ICANN: Internationalized Domain Names and Security",
    },

    "encoded_obfuscation": {
        "title":       "URL Encoding Used for Obfuscation",
        "severity":    "Medium",
        "icon":        "🔏",
        "explanation": (
            "URLs can use percent-encoding to represent characters (e.g., %2F for /). "
            "While normal for special characters in parameters, excessive encoding "
            "of simple characters is a classic obfuscation technique used to "
            "bypass URL scanners and hide malicious paths or payloads. "
            "Double encoding (%2525 = %25 = %) adds another layer of deception."
        ),
        "what_to_do": [
            "Use a URL decoder tool to reveal the true URL before visiting.",
            "Be suspicious of URLs with many % sequences outside of query parameters.",
            "Report suspected obfuscated URLs to your security team.",
        ],
        "learn_more": "OWASP: URL Encoding and Injection Attacks",
    },

    "anomaly_detected": {
        "title":       "Anomalous Behavior Detected by AI Engine",
        "severity":    "Medium",
        "icon":        "🤖",
        "explanation": (
            "SafeLink's Isolation Forest AI model identified this URL as statistically "
            "anomalous — its feature profile differs significantly from the normal "
            "distribution of safe URLs. This can indicate zero-day phishing sites, "
            "newly created malicious infrastructure, or sophisticated attack patterns "
            "not yet in any blacklist. AI anomaly detection catches threats that "
            "rule-based systems miss."
        ),
        "what_to_do": [
            "Treat this URL with caution even if it appears superficially legitimate.",
            "Verify through multiple independent sources before visiting.",
            "Submit to VirusTotal for a second opinion from 70+ AV engines.",
        ],
        "learn_more": "MIT Lincoln Lab: Anomaly Detection in Cybersecurity",
    },

    "general_safe": {
        "title":       "URL Appears Safe",
        "severity":    "Info",
        "icon":        "✅",
        "explanation": (
            "No significant threat indicators were detected in this URL. "
            "The domain is established, HTTPS is properly configured, "
            "and no suspicious patterns were found. However, no automated "
            "system is 100% accurate — always exercise caution when entering "
            "sensitive information online."
        ),
        "what_to_do": [
            "Stay vigilant — even safe-looking sites can be compromised.",
            "Use a password manager to avoid reusing credentials.",
            "Enable two-factor authentication (2FA) on important accounts.",
        ],
        "learn_more": "NIST Cybersecurity Framework: Protect Your Digital Life",
    },
}


CYBERSECURITY_TIPS = [
    "💡 Always look for HTTPS and the padlock icon before entering personal information.",
    "💡 Hover over links before clicking to preview their actual destination.",
    "💡 Use a password manager to create and store unique passwords for each site.",
    "💡 Enable two-factor authentication (2FA) wherever possible.",
    "💡 Keep your browser and operating system updated to patch security vulnerabilities.",
    "💡 Be skeptical of urgent messages asking you to 'act now' — it's a social engineering tactic.",
    "💡 Use a VPN when connecting to public Wi-Fi networks.",
    "💡 Regularly check haveibeenpwned.com to see if your email has appeared in data breaches.",
    "💡 DNS over HTTPS (DoH) protects your browsing queries from network eavesdroppers.",
    "💡 Zero-day vulnerabilities are threats not yet in any database — AI anomaly detection helps catch these.",
]


# ─── Explanation Generator ────────────────────────────────────────────────────
def generate_educational_insights(scan_data: dict) -> list[dict]:
    """
    Analyzes scan results and returns a ranked list of educational insights
    tailored to the specific threats found in this URL.
    """
    insights   = []
    added_keys = set()

    def add_insight(key: str):
        if key not in added_keys and key in THREAT_LIBRARY:
            insights.append(THREAT_LIBRARY[key])
            added_keys.add(key)

    # ── Priority checks (Critical first) ─────────────────────────────────────
    if scan_data.get("is_blacklisted"):
        add_insight("blacklisted")

    if scan_data.get("has_ip_in_url"):
        add_insight("ip_in_url")

    if not scan_data.get("has_https"):
        add_insight("no_https")

    if not scan_data.get("has_valid_ssl") and scan_data.get("has_https"):
        add_insight("invalid_ssl")

    url_struct = scan_data.get("url_struct", {})

    if url_struct.get("has_punycode"):
        add_insight("punycode")

    if url_struct.get("has_at_symbol"):
        add_insight("phishing_keywords")

    # ── Domain age ────────────────────────────────────────────────────────────
    age = scan_data.get("domain_age_days", -1)
    if age != -1 and age < 180:
        add_insight("new_domain")

    # ── Redirects ─────────────────────────────────────────────────────────────
    if scan_data.get("redirect_count", 0) >= 3:
        add_insight("excessive_redirects")

    # ── Phishing keywords ─────────────────────────────────────────────────────
    if scan_data.get("suspicious_patterns", 0) >= 1:
        add_insight("phishing_keywords")

    # ── URL Shortener ─────────────────────────────────────────────────────────
    if url_struct.get("is_url_shortener"):
        add_insight("url_shortener")

    # ── Suspicious TLD ────────────────────────────────────────────────────────
    if url_struct.get("has_suspicious_tld"):
        add_insight("suspicious_tld")

    # ── URL encoding ─────────────────────────────────────────────────────────
    if url_struct.get("pct_encoded_count", 0) >= 3:
        add_insight("encoded_obfuscation")

    # ── ML anomaly ────────────────────────────────────────────────────────────
    if scan_data.get("is_anomaly") and scan_data.get("anomaly_confidence") in ("High", "Medium"):
        add_insight("anomaly_detected")

    # ── Default safe message if no threats ────────────────────────────────────
    if not insights:
        add_insight("general_safe")

    return insights


def get_threat_summary(scan_data: dict) -> dict:
    """
    Returns a concise threat summary for display in the results panel.
    """
    risk_score   = scan_data.get("risk_score", 0)
    threat_level = scan_data.get("threat_level", "Unknown")

    if threat_level == "High Risk":
        summary = (
            "⚠️ This URL exhibits multiple high-risk indicators. "
            "Do not proceed. The site may attempt to steal your credentials, "
            "install malware, or defraud you."
        )
    elif threat_level == "Suspicious":
        summary = (
            "🔍 This URL has some suspicious characteristics. "
            "Proceed with extreme caution. Verify the site's legitimacy "
            "through official channels before entering any information."
        )
    else:
        summary = (
            "✅ No critical threats were detected. This URL appears relatively safe "
            "based on our analysis. Still, maintain healthy skepticism online."
        )

    return {
        "summary":       summary,
        "threat_level":  threat_level,
        "risk_score":    risk_score,
        "threat_count":  len([r for r in scan_data.get("all_rules", []) if r]),
    }


def get_random_tip() -> str:
    """Returns a random cybersecurity awareness tip."""
    import random
    return random.choice(CYBERSECURITY_TIPS)


def format_educational_tips_for_db(insights: list[dict]) -> list[str]:
    """Serialize insight titles for compact DB storage."""
    return [f"{i.get('icon','')} {i.get('title','')}" for i in insights]
