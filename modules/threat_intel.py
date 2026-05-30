"""
Threat Intelligence Module
--------------------------
Queries multiple external threat-intel sources and aggregates verdicts.
This implements the defense-in-depth principle: never trust a single source.

Sources:
  1. Google Safe Browsing  (free with API key)
  2. VirusTotal            (free tier: 4 req/min with API key)
  3. PhishTank local feed  (cached blocklist, no key required)

If API keys are not provided, the corresponding source is skipped gracefully
and the analyst sees "SKIPPED" in the dashboard instead of a hard failure.
"""

import hashlib
import json
import os
import time
from urllib.parse import quote_plus

import requests

# ---------------------------------------------------------------------------
# Configuration — keys are loaded from environment variables.
# Set them before running:
#   export GOOGLE_SAFE_BROWSING_KEY="..."
#   export VIRUSTOTAL_KEY="..."
# Without keys the module still works in DEMO MODE (uses a local blocklist).
# ---------------------------------------------------------------------------
GSB_KEY = os.environ.get("GOOGLE_SAFE_BROWSING_KEY", "")
VT_KEY = os.environ.get("VIRUSTOTAL_KEY", "")

PHISHTANK_CACHE = os.path.join(
    os.path.dirname(__file__), "..", "data", "phishtank_cache.txt"
)


def _check_google_safe_browsing(url: str) -> dict:
    """Query Google Safe Browsing v4 lookup endpoint."""
    if not GSB_KEY:
        return {"source": "Google Safe Browsing", "status": "SKIPPED",
                "verdict": "unknown", "detail": "No API key configured"}

    endpoint = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={GSB_KEY}"
    payload = {
        "client": {"clientId": "phishguard", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING",
                            "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}],
        },
    }
    try:
        r = requests.post(endpoint, json=payload, timeout=6)
        if r.status_code != 200:
            return {"source": "Google Safe Browsing", "status": "ERROR",
                    "verdict": "unknown", "detail": f"HTTP {r.status_code}"}
        matches = r.json().get("matches", [])
        if matches:
            threat = matches[0].get("threatType", "THREAT")
            return {"source": "Google Safe Browsing", "status": "OK",
                    "verdict": "malicious",
                    "detail": f"Flagged as {threat}"}
        return {"source": "Google Safe Browsing", "status": "OK",
                "verdict": "clean", "detail": "No match in Google's database"}
    except Exception as e:
        return {"source": "Google Safe Browsing", "status": "ERROR",
                "verdict": "unknown", "detail": str(e)[:80]}


def _check_virustotal(url: str) -> dict:
    """Query VirusTotal v3 — returns how many AV engines flag the URL."""
    if not VT_KEY:
        return {"source": "VirusTotal", "status": "SKIPPED",
                "verdict": "unknown", "detail": "No API key configured"}

    # VT uses base64url-encoded URL as the resource ID
    import base64
    url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
    endpoint = f"https://www.virustotal.com/api/v3/urls/{url_id}"
    headers = {"x-apikey": VT_KEY}
    try:
        r = requests.get(endpoint, headers=headers, timeout=8)
        if r.status_code == 404:
            return {"source": "VirusTotal", "status": "OK",
                    "verdict": "unknown",
                    "detail": "URL not previously scanned by VT"}
        if r.status_code != 200:
            return {"source": "VirusTotal", "status": "ERROR",
                    "verdict": "unknown", "detail": f"HTTP {r.status_code}"}
        stats = r.json()["data"]["attributes"]["last_analysis_stats"]
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        total = sum(stats.values()) or 1
        if malicious + suspicious >= 3:
            verdict = "malicious"
        elif malicious + suspicious >= 1:
            verdict = "suspicious"
        else:
            verdict = "clean"
        return {"source": "VirusTotal", "status": "OK", "verdict": verdict,
                "detail": f"{malicious} malicious / {suspicious} suspicious of {total} engines"}
    except Exception as e:
        return {"source": "VirusTotal", "status": "ERROR",
                "verdict": "unknown", "detail": str(e)[:80]}


def _check_phishtank_local(url: str) -> dict:
    """
    Check against a local PhishTank-style blocklist.
    Demonstrates how blocklist-feeds work in real EDR/SWG products.
    """
    try:
        if not os.path.exists(PHISHTANK_CACHE):
            return {"source": "PhishTank (local feed)", "status": "SKIPPED",
                    "verdict": "unknown",
                    "detail": "Local feed not initialised"}
        with open(PHISHTANK_CACHE, "r") as f:
            blocklist = {line.strip().lower() for line in f if line.strip()
                         and not line.startswith("#")}
        url_lower = url.lower().rstrip("/")
        # exact match OR domain match
        from urllib.parse import urlparse
        domain = urlparse(url_lower).netloc
        if url_lower in blocklist or domain in blocklist:
            return {"source": "PhishTank (local feed)", "status": "OK",
                    "verdict": "malicious",
                    "detail": "URL/domain in PhishTank feed"}
        return {"source": "PhishTank (local feed)", "status": "OK",
                "verdict": "clean", "detail": f"{len(blocklist)} entries scanned"}
    except Exception as e:
        return {"source": "PhishTank (local feed)", "status": "ERROR",
                "verdict": "unknown", "detail": str(e)[:80]}


def query_all_sources(url: str) -> dict:
    """
    Run every TI source and return a consolidated report.

    Output shape:
        {
          "sources": [ {source, status, verdict, detail}, ... ],
          "malicious_hits": int,
          "score": 0..100   # higher = more dangerous
        }
    """
    results = [
        _check_google_safe_browsing(url),
        _check_virustotal(url),
        _check_phishtank_local(url),
    ]

    malicious_hits = sum(1 for r in results if r["verdict"] == "malicious")
    suspicious_hits = sum(1 for r in results if r["verdict"] == "suspicious")

    # Risk contribution: each malicious source = 40 pts, suspicious = 15 pts
    score = min(100, malicious_hits * 40 + suspicious_hits * 15)

    return {
        "sources": results,
        "malicious_hits": malicious_hits,
        "suspicious_hits": suspicious_hits,
        "score": score,
    }
