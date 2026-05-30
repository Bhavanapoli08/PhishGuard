"""
WHOIS Analysis Module
---------------------
Performs domain registration forensics — a core technique in CTI
(Cyber Threat Intelligence) and incident response.

Red flags we look for:
  * Domain registered very recently (< 90 days)        -> phishers use fresh domains
  * Privacy-protected registrant ("Domains By Proxy", "WhoisGuard")
  * Domain expiring soon (< 30 days)                   -> throwaway domain
  * Registrant country mismatch with claimed brand
  * Free / commonly-abused TLDs (.tk, .ml, .ga, .cf, .gq, .xyz, .top)
"""

from datetime import datetime, timezone
from urllib.parse import urlparse

import whois

ABUSED_TLDS = {".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top",
               ".click", ".loan", ".work", ".country", ".kim"}

PRIVACY_PROXIES = ["privacy", "whoisguard", "domains by proxy",
                   "perfect privacy", "withheld for privacy",
                   "redacted for privacy", "data protected"]


def _to_date(value):
    """WHOIS libraries return dates as datetime, list, or string. Normalise it."""
    if value is None:
        return None
    if isinstance(value, list):
        value = value[0] if value else None
    if isinstance(value, str):
        try:
            from dateutil.parser import parse
            value = parse(value)
        except Exception:
            return None
    if isinstance(value, datetime):
        # Strip tz for safe arithmetic
        return value.replace(tzinfo=None)
    return None


def analyse(url: str) -> dict:
    """
    Returns a structured WHOIS report with a risk score (0..100).
    """
    report = {
        "domain": None,
        "registrar": None,
        "registrant_country": None,
        "creation_date": None,
        "expiration_date": None,
        "age_days": None,
        "expires_in_days": None,
        "privacy_protected": False,
        "abused_tld": False,
        "flags": [],
        "score": 0,
    }

    try:
        domain = urlparse(url).netloc.lower()
        if domain.startswith("www."):
            domain = domain[4:]
        report["domain"] = domain
    except Exception:
        report["flags"].append("Unable to parse domain from URL")
        return report

    # TLD check is cheap and always works, do it first
    for tld in ABUSED_TLDS:
        if domain.endswith(tld):
            report["abused_tld"] = True
            report["flags"].append(f"Uses abused free TLD ({tld})")
            report["score"] += 20
            break

    # WHOIS lookup
    try:
        w = whois.whois(domain)
    except Exception as e:
        report["flags"].append(f"WHOIS lookup failed: {str(e)[:60]}")
        report["score"] += 10  # unknown is mildly risky
        return report

    report["registrar"] = str(w.registrar) if w.registrar else None
    report["registrant_country"] = str(w.country) if w.country else None

    creation = _to_date(w.creation_date)
    expiry = _to_date(w.expiration_date)
    now = datetime.utcnow()

    if creation:
        report["creation_date"] = creation.isoformat()
        age = (now - creation).days
        report["age_days"] = age
        if age < 30:
            report["flags"].append(f"Domain very new ({age} days old)")
            report["score"] += 35
        elif age < 90:
            report["flags"].append(f"Domain young ({age} days old)")
            report["score"] += 20
        elif age < 180:
            report["score"] += 5
    else:
        report["flags"].append("Creation date unavailable")
        report["score"] += 5

    if expiry:
        report["expiration_date"] = expiry.isoformat()
        rem = (expiry - now).days
        report["expires_in_days"] = rem
        if rem < 30:
            report["flags"].append(f"Domain expires in {rem} days")
            report["score"] += 15

    # Privacy proxy detection
    fields_to_scan = " ".join(filter(None, [
        str(w.registrar or ""),
        str(w.name or ""),
        str(w.org or ""),
        str(w.emails or ""),
    ])).lower()
    for marker in PRIVACY_PROXIES:
        if marker in fields_to_scan:
            report["privacy_protected"] = True
            report["flags"].append("Registrant uses privacy/proxy service")
            report["score"] += 10
            break

    report["score"] = min(100, report["score"])
    return report
