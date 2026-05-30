"""
Typosquatting & Homoglyph Detection
-----------------------------------
Detects domains that impersonate well-known brands via:

  1. Levenshtein distance (paypa1.com -> paypal.com)
  2. Character substitution (g00gle, faceb00k)
  3. Unicode homoglyphs / IDN attacks (аpple.com using Cyrillic 'а')
  4. Brand-as-subdomain (paypal.com.evil.tk)
  5. Brand + dash (paypal-secure-login.com)

No external libraries required — uses pure-Python Levenshtein.
"""

import re
from urllib.parse import urlparse

# Top brands phishers commonly impersonate.
# In production this would be loaded from a feed; for the project a static
# list is fine and easy to extend.
PROTECTED_BRANDS = [
    "paypal", "google", "facebook", "instagram", "amazon", "apple",
    "microsoft", "outlook", "office365", "linkedin", "twitter", "netflix",
    "whatsapp", "snapchat", "tiktok", "github", "dropbox", "adobe",
    "chase", "wellsfargo", "bankofamerica", "hsbc", "barclays",
    "icicibank", "hdfcbank", "sbi", "axisbank", "kotakbank",
    "paytm", "phonepe", "razorpay",
    "binance", "coinbase", "metamask",
    "dhl", "fedex", "ups", "irs", "gov",
]

# Common phishing decorators appended to brand names
DECORATORS = ["secure", "login", "signin", "verify", "account",
              "update", "support", "service", "auth", "wallet", "billing"]

# Cyrillic / Greek lookalikes that render almost identically to Latin
HOMOGLYPHS = {
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c",  # Cyrillic
    "х": "x", "у": "y", "і": "i", "ј": "j", "ѕ": "s",
    "α": "a", "ο": "o", "ρ": "p", "τ": "t",            # Greek
}


def _levenshtein(a: str, b: str) -> int:
    """Classic DP implementation — fine for short brand strings."""
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        curr = [i] + [0] * len(b)
        for j, cb in enumerate(b, 1):
            ins = curr[j - 1] + 1
            dele = prev[j] + 1
            sub = prev[j - 1] + (ca != cb)
            curr[j] = min(ins, dele, sub)
        prev = curr
    return prev[-1]


def _normalise_homoglyphs(s: str) -> str:
    """Replace lookalike Unicode chars with their Latin equivalents."""
    return "".join(HOMOGLYPHS.get(c, c) for c in s)


def _strip_digits_for_letter_match(s: str) -> str:
    """1 -> l, 0 -> o, 5 -> s, 3 -> e — common in g00gle, paypa1"""
    return s.translate(str.maketrans("01345", "olses"))


def analyse(url: str) -> dict:
    report = {
        "domain": None,
        "registered_domain": None,
        "matched_brand": None,
        "match_type": None,
        "edit_distance": None,
        "has_homoglyph": False,
        "flags": [],
        "score": 0,
    }

    try:
        netloc = urlparse(url).netloc.lower()
        if netloc.startswith("www."):
            netloc = netloc[4:]
        report["domain"] = netloc
        parts = netloc.split(".")
        # registered_domain = second-level label (the part before the TLD)
        registered = parts[-2] if len(parts) >= 2 else parts[0]
        report["registered_domain"] = registered
    except Exception:
        report["flags"].append("Cannot parse URL")
        return report

    # ----- 1. Homoglyph detection on the FULL netloc -----
    normalised = _normalise_homoglyphs(netloc)
    if normalised != netloc:
        report["has_homoglyph"] = True
        report["flags"].append(
            f"Domain contains non-Latin lookalike characters")
        report["score"] += 40
        # continue analysis using normalised form
        netloc = normalised
        registered = _normalise_homoglyphs(registered)

    # ----- 2. Brand-as-subdomain (paypal.com.evil.tk, paypal-verify.evil.tk) -----
    subdomain_labels = parts[:-2] if len(parts) > 2 else []
    for brand in PROTECTED_BRANDS:
        for label in subdomain_labels:
            if brand in label:
                report["matched_brand"] = brand
                report["match_type"] = "brand_in_subdomain"
                report["flags"].append(
                    f"Brand '{brand}' appears in subdomain '{label}' — classic phishing pattern")
                report["score"] += 50
                return report  # this is conclusive enough

    # ----- 3. Exact brand + decorator (paypal-secure-login.com,
    #         paypa1-secure-login.com via digit substitution) -----
    reg_clean = re.sub(r"[^a-z0-9]", "", registered)
    reg_normalised_digits = _strip_digits_for_letter_match(registered)
    for brand in PROTECTED_BRANDS:
        hit = ((brand in registered and registered != brand) or
               (brand in reg_normalised_digits and reg_normalised_digits != brand))
        if hit:
            for dec in DECORATORS:
                if dec in registered:
                    report["matched_brand"] = brand
                    report["match_type"] = "brand_plus_decorator"
                    report["flags"].append(
                        f"Brand '{brand}' combined with decorator '{dec}'")
                    report["score"] += 45
                    return report

    # ----- 4. Levenshtein + digit-substitution -----
    candidate = _strip_digits_for_letter_match(reg_clean)
    best = (None, 99)
    for brand in PROTECTED_BRANDS:
        # avoid false positive: exact match means legitimate domain
        if registered == brand or reg_clean == brand:
            continue
        # only compare if lengths are similar
        if abs(len(candidate) - len(brand)) > 2:
            continue
        dist = _levenshtein(candidate, brand)
        if dist < best[1]:
            best = (brand, dist)

    if best[0] and best[1] <= 2:
        report["matched_brand"] = best[0]
        report["edit_distance"] = best[1]
        report["match_type"] = "edit_distance"
        report["flags"].append(
            f"Domain '{registered}' is {best[1]} edit(s) away from '{best[0]}'")
        report["score"] += (50 - best[1] * 15)  # closer = riskier

    report["score"] = min(100, report["score"])
    return report
