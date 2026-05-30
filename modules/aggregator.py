"""
Risk Aggregator
---------------
Combines scores from every detection module into a single verdict using
weighted scoring — exactly how multi-engine security products work
(e.g. Microsoft Defender SmartScreen, Cisco Talos, Palo Alto WildFire).

Weights reflect signal reliability:
  Threat Intel  : 35 %   (high — based on real blocklists)
  Typosquatting : 20 %   (high — strong indicator when triggered)
  WHOIS         : 15 %   (medium — infrastructure age matters)
  DNS           : 10 %   (medium — supporting evidence)
  ML model      : 20 %   (medium — lexical features can be gamed)

Verdict bands:
  0–24    -> SAFE
  25–49   -> LOW RISK
  50–74   -> SUSPICIOUS
  75–100  -> DANGEROUS
"""

WEIGHTS = {
    "threat_intel": 0.35,
    "typosquat": 0.20,
    "ml": 0.20,
    "whois": 0.15,
    "dns": 0.10,
}


def aggregate(signals: dict) -> dict:
    """
    signals is a dict with keys: ml, threat_intel, whois, dns, typosquat.
    Each value must have a 'score' field (0..100).
    """
    weighted = 0.0
    breakdown = {}
    for key, weight in WEIGHTS.items():
        score = signals.get(key, {}).get("score", 0) or 0
        contribution = score * weight
        weighted += contribution
        breakdown[key] = {
            "raw_score": score,
            "weight": weight,
            "contribution": round(contribution, 2),
        }

    final = round(weighted, 1)

    if final < 25:
        verdict = "SAFE"
        color = "green"
    elif final < 50:
        verdict = "LOW RISK"
        color = "yellow"
    elif final < 75:
        verdict = "SUSPICIOUS"
        color = "orange"
    else:
        verdict = "DANGEROUS"
        color = "red"

    # Hard override: if Google Safe Browsing or VirusTotal explicitly flagged
    # the URL as malicious, force at least SUSPICIOUS regardless of other signals.
    ti_sources = signals.get("threat_intel", {}).get("sources", [])
    for s in ti_sources:
        if s.get("verdict") == "malicious" and s.get("status") == "OK":
            if verdict == "SAFE" or verdict == "LOW RISK":
                verdict = "SUSPICIOUS"
                color = "orange"
                final = max(final, 60.0)
            break

    return {
        "final_score": final,
        "verdict": verdict,
        "color": color,
        "breakdown": breakdown,
    }
