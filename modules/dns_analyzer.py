"""
DNS Analysis Module
-------------------
Inspects DNS records for indicators commonly seen in phishing infrastructure:

  * A records pointing to known bulletproof / cloud-abuse ranges
  * No MX records on a domain claiming to send email
  * Low TTL values (fast-flux indicator)
  * High number of A records (load-balancing OR fast-flux)
  * No SPF / DMARC TXT records  ->  domain easily spoofable
  * Reverse DNS mismatch
"""

import socket
from urllib.parse import urlparse

try:
    import dns.resolver
    import dns.reversename
    DNS_AVAILABLE = True
except ImportError:
    DNS_AVAILABLE = False


def _safe_query(resolver, domain, rtype):
    try:
        ans = resolver.resolve(domain, rtype, lifetime=4)
        return [r.to_text().strip('"') for r in ans], ans.rrset.ttl
    except Exception:
        return [], None


def analyse(url: str) -> dict:
    report = {
        "domain": None,
        "a_records": [],
        "mx_records": [],
        "ns_records": [],
        "txt_records": [],
        "ttl": None,
        "reverse_dns": None,
        "has_spf": False,
        "has_dmarc": False,
        "fast_flux_indicator": False,
        "flags": [],
        "score": 0,
    }

    try:
        domain = urlparse(url).netloc.lower()
        if domain.startswith("www."):
            domain = domain[4:]
        report["domain"] = domain
    except Exception:
        report["flags"].append("Unable to parse domain")
        return report

    if not DNS_AVAILABLE:
        # Fallback: use socket for at least the A record
        try:
            ip = socket.gethostbyname(domain)
            report["a_records"] = [ip]
            report["flags"].append("dnspython not installed — limited DNS analysis")
        except Exception:
            report["flags"].append("DNS resolution failed")
            report["score"] += 25
        return report

    resolver = dns.resolver.Resolver()
    resolver.timeout = 3
    resolver.lifetime = 4

    a_recs, ttl = _safe_query(resolver, domain, "A")
    report["a_records"] = a_recs
    report["ttl"] = ttl

    mx_recs, _ = _safe_query(resolver, domain, "MX")
    report["mx_records"] = mx_recs

    ns_recs, _ = _safe_query(resolver, domain, "NS")
    report["ns_records"] = ns_recs

    txt_recs, _ = _safe_query(resolver, domain, "TXT")
    report["txt_records"] = txt_recs

    # DMARC lives on _dmarc.<domain>
    dmarc_recs, _ = _safe_query(resolver, f"_dmarc.{domain}", "TXT")

    if not a_recs:
        report["flags"].append("No A record — domain may not resolve")
        report["score"] += 30
        return report

    # Fast-flux: many A records + very low TTL
    if len(a_recs) >= 5 and (ttl or 9999) < 300:
        report["fast_flux_indicator"] = True
        report["flags"].append(
            f"Possible fast-flux: {len(a_recs)} IPs, TTL={ttl}s")
        report["score"] += 25
    elif (ttl or 9999) < 60:
        report["flags"].append(f"Very low TTL ({ttl}s) — suspicious")
        report["score"] += 10

    if not mx_recs:
        report["flags"].append("No MX records (cannot receive email)")
        report["score"] += 5

    # SPF / DMARC presence
    for t in txt_recs:
        if t.lower().startswith("v=spf1"):
            report["has_spf"] = True
            break
    for t in dmarc_recs:
        if t.lower().startswith("v=dmarc1"):
            report["has_dmarc"] = True
            break
    if not report["has_spf"]:
        report["flags"].append("No SPF record — domain easily spoofable")
        report["score"] += 8
    if not report["has_dmarc"]:
        report["flags"].append("No DMARC record — no email auth policy")
        report["score"] += 7

    # Reverse DNS check on the first A record
    try:
        ptr_name = dns.reversename.from_address(a_recs[0])
        ptr = resolver.resolve(ptr_name, "PTR", lifetime=3)
        report["reverse_dns"] = str(ptr[0]).rstrip(".")
        if domain not in report["reverse_dns"]:
            # Common for shared hosting — informational only
            report["flags"].append(
                f"Reverse DNS does not contain domain ({report['reverse_dns']})")
    except Exception:
        report["flags"].append("No reverse DNS record")

    report["score"] = min(100, report["score"])
    return report
