"""
PhishGuard — Multi-Layer Phishing Detection Platform
====================================================
Orchestrates five independent detection signals, aggregates them with
weighted scoring, logs every scan to SQLite, and exposes a Flask UI plus
an analyst dashboard.

Architecture
------------
    Frontend (Flask UI)
          v
    URL Analyzer  (orchestrator below)
          v
    +-------------------------------+
    | ML Prediction                 |
    | Threat Intelligence (3 srcs)  |
    | WHOIS Analysis                |
    | DNS Analysis                  |
    | Typosquatting Detection       |
    +-------------------------------+
          v
    Risk Aggregator  (weighted scoring)
          v
    SQLite Logging   (audit trail)
          v
    Dashboard
"""

import hashlib
import re
from datetime import datetime
from urllib.parse import urlparse

from flask import Flask, jsonify, redirect, render_template, request, url_for

from modules import (
    aggregator,
    db,
    dns_analyzer,
    ml_signal,
    threat_intel,
    typosquat,
    whois_analyzer,
)

app = Flask(__name__)
db.init_db()


# ---------------------------------------------------------------------------
# Input validation — secure-coding practice. Reject malformed URLs early.
# ---------------------------------------------------------------------------
URL_RE = re.compile(
    r"^(https?://)"                       # scheme is mandatory
    r"([a-zA-Z0-9\-\.\u00a1-\uffff]+)"    # hostname incl. IDN
    r"(:[0-9]+)?"                         # optional port
    r"(/.*)?$"                            # optional path
)


def _validate(url: str):
    url = (url or "").strip()
    if not url:
        return None, "Empty URL"
    if len(url) > 2048:
        return None, "URL too long (>2048 chars)"
    if not url.lower().startswith(("http://", "https://")):
        url = "http://" + url  # tolerate user pasting bare domain
    if not URL_RE.match(url):
        return None, "Malformed URL"
    return url, None


def _client_ip_hash():
    """Hash client IP for privacy-preserving logging."""
    ip = request.headers.get("X-Forwarded-For", request.remote_addr) or "0.0.0.0"
    return hashlib.sha256(ip.encode()).hexdigest()[:16]


# ---------------------------------------------------------------------------
# Core orchestrator
# ---------------------------------------------------------------------------
def analyse_url(url: str) -> dict:
    """Run every signal, aggregate, log, return the full report."""
    started = datetime.utcnow()

    signals = {
        "ml":           ml_signal.predict(url),
        "threat_intel": threat_intel.query_all_sources(url),
        "whois":        whois_analyzer.analyse(url),
        "dns":          dns_analyzer.analyse(url),
        "typosquat":    typosquat.analyse(url),
    }
    verdict = aggregator.aggregate(signals)

    domain = urlparse(url).netloc.lower()
    if domain.startswith("www."):
        domain = domain[4:]

    full = {
        "url": url,
        "domain": domain,
        "scanned_at": started.isoformat(timespec="seconds"),
        "duration_ms": int((datetime.utcnow() - started).total_seconds() * 1000),
        "signals": signals,
        "verdict": verdict,
    }

    db.log_scan(
        url=url,
        domain=domain,
        client_ip_hash=_client_ip_hash(),
        verdict=verdict["verdict"],
        final_score=verdict["final_score"],
        signals=signals,
        full_report=full,
    )
    return full


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------
@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        url, err = _validate(request.form.get("url", ""))
        if err:
            return render_template("index.html", error=err, report=None)
        report = analyse_url(url)
        return render_template("index.html", report=report, error=None)
    return render_template("index.html", report=None, error=None)


@app.route("/dashboard")
def dashboard():
    return render_template(
        "dashboard.html",
        stats=db.stats(),
        recent=db.recent_scans(50),
    )


@app.route("/scan/<int:scan_id>")
def scan_detail(scan_id):
    row = db.get_scan(scan_id)
    if not row:
        return redirect(url_for("dashboard"))
    return render_template("index.html", report=row["full_report"], error=None,
                           historical=True)


# ---------------------------------------------------------------------------
# JSON API — for the bulk-scan / browser-extension use case
# ---------------------------------------------------------------------------
@app.route("/api/v1/scan", methods=["POST"])
def api_scan():
    data = request.get_json(silent=True) or {}
    url, err = _validate(data.get("url", ""))
    if err:
        return jsonify({"error": err}), 400
    return jsonify(analyse_url(url))


@app.route("/api/v1/stats")
def api_stats():
    return jsonify(db.stats())


if __name__ == "__main__":
    app.run(debug=True, port=5001)
