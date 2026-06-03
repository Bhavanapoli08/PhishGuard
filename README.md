# PhishGuard — Multi-Layer Phishing Detection Platform

A defense-in-depth phishing analyzer that combines five independent
detection signals, aggregates them with weighted scoring, logs every
scan, and exposes both a Flask UI and a JSON API.

## Web Application

<img width="1280" height="832" alt="image" src="https://github.com/user-attachments/assets/9a78d49e-beac-4ab1-b4db-77e0aa931b09" />

<img width="1280" height="832" alt="image" src="https://github.com/user-attachments/assets/eeeca8bc-49fa-4cb6-9e13-4e3e45fe4a02" />

<img width="1280" height="832" alt="image" src="https://github.com/user-attachments/assets/514375d0-0008-4b84-8f4d-aeb6fa5b09d2" />

<img width="1280" height="832" alt="image" src="https://github.com/user-attachments/assets/3907367c-a4e0-4df0-9281-848192b297e0" />

<img width="1280" height="832" alt="image" src="https://github.com/user-attachments/assets/771675df-5d45-43a7-871a-a0f6adbe9618" />

<img width="1280" height="832" alt="image" src="https://github.com/user-attachments/assets/1a405d2c-a2b7-4e9f-ad03-8fd346dca609" />

<img width="1280" height="832" alt="image" src="https://github.com/user-attachments/assets/14414ffd-093d-4ffc-ba65-53cdd3d306a2" />

<img width="1280" height="832" alt="image" src="https://github.com/user-attachments/assets/ba918340-596f-4a34-892b-8fffa3876eaa" />

<img width="1280" height="832" alt="image" src="https://github.com/user-attachments/assets/7f94d8e4-ef4f-472a-93d1-1699900abdaf" />

<img width="1280" height="832" alt="image" src="https://github.com/user-attachments/assets/054af253-a896-4922-b2c2-91df0ef34a9b" />

<img width="1280" height="832" alt="image" src="https://github.com/user-attachments/assets/996e7743-4642-47d2-b99f-617159940c9f" />

## Architecture

```
Frontend (Flask UI)
        │
        ▼
   URL Analyzer (orchestrator)
        │
 ┌──────┴──────────────────────────┐
 │  ML Prediction        (20%)     │
 │  Threat Intelligence  (35%)     │
 │  WHOIS Analysis       (15%)     │
 │  DNS Analysis         (10%)     │
 │  Typosquat Detection  (20%)     │
 └──────┬──────────────────────────┘
        ▼
   Risk Aggregator (weighted)
        ▼
   SQLite Logging (audit trail)
        ▼
   Analyst Dashboard
```

## Cybersecurity Concepts Demonstrated

| Concept                         | Where it lives                                   |
| ------------------------------- | ------------------------------------------------ |
| Defense in depth                | 5 independent signals + aggregator               |
| Threat-intel correlation        | `modules/threat_intel.py` (GSB, VT, PhishTank)   |
| Infrastructure forensics        | `modules/whois_analyzer.py`                      |
| DNS forensics & fast-flux       | `modules/dns_analyzer.py`                        |
| Typosquatting / IDN homographs  | `modules/typosquat.py`                           |
| Weighted multi-engine verdict   | `modules/aggregator.py`                          |
| SIEM-style audit logging        | `modules/db.py` (SQLite)                         |
| Secure input validation         | `app.py` `_validate()`                           |
| Privacy-preserving telemetry    | SHA-256 hashed client IPs                        |
| JSON API with bulk-scan support | `/api/v1/scan` endpoint                          |

## Project Layout

```
.
├── app.py                  Flask app + orchestrator
├── feature.py              (kept from original) ML feature extractor
├── pickle/model.pkl        (kept from original) trained GBC model
├── modules/
│   ├── ml_signal.py
│   ├── threat_intel.py
│   ├── whois_analyzer.py
│   ├── dns_analyzer.py
│   ├── typosquat.py
│   ├── aggregator.py
│   └── db.py
├── templates/
│   ├── index.html          Scanner + report view
│   └── dashboard.html      Analyst dashboard
├── static/styles.css
├── data/
│   ├── phishtank_cache.txt Local TI feed (sample)
│   └── scans.db            (auto-created on first run)
└── requirements.txt
```

## Installation

```bash
pip install -r requirements.txt
```

Then optionally export API keys for live threat-intel sources:

```bash
export GOOGLE_SAFE_BROWSING_KEY="your-key"
export VIRUSTOTAL_KEY="your-key"
```

Without keys, those sources show `SKIPPED` and the local PhishTank
feed plus all other modules continue to work.

## Run

```bash
python app.py
```

Then open:
- `http://localhost:5001/` — scanner
- `http://localhost:5001/dashboard` — analyst dashboard

## API

```bash
# Scan a URL
curl -X POST http://localhost:5001/api/v1/scan \
     -H "Content-Type: application/json" \
     -d '{"url": "https://example.com"}'

# Get aggregate stats
curl http://localhost:5001/api/v1/stats
```

## Why this is more than an ML demo

The original project was a single ML model behind a form. This version
demonstrates real SOC tooling principles:

1. **No single point of trust** — five independent signals must agree.
2. **External corroboration** — verdicts cross-checked against Google,
   VirusTotal, PhishTank.
3. **Infrastructure forensics** — same techniques used by CTI analysts.
4. **Auditability** — every scan logged, queryable, exportable.
5. **Operational interface** — dashboard for analysts, API for automation.
