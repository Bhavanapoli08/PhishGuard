# PhishGuard — Multi-Layer Phishing Detection Platform

A defense-in-depth phishing analyzer that combines five independent
detection signals, aggregates them with weighted scoring, logs every
scan, and exposes both a Flask UI and a JSON API.

## Web Application


<img width="1280" height="800" alt="image" src="https://github.com/user-attachments/assets/db813904-0d41-4422-8f85-69535181511c" />


<img width="1280" height="800" alt="image" src="https://github.com/user-attachments/assets/0140402c-ce00-4978-8250-3f365644e822" />


<img width="1280" height="800" alt="image" src="https://github.com/user-attachments/assets/3f07a9f6-86d4-4b27-b8a2-9a1ea8b926fe" />


<img width="1280" height="800" alt="image" src="https://github.com/user-attachments/assets/810ae699-8e84-4353-ab25-6421f2ee2400" />


<img width="1280" height="800" alt="image" src="https://github.com/user-attachments/assets/7e66f528-abe0-4301-97d7-2ff7dea8154e" />


<img width="1280" height="800" alt="image" src="https://github.com/user-attachments/assets/cb44a493-cb4d-4bb5-9ce9-a417b919d17b" />


<img width="1280" height="800" alt="image" src="https://github.com/user-attachments/assets/b4c768e4-1adc-4923-9476-c5c603d2617e" />


<img width="1280" height="800" alt="image" src="https://github.com/user-attachments/assets/14944736-b102-4ee1-b972-3d59cfa3fbce" />

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
