# SecureVault — Web Vulnerability Scanner

A DAST-based automated web vulnerability scanner powered by OWASP ZAP, with JWT authentication, RBAC, STRIDE threat modeling, and structured JSON reports with CVSS scores and CWE mappings.

---

## Screenshots

```
┌─────────────────────────────────────────────────────┐
│  SecureVault Dashboard                              │
│  ┌──────────┐ ┌────────────┐ ┌──────┐ ┌─────────┐ │
│  │ Scans: 3 │ │ Vulns: 12  │ │ H/C:4│ │COMPLETE │ │
│  └──────────┘ └────────────┘ └──────┘ └─────────┘ │
│                                                     │
│  ▶ New Scan          📊 Severity Breakdown         │
│  Target: [_______]   Critical ░░ 0                 │
│  Type:   [passive▼]  High     ████ 2               │
│  [Start Scan]        Medium   ██████ 3             │
│                      Low      ████ 2               │
│  🕐 Recent Scans     Info     ██ 1                 │
│  #1 vulnweb.com  COMPLETE  8 vulns  [View]         │
└─────────────────────────────────────────────────────┘
```

---

## Features

- **DAST scanning** via OWASP ZAP API (passive and active modes)
- **SAST** via Bandit — see `bandit_report.txt`
- **JWT authentication** with BCrypt password hashing
- **Role-Based Access Control** (Admin / Analyst / Viewer)
- **STRIDE threat modeling** — see `THREAT_MODEL.md`
- **Structured JSON reports** with CVSS scores, CWE IDs, OWASP Top 10 mapping
- **Immutable audit logging** for all user actions
- **Web dashboard** with live scan management and vulnerability viewer
- **Dockerized** deployment with OWASP ZAP as a sidecar container

---

## Architecture

```
┌────────────────────┐       ┌──────────────────┐
│  Flask REST API    │──────▶│  OWASP ZAP       │
│  (SecureVault)     │       │  (DAST Engine)   │
└────────┬───────────┘       └──────────────────┘
         │
         ▼
┌────────────────────┐       ┌──────────────────┐
│  SQLite / Postgres │       │  HTML Dashboard  │
│  - Users           │       │  JWT auth        │
│  - Scan Results    │       │  Live scan mgmt  │
│  - Vulnerabilities │       │  Vuln reports    │
│  - Audit Logs      │       └──────────────────┘
└────────────────────┘
```

---

## Quick Start

### 1. Clone and configure

```bash
git clone https://github.com/Satyam5367/SecureVault.git
cd SecureVault
cp .env.example .env
# Edit .env — set strong SECRET_KEY, JWT_SECRET_KEY, ZAP_API_KEY
```

### 2. Run with Docker Compose

```bash
docker-compose up --build
```

- API + Dashboard: `http://localhost:5000`
- ZAP: `http://localhost:8080`

### 3. Run locally (without Docker)

```bash
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python run.py
```

---

## Demo

```bash
# Full live demo against testphp.vulnweb.com
python demo.py

# Active scan
python demo.py --url http://testphp.vulnweb.com --type active

# Use pre-built sample report (no ZAP needed)
python demo.py --sample
```

**Sample output:**
```
[Step 1] Registering demo admin user...
  ✓ Registered: demo_admin (role: admin)
[Step 2] Logging in...
  ✓ JWT Token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
[Step 3] Starting PASSIVE scan...
  ✓ Scan #1 started
[Step 4] Polling status...
  [42s] Status: complete | 8 vulnerabilities found
[Step 6] Vulnerability Summary
  High     ██ 2    Medium ████ 3    Low ██ 2    Info █ 1
  [HIGH] SQL Injection — CWE-89 — CVSS 7.5
  [HIGH] Cross Site Scripting — CWE-79 — CVSS 7.5
[Step 7] Audit log: 4 entries logged
```

---

## Sample Report

See `reports/examples/sample_report_scan_1.json` — full JSON report with CVSS scores, CWE IDs, OWASP categories, evidence, and remediation.

---

## SAST — Bandit

```bash
bandit -r app/ -c bandit.yaml -f txt -o bandit_report.txt
```

Pre-generated: `bandit_report.txt` — **Result: PASSED** (0 medium/high issues)

---

## Tests

```bash
pytest tests/ -v
```

Covers: auth, RBAC, input validation, JWT enforcement, URL validation.

---

## API Reference

| Method | Endpoint                   | Auth            |
|--------|----------------------------|-----------------|
| POST   | /auth/register             | No              |
| POST   | /auth/login                | No              |
| GET    | /auth/me                   | JWT             |
| POST   | /scanner/scan              | Analyst / Admin |
| GET    | /scanner/scans             | JWT             |
| GET    | /scanner/scans/{id}/report | JWT (own/admin) |
| GET    | /api/stats                 | JWT             |
| GET    | /api/audit-logs            | Admin only      |

---

## Security Controls

| Control            | Implementation                              |
|--------------------|---------------------------------------------|
| Authentication     | JWT HS256, 1-hour expiry                    |
| Password storage   | BCrypt adaptive hashing                     |
| Authorisation      | RBAC via JWT claims                         |
| Input validation   | URL regex, field checks on all endpoints    |
| Audit logging      | Immutable DB table                          |
| Secrets            | Environment variables only                  |
| DAST               | OWASP ZAP API                               |
| SAST               | Bandit (see bandit_report.txt)              |
| Threat model       | STRIDE (see THREAT_MODEL.md)                |
| Container security | Non-root Docker user                        |

---

## Tech Stack

Python · Flask · OWASP ZAP · Bandit · SQLite/PostgreSQL · Docker · Linux
