# STRIDE Threat Model — SecureVault

## System Overview

SecureVault is a web-based automated vulnerability scanner. It allows authenticated
users to submit target URLs for DAST scanning using OWASP ZAP and view structured
vulnerability reports. The system exposes a Flask REST API and a web dashboard.

---

## Components

- Flask REST API (backend)
- OWASP ZAP (scanning engine, runs in Docker)
- SQLite / PostgreSQL (scan results and audit logs)
- JWT (authentication tokens)
- React/HTML dashboard (frontend)
- Docker (containerisation)

---

## STRIDE Analysis

### S — Spoofing

**Threat**: An attacker impersonates a legitimate user by forging or stealing JWT tokens.

**Risk**: High

**Mitigations implemented**:
- JWT tokens signed with HS256 using a strong secret stored in environment variables
- Tokens expire after 1 hour (`JWT_ACCESS_TOKEN_EXPIRES = 3600`)
- BCrypt-hashed passwords prevent credential theft from DB dumps
- All login failures are recorded in the audit log with IP address

---

### T — Tampering

**Threat**: An attacker modifies scan results or vulnerability reports in transit or
at rest to hide findings or falsely report clean results.

**Risk**: High

**Mitigations implemented**:
- Reports stored as JSON files server-side, not editable by clients
- HTTPS enforced in production (TLS termination at reverse proxy)
- Database rows are append-only for scan results; no update endpoint exposed
- Report filenames include scan ID and timestamp to prevent collision

---

### R — Repudiation

**Threat**: A malicious admin or analyst claims they did not trigger a scan or access
a report.

**Risk**: Medium

**Mitigations implemented**:
- Immutable audit log table (`AuditLog`) records every action with:
  - user_id
  - action type
  - target resource
  - IP address
  - user agent
  - timestamp
  - status (success / failure)
- Audit logs accessible only to admin role

---

### I — Information Disclosure

**Threat**: Sensitive scan reports or vulnerability details are accessed by
unauthorised users.

**Risk**: High

**Mitigations implemented**:
- RBAC enforced on every endpoint via JWT claims (`role`: admin / analyst / viewer)
- Viewers can only see their own scans
- Analysts can run scans and view their own reports
- Admins can view all scans and audit logs
- No raw ZAP output is exposed to the client; only parsed and sanitised data

---

### D — Denial of Service

**Threat**: An attacker submits hundreds of concurrent scan requests to exhaust ZAP
resources or block the server.

**Risk**: Medium

**Mitigations implemented**:
- Only analyst and admin roles can initiate scans (viewers blocked at API level)
- Scans run in background threads; server remains responsive
- Target URL validated with strict regex before scan is queued
- Production deployment should add rate limiting (Flask-Limiter) per user

---

### E — Elevation of Privilege

**Threat**: A viewer-role user accesses admin endpoints (audit logs, user list) or
triggers scans without analyst role.

**Risk**: Critical

**Mitigations implemented**:
- JWT claims carry `role` field set at registration time
- Every protected endpoint checks `get_jwt()['role']` before processing
- Role assignment: first registered user → admin; subsequent → viewer
- Role changes require direct DB admin action; no self-service role escalation endpoint

---

## Residual Risks

| Risk                              | Likelihood | Impact | Mitigation Status        |
|-----------------------------------|------------|--------|--------------------------|
| JWT secret leaked via env file    | Low        | High   | Use secrets manager in prod |
| OWASP ZAP scans attacker's infra  | Medium     | Medium | URL whitelist (future)   |
| SQLite race condition on writes   | Low        | Medium | Use PostgreSQL in prod   |
| No rate limiting on login         | Medium     | High   | Add Flask-Limiter        |

---

## Security Controls Summary

| Control                    | Implementation                        |
|----------------------------|---------------------------------------|
| Authentication             | JWT (HS256, 1h expiry)                |
| Password storage           | BCrypt (cost factor 12)               |
| Authorisation              | RBAC via JWT claims                   |
| Input validation           | URL regex, field presence checks      |
| Audit logging              | Immutable AuditLog table              |
| Data in transit            | HTTPS (TLS at reverse proxy)          |
| Secrets management         | Environment variables                 |
| Containerisation           | Docker + Docker Compose               |
| DAST                       | OWASP ZAP API                         |
| SAST                       | Bandit (pre-deployment)               |
