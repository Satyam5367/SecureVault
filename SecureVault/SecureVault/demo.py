"""
demo.py — SecureVault End-to-End Demo
======================================
Demonstrates the full flow against a live SecureVault API:

1. Register admin user
2. Login and get JWT token
3. Start a passive scan against DVWA / testphp.vulnweb.com
4. Poll scan status until complete
5. Fetch the vulnerability report
6. Print a formatted summary

Usage:
    python demo.py
    python demo.py --url http://testphp.vulnweb.com --type passive
    python demo.py --url http://localhost/dvwa --type active

Requirements:
    pip install requests
    SecureVault running: docker-compose up
"""

import requests
import time
import json
import argparse
import sys
from datetime import datetime

BASE_URL   = 'http://localhost:5000'
DEMO_USER  = 'demo_admin'
DEMO_PASS  = 'DemoPass123!'
DEMO_EMAIL = 'demo@securevault.local'

SEVERITY_COLORS = {
    'Critical': '\033[91m',
    'High':     '\033[91m',
    'Medium':   '\033[93m',
    'Low':      '\033[94m',
    'Info':     '\033[92m',
}
RESET  = '\033[0m'
BOLD   = '\033[1m'
CYAN   = '\033[96m'
GREEN  = '\033[92m'
RED    = '\033[91m'
YELLOW = '\033[93m'


def banner():
    print(f"""{CYAN}
╔══════════════════════════════════════════╗
║       SecureVault — Live Demo            ║
║  OWASP ZAP DAST + JWT + RBAC + Audit    ║
╚══════════════════════════════════════════╝{RESET}
""")


def step(n, msg):
    print(f"\n{BOLD}[Step {n}]{RESET} {msg}")


def ok(msg):
    print(f"  {GREEN}✓{RESET} {msg}")


def err(msg):
    print(f"  {RED}✗{RESET} {msg}")
    sys.exit(1)


def info(msg):
    print(f"  {YELLOW}→{RESET} {msg}")


def register_user():
    step(1, "Registering demo admin user...")
    res = requests.post(f'{BASE_URL}/auth/register', json={
        'username': DEMO_USER,
        'email':    DEMO_EMAIL,
        'password': DEMO_PASS
    })
    if res.status_code == 201:
        ok(f"Registered: {DEMO_USER} (role: {res.json().get('role')})")
    elif res.status_code == 409:
        info("User already exists, continuing...")
    else:
        err(f"Registration failed: {res.text}")


def login():
    step(2, "Logging in and obtaining JWT token...")
    res = requests.post(f'{BASE_URL}/auth/login', json={
        'username': DEMO_USER,
        'password': DEMO_PASS
    })
    if res.status_code != 200:
        err(f"Login failed: {res.text}")

    data  = res.json()
    token = data['access_token']
    user  = data['user']
    ok(f"Logged in as: {user['username']} | Role: {user['role']}")
    info(f"JWT Token: {token[:40]}...{RESET}")
    return token


def start_scan(token, target_url, scan_type):
    step(3, f"Starting {scan_type.upper()} scan against: {target_url}")
    res = requests.post(f'{BASE_URL}/scanner/scan',
        json={'target_url': target_url, 'scan_type': scan_type},
        headers={'Authorization': f'Bearer {token}'}
    )
    if res.status_code != 202:
        err(f"Scan start failed: {res.text}")

    scan_id = res.json()['scan_id']
    ok(f"Scan #{scan_id} started successfully")
    return scan_id


def poll_scan(token, scan_id):
    step(4, f"Polling scan #{scan_id} status...")
    start = time.time()
    while True:
        res = requests.get(f'{BASE_URL}/scanner/scans/{scan_id}',
                           headers={'Authorization': f'Bearer {token}'})
        data   = res.json()
        status = data.get('status', 'unknown')
        elapsed = int(time.time() - start)

        print(f"  [{elapsed:>3}s] Status: {YELLOW}{status}{RESET} | Vulns found so far: {data.get('vulnerability_count', 0)}", end='\r')

        if status == 'complete':
            print()
            ok(f"Scan complete in {elapsed}s — {data['vulnerability_count']} vulnerabilities found")
            return data
        elif status == 'failed':
            print()
            err("Scan failed. Is ZAP running? Check docker-compose logs.")
        time.sleep(5)


def fetch_report(token, scan_id):
    step(5, f"Fetching vulnerability report for scan #{scan_id}...")
    res = requests.get(f'{BASE_URL}/scanner/scans/{scan_id}/report',
                       headers={'Authorization': f'Bearer {token}'})
    if res.status_code != 200:
        err(f"Report fetch failed: {res.text}")
    ok("Report fetched successfully")
    return res.json()


def print_report(report):
    step(6, "Vulnerability Report Summary")

    scan    = report.get('scan', {})
    summary = report.get('summary', {})
    vulns   = report.get('vulnerabilities', [])

    print(f"""
  {BOLD}Target:{RESET}  {scan.get('target_url')}
  {BOLD}Scan Type:{RESET} {scan.get('scan_type')}
  {BOLD}Completed:{RESET} {scan.get('completed_at', 'N/A')}

  {BOLD}── Severity Breakdown ──{RESET}""")

    breakdown = summary.get('by_severity', {})
    for sev, count in breakdown.items():
        color = SEVERITY_COLORS.get(sev, '')
        bar   = '█' * count
        print(f"  {color}{sev:<10}{RESET} {bar} {count}")

    print(f"\n  {BOLD}Total:{RESET} {summary.get('total', 0)} vulnerabilities\n")

    if vulns:
        print(f"  {BOLD}── Top Findings ──{RESET}")
        for v in vulns[:5]:
            color = SEVERITY_COLORS.get(v['severity'], '')
            print(f"""
  {color}[{v['severity'].upper()}]{RESET} {BOLD}{v['name']}{RESET}
    CWE:     {v.get('cwe_id', 'N/A')}
    CVSS:    {v.get('cvss_score', 'N/A')}
    OWASP:   {v.get('owasp_category', 'N/A')}
    URL:     {v.get('url', 'N/A')}
    Fix:     {v.get('remediation', 'N/A')[:120]}...""")

    print(f"\n  {GREEN}Full JSON report saved to: reports/{RESET}")


def fetch_audit_log(token):
    step(7, "Fetching audit log (admin only)...")
    res = requests.get(f'{BASE_URL}/api/audit-logs',
                       headers={'Authorization': f'Bearer {token}'})
    if res.status_code == 200:
        logs = res.json()
        ok(f"{len(logs)} audit entries found")
        for log in logs[:5]:
            status_color = GREEN if log['status'] == 'success' else RED
            print(f"  [{status_color}{log['status']}{RESET}] {log['action']} — {log['ip_address']} @ {log['timestamp']}")
    else:
        info("Audit log not accessible (admin role required)")


def use_sample_report():
    """Load and display sample report if ZAP is not running."""
    try:
        with open('reports/examples/sample_report_scan_1.json') as f:
            return json.load(f)
    except FileNotFoundError:
        return None


def main():
    parser = argparse.ArgumentParser(description='SecureVault Demo')
    parser.add_argument('--url',    default='http://testphp.vulnweb.com', help='Target URL to scan')
    parser.add_argument('--type',   default='passive', choices=['passive','active'], help='Scan type')
    parser.add_argument('--sample', action='store_true', help='Use sample report (no ZAP needed)')
    args = parser.parse_args()

    banner()

    # Check API is running
    try:
        requests.get(f'{BASE_URL}/', timeout=3)
    except requests.ConnectionError:
        print(f"{RED}Cannot connect to SecureVault API at {BASE_URL}{RESET}")
        print(f"{YELLOW}Start it with: docker-compose up{RESET}\n")

        if args.sample:
            print(f"{CYAN}-- Running in SAMPLE MODE (no API needed) --{RESET}\n")
            report = use_sample_report()
            if report:
                print_report(report)
            else:
                print(f"{RED}Sample report not found.{RESET}")
        sys.exit(0)

    register_user()
    token = login()

    if args.sample:
        info("--sample flag set: using pre-built sample report instead of live scan")
        report = use_sample_report()
        if report:
            print_report(report)
        fetch_audit_log(token)
    else:
        scan_id = start_scan(token, args.url, args.type)
        poll_scan(token, scan_id)
        report  = fetch_report(token, scan_id)
        print_report(report)
        fetch_audit_log(token)

    print(f"\n{GREEN}{'─'*50}")
    print(f"  Demo complete. Dashboard: http://localhost:5000")
    print(f"{'─'*50}{RESET}\n")


if __name__ == '__main__':
    main()
