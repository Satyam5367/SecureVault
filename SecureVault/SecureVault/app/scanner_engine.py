import requests
import time
import json
import os
from datetime import datetime


ZAP_BASE_URL = os.environ.get('ZAP_API_URL', 'http://localhost:8080')
ZAP_API_KEY  = os.environ.get('ZAP_API_KEY', 'changeme')

# OWASP Top 10 category mapping by CWE
OWASP_MAP = {
    'CWE-89':  'A03:2021 – Injection',
    'CWE-79':  'A03:2021 – Injection (XSS)',
    'CWE-352': 'A01:2021 – Broken Access Control (CSRF)',
    'CWE-287': 'A07:2021 – Identification and Authentication Failures',
    'CWE-798': 'A02:2021 – Cryptographic Failures',
    'CWE-200': 'A02:2021 – Cryptographic Failures (Info Disclosure)',
    'CWE-522': 'A02:2021 – Cryptographic Failures (Weak Credentials)',
    'CWE-601': 'A01:2021 – Broken Access Control (Open Redirect)',
    'CWE-611': 'A05:2021 – Security Misconfiguration (XXE)',
    'CWE-94':  'A03:2021 – Injection (Code Injection)',
}

# CVSS base scores per severity (simplified)
CVSS_MAP = {
    'Critical': 9.0,
    'High':     7.5,
    'Medium':   5.0,
    'Low':      2.5,
    'Info':     0.0,
}


class ZAPScanner:
    def __init__(self):
        self.base = ZAP_BASE_URL
        self.key  = ZAP_API_KEY

    def _get(self, path, params=None):
        params = params or {}
        params['apikey'] = self.key
        try:
            r = requests.get(f'{self.base}/JSON/{path}', params=params, timeout=30)
            r.raise_for_status()
            return r.json()
        except requests.RequestException as e:
            raise RuntimeError(f'ZAP API error: {e}')

    def _post(self, path, data=None):
        data = data or {}
        data['apikey'] = self.key
        try:
            r = requests.post(f'{self.base}/JSON/{path}', data=data, timeout=30)
            r.raise_for_status()
            return r.json()
        except requests.RequestException as e:
            raise RuntimeError(f'ZAP API error: {e}')

    def start_spider(self, target_url):
        result = self._get('spider/action/scan/', {'url': target_url})
        return result.get('scan')

    def spider_progress(self, scan_id):
        result = self._get('spider/view/status/', {'scanId': scan_id})
        return int(result.get('status', 0))

    def start_active_scan(self, target_url):
        result = self._get('ascan/action/scan/', {'url': target_url, 'recurse': 'true'})
        return result.get('scan')

    def active_scan_progress(self, scan_id):
        result = self._get('ascan/view/status/', {'scanId': scan_id})
        return int(result.get('status', 0))

    def get_alerts(self, target_url):
        result = self._get('core/view/alerts/', {'baseurl': target_url, 'start': 0, 'count': 200})
        return result.get('alerts', [])

    def run_passive_scan(self, target_url):
        """Spider only — no active attacks."""
        scan_id = self.start_spider(target_url)
        while self.spider_progress(scan_id) < 100:
            time.sleep(2)
        return self.get_alerts(target_url)

    def run_active_scan(self, target_url):
        """Spider then active attack scan."""
        spider_id = self.start_spider(target_url)
        while self.spider_progress(spider_id) < 100:
            time.sleep(2)

        ascan_id = self.start_active_scan(target_url)
        while self.active_scan_progress(ascan_id) < 100:
            time.sleep(5)

        return self.get_alerts(target_url)


def parse_alerts(alerts):
    """Convert raw ZAP alerts into structured vulnerability dicts."""
    parsed = []
    for alert in alerts:
        risk_map = {'High': 'High', 'Medium': 'Medium', 'Low': 'Low', 'Informational': 'Info'}
        severity  = risk_map.get(alert.get('risk', 'Info'), 'Info')
        cwe_id    = f"CWE-{alert.get('cweid', '')}" if alert.get('cweid') else None
        owasp_cat = OWASP_MAP.get(cwe_id, 'A05:2021 – Security Misconfiguration') if cwe_id else None
        cvss      = CVSS_MAP.get(severity, 0.0)

        parsed.append({
            'name':          alert.get('name', 'Unknown'),
            'cwe_id':        cwe_id,
            'cvss_score':    cvss,
            'severity':      severity,
            'description':   alert.get('description', ''),
            'url':           alert.get('url', ''),
            'parameter':     alert.get('param', ''),
            'evidence':      alert.get('evidence', ''),
            'remediation':   alert.get('solution', ''),
            'owasp_category': owasp_cat,
        })

    # Sort by CVSS descending
    parsed.sort(key=lambda x: x['cvss_score'], reverse=True)
    return parsed


def generate_report(scan_id, target_url, vulnerabilities, report_dir='reports'):
    """Generate a structured JSON report with CVSS scores and CWE mappings."""
    os.makedirs(report_dir, exist_ok=True)

    severity_counts = {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0, 'Info': 0}
    for v in vulnerabilities:
        severity_counts[v.get('severity', 'Info')] += 1

    report = {
        'report_metadata': {
            'scan_id':       scan_id,
            'target_url':    target_url,
            'generated_at':  datetime.utcnow().isoformat(),
            'tool':          'SecureVault (OWASP ZAP Integration)',
            'standard':      'OWASP Top 10 2021'
        },
        'summary': {
            'total_vulnerabilities': len(vulnerabilities),
            'severity_breakdown':    severity_counts,
            'risk_score':            round(sum(v['cvss_score'] for v in vulnerabilities) / max(len(vulnerabilities), 1), 2)
        },
        'vulnerabilities': vulnerabilities
    }

    filename = f'report_scan_{scan_id}_{datetime.utcnow().strftime("%Y%m%d_%H%M%S")}.json'
    path     = os.path.join(report_dir, filename)

    with open(path, 'w') as f:
        json.dump(report, f, indent=2)

    return path
