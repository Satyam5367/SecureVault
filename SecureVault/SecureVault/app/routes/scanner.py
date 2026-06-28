from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity, get_jwt
from app import db
from app.models import ScanResult, Vulnerability, AuditLog, User
from app.scanner_engine import ZAPScanner, parse_alerts, generate_report
from datetime import datetime
import threading
import re

scanner_bp = Blueprint('scanner', __name__)


def validate_url(url):
    pattern = re.compile(
        r'^https?://'
        r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+[A-Z]{2,6}\.?|localhost|\d{1,3}(?:\.\d{1,3}){3})'
        r'(?::\d+)?(?:/?|[/?]\S+)$', re.IGNORECASE)
    return bool(pattern.match(url))


def log_action(user_id, action, resource, ip, ua, status, details=None):
    log = AuditLog(
        user_id=user_id, action=action, resource=resource,
        ip_address=ip, user_agent=ua, status=status,
        details=details, timestamp=datetime.utcnow()
    )
    db.session.add(log)
    db.session.commit()


def run_scan_background(app, scan_id, target_url, scan_type):
    with app.app_context():
        scan = ScanResult.query.get(scan_id)
        if not scan:
            return
        scan.status = 'running'
        db.session.commit()

        try:
            zap = ZAPScanner()
            if scan_type == 'passive':
                raw_alerts = zap.run_passive_scan(target_url)
            else:
                raw_alerts = zap.run_active_scan(target_url)

            parsed = parse_alerts(raw_alerts)

            for v in parsed:
                vuln = Vulnerability(
                    scan_id=scan_id,
                    name=v['name'],
                    cwe_id=v['cwe_id'],
                    cvss_score=v['cvss_score'],
                    severity=v['severity'],
                    description=v['description'],
                    url=v['url'],
                    parameter=v['parameter'],
                    evidence=v['evidence'],
                    remediation=v['remediation'],
                    owasp_category=v['owasp_category']
                )
                db.session.add(vuln)

            report_path = generate_report(scan_id, target_url, parsed)
            scan.report_path = report_path
            scan.status = 'complete'
            scan.completed_at = datetime.utcnow()

        except Exception as e:
            scan.status = 'failed'
            scan.completed_at = datetime.utcnow()

        db.session.commit()


@scanner_bp.route('/scan', methods=['POST'])
@jwt_required()
def start_scan():
    claims  = get_jwt()
    user_id = int(get_jwt_identity())
    role    = claims.get('role')

    if role not in ('admin', 'analyst'):
        return jsonify({'error': 'Analyst or Admin role required to start scans'}), 403

    data = request.get_json()
    if not data or 'target_url' not in data:
        return jsonify({'error': 'target_url is required'}), 400

    target_url = str(data['target_url']).strip()
    scan_type  = str(data.get('scan_type', 'passive')).strip()

    if not validate_url(target_url):
        return jsonify({'error': 'Invalid target URL'}), 400

    if scan_type not in ('passive', 'active', 'full'):
        return jsonify({'error': 'scan_type must be passive, active, or full'}), 400

    scan = ScanResult(
        user_id=user_id,
        target_url=target_url,
        scan_type=scan_type,
        status='pending'
    )
    db.session.add(scan)
    db.session.commit()

    log_action(user_id, 'START_SCAN', f'/scanner/scan',
               request.remote_addr, request.user_agent.string, 'success',
               f'Target: {target_url}, Type: {scan_type}')

    from flask import current_app
    thread = threading.Thread(
        target=run_scan_background,
        args=(current_app._get_current_object(), scan.id, target_url, scan_type)
    )
    thread.daemon = True
    thread.start()

    return jsonify({'message': 'Scan started', 'scan_id': scan.id}), 202


@scanner_bp.route('/scans', methods=['GET'])
@jwt_required()
def list_scans():
    claims  = get_jwt()
    user_id = int(get_jwt_identity())
    role    = claims.get('role')

    if role == 'admin':
        scans = ScanResult.query.order_by(ScanResult.started_at.desc()).all()
    else:
        scans = ScanResult.query.filter_by(user_id=user_id).order_by(ScanResult.started_at.desc()).all()

    return jsonify([s.to_dict() for s in scans]), 200


@scanner_bp.route('/scans/<int:scan_id>', methods=['GET'])
@jwt_required()
def get_scan(scan_id):
    claims  = get_jwt()
    user_id = int(get_jwt_identity())
    role    = claims.get('role')

    scan = ScanResult.query.get_or_404(scan_id)

    if role != 'admin' and scan.user_id != user_id:
        return jsonify({'error': 'Access denied'}), 403

    result = scan.to_dict()
    result['vulnerabilities'] = [v.to_dict() for v in scan.vulnerabilities]
    return jsonify(result), 200


@scanner_bp.route('/scans/<int:scan_id>/report', methods=['GET'])
@jwt_required()
def get_report(scan_id):
    claims  = get_jwt()
    user_id = int(get_jwt_identity())
    role    = claims.get('role')

    scan = ScanResult.query.get_or_404(scan_id)

    if role != 'admin' and scan.user_id != user_id:
        return jsonify({'error': 'Access denied'}), 403

    if scan.status != 'complete':
        return jsonify({'error': 'Scan not complete yet'}), 400

    vulns = [v.to_dict() for v in scan.vulnerabilities]

    severity_counts = {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0, 'Info': 0}
    for v in scan.vulnerabilities:
        severity_counts[v.severity] += 1

    return jsonify({
        'scan': scan.to_dict(),
        'summary': {
            'total': len(vulns),
            'by_severity': severity_counts
        },
        'vulnerabilities': vulns
    }), 200
