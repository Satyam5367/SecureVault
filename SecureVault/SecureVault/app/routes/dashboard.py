from flask import Blueprint, render_template, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity, get_jwt
from app.models import ScanResult, Vulnerability, AuditLog, User
from app import db

dashboard_bp = Blueprint('dashboard', __name__)


@dashboard_bp.route('/')
def index():
    return render_template('index.html')


@dashboard_bp.route('/dashboard')
def dashboard():
    return render_template('dashboard.html')


@dashboard_bp.route('/api/stats', methods=['GET'])
@jwt_required()
def stats():
    claims = get_jwt()
    role   = claims.get('role')

    total_scans  = ScanResult.query.count()
    total_vulns  = Vulnerability.query.count()
    critical_high = Vulnerability.query.filter(
        Vulnerability.severity.in_(['Critical', 'High'])
    ).count()

    recent_scans = ScanResult.query.order_by(
        ScanResult.started_at.desc()
    ).limit(5).all()

    return jsonify({
        'total_scans':    total_scans,
        'total_vulns':    total_vulns,
        'critical_high':  critical_high,
        'recent_scans':   [s.to_dict() for s in recent_scans]
    }), 200


@dashboard_bp.route('/api/audit-logs', methods=['GET'])
@jwt_required()
def audit_logs():
    claims = get_jwt()
    if claims.get('role') != 'admin':
        return jsonify({'error': 'Admin only'}), 403

    logs = AuditLog.query.order_by(AuditLog.timestamp.desc()).limit(100).all()
    return jsonify([l.to_dict() for l in logs]), 200
