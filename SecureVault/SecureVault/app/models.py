from app import db
from datetime import datetime


class User(db.Model):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), nullable=False, default='viewer')  # admin / analyst / viewer
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_active = db.Column(db.Boolean, default=True)

    scans = db.relationship('ScanResult', backref='user', lazy=True)
    logs = db.relationship('AuditLog', backref='user', lazy=True)

    def to_dict(self):
        return {
            'id': self.id,
            'username': self.username,
            'email': self.email,
            'role': self.role,
            'created_at': self.created_at.isoformat(),
            'is_active': self.is_active
        }


class ScanResult(db.Model):
    __tablename__ = 'scan_results'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    target_url = db.Column(db.String(500), nullable=False)
    scan_type = db.Column(db.String(50), nullable=False)   # passive / active / full
    status = db.Column(db.String(20), default='pending')   # pending / running / complete / failed
    started_at = db.Column(db.DateTime, default=datetime.utcnow)
    completed_at = db.Column(db.DateTime, nullable=True)
    report_path = db.Column(db.String(500), nullable=True)

    vulnerabilities = db.relationship('Vulnerability', backref='scan', lazy=True)

    def to_dict(self):
        return {
            'id': self.id,
            'target_url': self.target_url,
            'scan_type': self.scan_type,
            'status': self.status,
            'started_at': self.started_at.isoformat(),
            'completed_at': self.completed_at.isoformat() if self.completed_at else None,
            'vulnerability_count': len(self.vulnerabilities)
        }


class Vulnerability(db.Model):
    __tablename__ = 'vulnerabilities'

    id = db.Column(db.Integer, primary_key=True)
    scan_id = db.Column(db.Integer, db.ForeignKey('scan_results.id'), nullable=False)
    name = db.Column(db.String(200), nullable=False)
    cwe_id = db.Column(db.String(20), nullable=True)       # e.g. CWE-89
    cvss_score = db.Column(db.Float, nullable=True)
    severity = db.Column(db.String(20), nullable=False)    # Critical / High / Medium / Low / Info
    description = db.Column(db.Text, nullable=True)
    url = db.Column(db.String(500), nullable=True)
    parameter = db.Column(db.String(200), nullable=True)
    evidence = db.Column(db.Text, nullable=True)
    remediation = db.Column(db.Text, nullable=True)
    owasp_category = db.Column(db.String(100), nullable=True)
    discovered_at = db.Column(db.DateTime, default=datetime.utcnow)

    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'cwe_id': self.cwe_id,
            'cvss_score': self.cvss_score,
            'severity': self.severity,
            'description': self.description,
            'url': self.url,
            'parameter': self.parameter,
            'evidence': self.evidence,
            'remediation': self.remediation,
            'owasp_category': self.owasp_category,
            'discovered_at': self.discovered_at.isoformat()
        }


class AuditLog(db.Model):
    __tablename__ = 'audit_logs'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    action = db.Column(db.String(200), nullable=False)
    resource = db.Column(db.String(200), nullable=True)
    ip_address = db.Column(db.String(50), nullable=True)
    user_agent = db.Column(db.String(300), nullable=True)
    status = db.Column(db.String(20), nullable=False)      # success / failure
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    details = db.Column(db.Text, nullable=True)

    def to_dict(self):
        return {
            'id': self.id,
            'user_id': self.user_id,
            'action': self.action,
            'resource': self.resource,
            'ip_address': self.ip_address,
            'status': self.status,
            'timestamp': self.timestamp.isoformat(),
            'details': self.details
        }
