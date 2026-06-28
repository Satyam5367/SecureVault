import pytest
import json
from app import create_app, db


@pytest.fixture
def client():
    app = create_app()
    app.config['TESTING'] = True
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
    app.config['JWT_SECRET_KEY'] = 'test-secret'

    with app.test_client() as client:
        with app.app_context():
            db.create_all()
        yield client


def register_and_login(client, username='testadmin', password='SecurePass123!'):
    client.post('/auth/register', json={
        'username': username, 'email': f'{username}@test.com', 'password': password
    })
    res = client.post('/auth/login', json={'username': username, 'password': password})
    return json.loads(res.data)['access_token']


# --- Auth tests ---

def test_register_success(client):
    res = client.post('/auth/register', json={
        'username': 'user1', 'email': 'user1@test.com', 'password': 'Password123!'
    })
    assert res.status_code == 201
    assert b'registered' in res.data


def test_register_duplicate_username(client):
    client.post('/auth/register', json={
        'username': 'dupeuser', 'email': 'a@test.com', 'password': 'Password123!'
    })
    res = client.post('/auth/register', json={
        'username': 'dupeuser', 'email': 'b@test.com', 'password': 'Password123!'
    })
    assert res.status_code == 409


def test_register_short_password(client):
    res = client.post('/auth/register', json={
        'username': 'weakuser', 'email': 'weak@test.com', 'password': '123'
    })
    assert res.status_code == 400


def test_login_success(client):
    client.post('/auth/register', json={
        'username': 'loginuser', 'email': 'login@test.com', 'password': 'Password123!'
    })
    res = client.post('/auth/login', json={
        'username': 'loginuser', 'password': 'Password123!'
    })
    assert res.status_code == 200
    data = json.loads(res.data)
    assert 'access_token' in data


def test_login_wrong_password(client):
    client.post('/auth/register', json={
        'username': 'wrongpass', 'email': 'wp@test.com', 'password': 'Password123!'
    })
    res = client.post('/auth/login', json={
        'username': 'wrongpass', 'password': 'wrongpassword'
    })
    assert res.status_code == 401


def test_protected_route_without_token(client):
    res = client.get('/auth/me')
    assert res.status_code == 401


def test_protected_route_with_token(client):
    token = register_and_login(client)
    res = client.get('/auth/me', headers={'Authorization': f'Bearer {token}'})
    assert res.status_code == 200


# --- RBAC tests ---

def test_viewer_cannot_start_scan(client):
    # Register second user (gets viewer role)
    token = register_and_login(client)  # first = admin
    client.post('/auth/register', json={
        'username': 'viewer1', 'email': 'viewer@test.com', 'password': 'Password123!'
    })
    res2 = client.post('/auth/login', json={'username': 'viewer1', 'password': 'Password123!'})
    viewer_token = json.loads(res2.data)['access_token']

    res = client.post('/scanner/scan',
                      json={'target_url': 'http://testphp.vulnweb.com', 'scan_type': 'passive'},
                      headers={'Authorization': f'Bearer {viewer_token}'})
    assert res.status_code == 403


def test_admin_can_view_audit_logs(client):
    token = register_and_login(client)
    res = client.get('/api/audit-logs', headers={'Authorization': f'Bearer {token}'})
    assert res.status_code == 200


# --- Input validation tests ---

def test_invalid_url_rejected(client):
    token = register_and_login(client)
    res = client.post('/scanner/scan',
                      json={'target_url': 'not-a-url', 'scan_type': 'passive'},
                      headers={'Authorization': f'Bearer {token}'})
    assert res.status_code == 400


def test_missing_target_url(client):
    token = register_and_login(client)
    res = client.post('/scanner/scan',
                      json={'scan_type': 'passive'},
                      headers={'Authorization': f'Bearer {token}'})
    assert res.status_code == 400
