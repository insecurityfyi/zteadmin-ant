import pytest
from cryptography.fernet import Fernet

from linkwatch.server.config import Config


@pytest.fixture
def lw_config(tmp_path):
    return Config(database_url=f"sqlite:///{tmp_path}/lw.db", secret_key=Fernet.generate_key().decode(),
                  admin_password="pw-for-tests", public_url="http://testserver", poll_interval=300,
                  raw_days=7, hourly_days=365, background=False)


@pytest.fixture
def app(lw_config):
    from linkwatch.server.app import create_app
    return create_app(lw_config)


@pytest.fixture
def client(app):
    from fastapi.testclient import TestClient
    with TestClient(app) as c:
        yield c


@pytest.fixture
def logged_in(client):
    r = client.post("/login", data={"username": "admin", "password": "pw-for-tests", "next": "/"}, follow_redirects=False)
    assert r.status_code == 303
    return client
