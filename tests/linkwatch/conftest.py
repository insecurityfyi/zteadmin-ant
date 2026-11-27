import socket
import threading
import time

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
    from linkwatch.server import api
    from linkwatch.server.app import create_app
    api._enroll_attempts.clear()      # the per-IP enrollment limit is process-wide; every test starts fresh
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


@pytest.fixture
def live_server(app):
    """The app served by uvicorn on a free local port, for tests that need real WebSockets end to end."""
    import uvicorn
    with socket.socket() as sk:
        sk.bind(("127.0.0.1", 0))
        port = sk.getsockname()[1]
    server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning"))
    th = threading.Thread(target=server.run, daemon=True)
    th.start()
    for _ in range(100):
        if server.started:
            break
        time.sleep(0.05)
    yield f"http://127.0.0.1:{port}"
    server.should_exit = True
    th.join(5)
