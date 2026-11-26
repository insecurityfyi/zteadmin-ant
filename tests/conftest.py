import pytest

from app.config import Config
from app.db import Store


@pytest.fixture
def store():
    return Store(":memory:")


@pytest.fixture
def config(tmp_path):
    return Config(data_dir=tmp_path, secret_key=None, password=None, demo=True, sync_minutes=60)
