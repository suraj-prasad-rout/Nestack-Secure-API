
import pytest

from fastapi.testclient import TestClient

from app import database
from app.main import app


@pytest.fixture
def client(tmp_path, monkeypatch):
    """
    Create an isolated SQLite database for every test.
    """

    test_db = tmp_path / "test_nestack.db"

    monkeypatch.setattr(
        database,
        "DATABASE_PATH",
        str(test_db)
    )

    with TestClient(app) as test_client:
        yield test_client


@pytest.fixture
def create_user(client):
    """Register a test user and return credentials."""

    def _create_user(username, password="SecurePassword@123"):
        response = client.post(
            "/register",
            json={
                "username": username,
                "password": password
            }
        )

        assert response.status_code == 201

        return {
            "username": username,
            "password": password
        }

    return _create_user


@pytest.fixture
def login_user(client):
    """Authenticate a user and return the session token."""

    def _login(username, password):
        response = client.post(
            "/login",
            json={
                "username": username,
                "password": password
            }
        )

        assert response.status_code == 200

        return response.json()["access_token"]

    return _login
