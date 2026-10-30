
import hashlib
import time

from app.database import get_db
from app.security import hash_session_token


def test_password_is_not_stored_in_plaintext(
    client,
    create_user
):
    password = "SecurePassword@123"
    create_user("suraj", password)

    with get_db() as db:
        user = db.execute(
            "SELECT password_hash FROM users WHERE username = ?",
            ("suraj",)
        ).fetchone()

    assert user["password_hash"] != password
    assert user["password_hash"].startswith("$argon2id$")


def test_session_token_is_not_stored_directly(
    client,
    create_user,
    login_user
):
    create_user("suraj")

    token = login_user(
        "suraj",
        "SecurePassword@123"
    )

    token_hash = hash_session_token(token)

    with get_db() as db:
        session = db.execute(
            "SELECT token_hash FROM sessions WHERE user_id = 1"
        ).fetchone()

    assert session is not None
    assert session["token_hash"] == token_hash
    assert session["token_hash"] != token


def test_expired_session_is_rejected(
    client,
    create_user,
    login_user
):
    create_user("suraj")

    token = login_user(
        "suraj",
        "SecurePassword@123"
    )

    token_hash = hash_session_token(token)

    with get_db() as db:
        db.execute(
            """
            UPDATE sessions
            SET expires_at = ?
            WHERE token_hash = ?
            """,
            (int(time.time()) - 100, token_hash)
        )

    response = client.get(
        "/me",
        headers={
            "Authorization": f"Bearer {token}"
        }
    )

    assert response.status_code == 401


def test_user_cannot_inject_record_owner(
    client,
    create_user,
    login_user
):
    create_user("suraj")
    create_user("rahul")

    token = login_user(
        "suraj",
        "SecurePassword@123"
    )

    response = client.post(
        "/records",
        headers={
            "Authorization": f"Bearer {token}"
        },
        json={
            "title": "Injected Record",
            "body": "Attempt to change owner",
            "user_id": 2
        }
    )

    assert response.status_code == 422


def test_successful_login_resets_failures(
    client,
    create_user,
    login_user
):
    create_user("suraj")

    for _ in range(3):
        client.post(
            "/login",
            json={
                "username": "suraj",
                "password": "WrongPassword@123"
            }
        )

    login_user(
        "suraj",
        "SecurePassword@123"
    )

    with get_db() as db:
        lock = db.execute(
            """
            SELECT * FROM account_locks
            WHERE username = ?
            """,
            ("suraj",)
        ).fetchone()

    assert lock is None
