
import time

from app.database import get_db


def test_expired_lockout_allows_fresh_attempts(
    client,
    create_user
):
    create_user("suraj")

    # Simulate five failed attempts.
    for _ in range(5):
        response = client.post(
            "/login",
            json={
                "username": "suraj",
                "password": "WrongPassword@123"
            }
        )

    assert response.status_code == 429

    # Simulate expiration of the 15-minute lock.
    with get_db() as db:
        db.execute(
            """
            UPDATE account_locks
            SET locked_until = ?
            WHERE username = ?
            """,
            (int(time.time()) - 1, "suraj")
        )

    # First new failed attempt should return 401.
    response = client.post(
        "/login",
        json={
            "username": "suraj",
            "password": "WrongPassword@123"
        }
    )

    assert response.status_code == 401
