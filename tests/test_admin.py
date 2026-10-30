
from app.database import get_db


def test_admin_can_read_any_record(
    client,
    create_user,
    login_user
):
    create_user("suraj")
    create_user("adminuser")

    # Create a record as Suraj.
    suraj_token = login_user(
        "suraj",
        "SecurePassword@123"
    )

    created = client.post(
        "/records",
        headers={
            "Authorization": f"Bearer {suraj_token}"
        },
        json={
            "title": "Suraj Private Record",
            "body": "Private data"
        }
    )

    record_id = created.json()["record"]["id"]

    # Assign admin role directly in the test database.
    with get_db() as db:
        db.execute(
            """
            UPDATE users
            SET role = ?
            WHERE username = ?
            """,
            ("admin", "adminuser")
        )

    admin_token = login_user(
        "adminuser",
        "SecurePassword@123"
    )

    response = client.get(
        f"/records/{record_id}",
        headers={
            "Authorization": f"Bearer {admin_token}"
        }
    )

    assert response.status_code == 200
    assert response.json()["record"]["title"] == "Suraj Private Record"


def test_user_cannot_register_as_admin(client):
    response = client.post(
        "/register",
        json={
            "username": "attacker",
            "password": "SecurePassword@123",
            "role": "admin"
        }
    )

    assert response.status_code == 422
