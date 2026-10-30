
def test_registration_rejects_short_password(client):
    response = client.post(
        "/register",
        json={
            "username": "suraj",
            "password": "short"
        }
    )

    assert response.status_code == 422


def test_registration_rejects_extra_fields(client):
    response = client.post(
        "/register",
        json={
            "username": "suraj",
            "password": "SecurePassword@123",
            "role": "admin"
        }
    )

    assert response.status_code == 422


def test_record_rejects_missing_title(client, create_user, login_user):
    create_user("suraj")

    token = login_user(
        "suraj",
        "SecurePassword@123"
    )

    response = client.post(
        "/records",
        headers={"Authorization": f"Bearer {token}"},
        json={
            "body": "Missing title"
        }
    )

    assert response.status_code == 422


def test_record_rejects_oversized_body(
    client,
    create_user,
    login_user
):
    create_user("suraj")

    token = login_user(
        "suraj",
        "SecurePassword@123"
    )

    response = client.post(
        "/records",
        headers={"Authorization": f"Bearer {token}"},
        json={
            "title": "Test",
            "body": "A" * 10001
        }
    )

    assert response.status_code == 422
