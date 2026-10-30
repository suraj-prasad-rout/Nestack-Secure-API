
def test_create_record(client, create_user, login_user):
    create_user("suraj")

    token = login_user(
        "suraj",
        "SecurePassword@123"
    )

    response = client.post(
        "/records",
        headers={"Authorization": f"Bearer {token}"},
        json={
            "title": "Security Report",
            "body": "This is my private security report."
        }
    )

    assert response.status_code == 201

    record = response.json()["record"]

    assert record["title"] == "Security Report"
    assert record["user_id"] == 1


def test_read_own_record(client, create_user, login_user):
    create_user("suraj")

    token = login_user(
        "suraj",
        "SecurePassword@123"
    )

    headers = {"Authorization": f"Bearer {token}"}

    created = client.post(
        "/records",
        headers=headers,
        json={
            "title": "My Record",
            "body": "Private information"
        }
    )

    record_id = created.json()["record"]["id"]

    response = client.get(
        f"/records/{record_id}",
        headers=headers
    )

    assert response.status_code == 200
    assert response.json()["record"]["title"] == "My Record"


def test_unauthenticated_record_creation(client):
    response = client.post(
        "/records",
        json={
            "title": "Unauthorized",
            "body": "Should not be created"
        }
    )

    assert response.status_code == 401
