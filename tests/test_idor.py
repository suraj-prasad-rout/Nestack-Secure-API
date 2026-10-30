
def test_user_cannot_read_another_users_record(
    client,
    create_user,
    login_user
):
    # Create two independent users.
    create_user("suraj")
    create_user("rahul")

    suraj_token = login_user(
        "suraj",
        "SecurePassword@123"
    )

    rahul_token = login_user(
        "rahul",
        "SecurePassword@123"
    )

    # Rahul creates a private record.
    rahul_record = client.post(
        "/records",
        headers={
            "Authorization": f"Bearer {rahul_token}"
        },
        json={
            "title": "Rahul Secret",
            "body": "Confidential information"
        }
    )

    assert rahul_record.status_code == 201

    record_id = rahul_record.json()["record"]["id"]

    # Suraj attempts to access Rahul's record.
    attack = client.get(
        f"/records/{record_id}",
        headers={
            "Authorization": f"Bearer {suraj_token}"
        }
    )

    # Access must be denied.
    assert attack.status_code == 404

    assert attack.json()["detail"] == "Record not found"


def test_nonexistent_record_returns_404(
    client,
    create_user,
    login_user
):
    create_user("suraj")

    token = login_user(
        "suraj",
        "SecurePassword@123"
    )

    response = client.get(
        "/records/99999",
        headers={
            "Authorization": f"Bearer {token}"
        }
    )

    assert response.status_code == 404
