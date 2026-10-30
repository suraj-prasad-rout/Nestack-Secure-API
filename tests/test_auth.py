
def test_registration_success(client):
    response = client.post(
        "/register",
        json={
            "username": "suraj",
            "password": "SecurePassword@123"
        }
    )

    assert response.status_code == 201
    assert response.json()["user"]["role"] == "user"


def test_duplicate_registration(client):
    data = {
        "username": "suraj",
        "password": "SecurePassword@123"
    }

    client.post("/register", json=data)

    response = client.post("/register", json=data)

    assert response.status_code == 409


def test_successful_login(client, create_user):
    create_user("suraj")

    response = client.post(
        "/login",
        json={
            "username": "suraj",
            "password": "SecurePassword@123"
        }
    )

    assert response.status_code == 200
    assert "access_token" in response.json()


def test_invalid_password(client, create_user):
    create_user("suraj")

    response = client.post(
        "/login",
        json={
            "username": "suraj",
            "password": "WrongPassword@123"
        }
    )

    assert response.status_code == 401


def test_invalid_session(client):
    response = client.get(
        "/me",
        headers={
            "Authorization": "Bearer invalid-session-token"
        }
    )

    assert response.status_code == 401


def test_logout_revokes_session(client, create_user, login_user):
    create_user("suraj")

    token = login_user(
        "suraj",
        "SecurePassword@123"
    )

    headers = {"Authorization": f"Bearer {token}"}

    logout = client.post("/logout", headers=headers)

    assert logout.status_code == 200

    response = client.get("/me", headers=headers)

    assert response.status_code == 401


def test_sql_injection_login_attempt(client):
    response = client.post(
        "/login",
        json={
            "username": "' OR 1=1 --",
            "password": "Anything@123"
        }
    )

    assert response.status_code == 401
