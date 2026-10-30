from fastapi.security import HTTPBearer
import secrets
import sqlite3
import time

from fastapi import APIRouter, Depends, HTTPException, Header, status
from pydantic import BaseModel, Field, ConfigDict

from app.database import get_db
from app.security import (
    hash_password,
    verify_password,
    generate_session_token,
    hash_session_token,
)


router = APIRouter()
bearer_scheme = HTTPBearer(auto_error=False)
# Security configuration
MAX_LOGIN_FAILURES = 5
LOCKOUT_MINUTES = 15
SESSION_TTL_HOURS = 24

SESSION_TTL_SECONDS = SESSION_TTL_HOURS * 60 * 60
LOCKOUT_SECONDS = LOCKOUT_MINUTES * 60

# Used to reduce timing differences for unknown usernames.
_DUMMY_PASSWORD_HASH = hash_password(secrets.token_urlsafe(32))


# --------------------------------------------------
# REQUEST MODELS
# --------------------------------------------------

class RegisterRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    username: str = Field(min_length=3, max_length=50)
    password: str = Field(min_length=8, max_length=128)


class LoginRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    username: str = Field(min_length=3, max_length=50)
    password: str = Field(min_length=1, max_length=128)


# --------------------------------------------------
# REGISTRATION
# --------------------------------------------------

@router.post("/register", status_code=status.HTTP_201_CREATED)
def register_user(username: str, password: str):

    username = username.strip()

    if not username:
        raise HTTPException(
            status_code=400,
            detail="Username cannot be empty"
        )

    password_hash = hash_password(password)
    current_time = int(time.time())

    try:
        with get_db() as db:
            cursor = db.execute(
                """
                INSERT INTO users (
                    username,
                    password_hash,
                    role,
                    created_at
                )
                VALUES (?, ?, 'user', ?)
                """,
                (username, password_hash, current_time)
            )

            user_id = cursor.lastrowid

    except sqlite3.IntegrityError:
        raise HTTPException(
            status_code=409,
            detail="Username already exists"
        )

    return {
        "id": user_id,
        "username": username,
        "role": "user"
    }


# --------------------------------------------------
# LOGIN
# --------------------------------------------------

@router.post("/login")
def authenticate_user(username: str, password: str):

    username = username.strip()
    current_time = int(time.time())

    if not username:
        raise HTTPException(
            status_code=401,
            detail="Invalid username or password"
        )

    error_status = None
    error_message = None
    result = None

    with get_db() as db:

        lock = db.execute(
            """
            SELECT failed_attempts, locked_until
            FROM account_locks
            WHERE username = ?
            """,
            (username,)
        ).fetchone()

        if lock and lock["locked_until"] is not None:

            if lock["locked_until"] > current_time:
                error_status = 429
                error_message = "Account temporarily locked"

            else:
                db.execute(
                    """
                    UPDATE account_locks
                    SET failed_attempts = 0,
                        locked_until = NULL
                    WHERE username = ?
                    """,
                    (username,)
                )

        if error_status is None:

            user = db.execute(
                """
                SELECT id, username, password_hash, role
                FROM users
                WHERE username = ?
                """,
                (username,)
            ).fetchone()

            stored_hash = (
                user["password_hash"]
                if user
                else _DUMMY_PASSWORD_HASH
            )

            password_valid = verify_password(
                password,
                stored_hash
            )

            if not user or not password_valid:

                db.execute(
                    """
                    INSERT INTO login_attempts (
                        username,
                        attempted_at,
                        success
                    )
                    VALUES (?, ?, 0)
                    """,
                    (username, current_time)
                )

                db.execute(
                    """
                    INSERT INTO account_locks (
                        username,
                        failed_attempts,
                        locked_until
                    )
                    VALUES (?, 1, NULL)
                    ON CONFLICT(username)
                    DO UPDATE SET
                        failed_attempts =
                            account_locks.failed_attempts + 1
                    """,
                    (username,)
                )

                updated_lock = db.execute(
                    """
                    SELECT failed_attempts
                    FROM account_locks
                    WHERE username = ?
                    """,
                    (username,)
                ).fetchone()

                if updated_lock["failed_attempts"] >= MAX_LOGIN_FAILURES:

                    locked_until = current_time + LOCKOUT_SECONDS

                    db.execute(
                        """
                        UPDATE account_locks
                        SET locked_until = ?
                        WHERE username = ?
                        """,
                        (locked_until, username)
                    )

                    error_status = 429
                    error_message = "Account temporarily locked"

                else:
                    error_status = 401
                    error_message = "Invalid username or password"

            else:

                db.execute(
                    """
                    INSERT INTO login_attempts (
                        username,
                        attempted_at,
                        success
                    )
                    VALUES (?, ?, 1)
                    """,
                    (username, current_time)
                )

                db.execute(
                    """
                    DELETE FROM account_locks
                    WHERE username = ?
                    """,
                    (username,)
                )

                session_token = generate_session_token()
                token_hash = hash_session_token(session_token)

                expires_at = current_time + SESSION_TTL_SECONDS

                db.execute(
                    """
                    INSERT INTO sessions (
                        token_hash,
                        user_id,
                        created_at,
                        expires_at
                    )
                    VALUES (?, ?, ?, ?)
                    """,
                    (
                        token_hash,
                        user["id"],
                        current_time,
                        expires_at
                    )
                )

                result = {
                    "message": "Login successful",
                    "access_token": session_token,
                    "token_type": "bearer",
                    "expires_in": SESSION_TTL_SECONDS,
                    "user": {
                        "id": user["id"],
                        "username": user["username"],
                        "role": user["role"]
                    }
                }

    if error_status is not None:
        raise HTTPException(
            status_code=error_status,
            detail=error_message
        )

    return result


# --------------------------------------------------
# AUTHENTICATION DEPENDENCY
# --------------------------------------------------

def get_current_user(
    authorization: str = Header(default=None)
):

    if not authorization:
        raise HTTPException(
            status_code=401,
            detail="Authentication required"
        )

    parts = authorization.split()

    if len(parts) != 2 or parts[0].lower() != "bearer":
        raise HTTPException(
            status_code=401,
            detail="Invalid authorization header"
        )

    session_token = parts[1]

    token_hash = hash_session_token(session_token)
    current_time = int(time.time())

    with get_db() as db:

        session = db.execute(
            """
            SELECT
                users.id,
                users.username,
                users.role,
                sessions.expires_at
            FROM sessions
            JOIN users
                ON users.id = sessions.user_id
            WHERE sessions.token_hash = ?
            """,
            (token_hash,)
        ).fetchone()

        if not session:
            raise HTTPException(
                status_code=401,
                detail="Invalid session"
            )

        if session["expires_at"] <= current_time:

            db.execute(
                """
                DELETE FROM sessions
                WHERE token_hash = ?
                """,
                (token_hash,)
            )

            raise HTTPException(
                status_code=401,
                detail="Session expired"
            )

        return {
            "id": session["id"],
            "username": session["username"],
            "role": session["role"]
        }


# --------------------------------------------------
# CURRENT USER
# --------------------------------------------------

@router.get("/me")
def get_me(
    current_user: dict = Depends(get_current_user)
):

    return {
        "user": current_user
    }


# --------------------------------------------------
# LOGOUT
# --------------------------------------------------

@router.post("/logout")
def logout_user(
    authorization: str = Header(default=None)
):

    if not authorization:
        raise HTTPException(
            status_code=401,
            detail="Authentication required"
        )

    parts = authorization.split()

    if len(parts) != 2 or parts[0].lower() != "bearer":
        raise HTTPException(
            status_code=401,
            detail="Invalid authorization header"
        )

    session_token = parts[1]
    token_hash = hash_session_token(session_token)

    with get_db() as db:

        session = db.execute(
            """
            SELECT token_hash
            FROM sessions
            WHERE token_hash = ?
            """,
            (token_hash,)
        ).fetchone()

        if not session:
            raise HTTPException(
                status_code=401,
                detail="Invalid session"
            )

        db.execute(
            """
            DELETE FROM sessions
            WHERE token_hash = ?
            """,
            (token_hash,)
        )

    return {
        "message": "Logged out successfully"
    }


def revoke_session(credentials):

    if credentials is None:
        raise HTTPException(
            status_code=401,
            detail="Authentication required"
        )

    token_hash = hash_session_token(credentials.credentials)

    with get_db() as db:
        cursor = db.execute(
            """
            DELETE FROM sessions
            WHERE token_hash = ?
            """,
            (token_hash,)
        )

        if cursor.rowcount == 0:
            raise HTTPException(
                status_code=401,
                detail="Invalid session"
            )

    return {
        "message": "Logged out successfully"
    }
