
import time

from fastapi import HTTPException

from app.database import get_db


def create_record(user_id: int, title: str, body: str):
    """
    Create a record belonging to the authenticated user.

    user_id comes from the verified server-side session,
    never from the request body.
    """

    current_time = int(time.time())

    with get_db() as db:

        cursor = db.execute(
            """
            INSERT INTO records
            (user_id, title, body, created_at)
            VALUES (?, ?, ?, ?)
            """,
            (user_id, title, body, current_time)
        )

        record_id = cursor.lastrowid

        record = db.execute(
            """
            SELECT id, user_id, title, body, created_at
            FROM records
            WHERE id = ?
            """,
            (record_id,)
        ).fetchone()

        return dict(record)


def get_record(record_id: int, current_user: dict):
    """
    Retrieve a record only if:
    1. The authenticated user owns it, OR
    2. The authenticated user has the admin role.

    Unauthorized and nonexistent records both return 404.
    """

    with get_db() as db:

        record = db.execute(
            """
            SELECT id, user_id, title, body, created_at
            FROM records
            WHERE id = ?
              AND (
                  user_id = ?
                  OR ? = 'admin'
              )
            """,
            (
                record_id,
                current_user["id"],
                current_user["role"]
            )
        ).fetchone()

        if record is None:
            raise HTTPException(
                status_code=404,
                detail="Record not found"
            )

        return dict(record)
