
import os
import sqlite3
from pathlib import Path
from contextlib import contextmanager
from dotenv import load_dotenv

# Load environment variables from the project root
BASE_DIR = Path(__file__).resolve().parent.parent
load_dotenv(BASE_DIR / ".env")

DATABASE_PATH = os.getenv(
    "DATABASE_PATH",
    str(BASE_DIR / "nestack.db")
)

# Resolve relative database paths against the project directory
if DATABASE_PATH != ":memory:":
    db_path = Path(DATABASE_PATH)
    if not db_path.is_absolute():
        db_path = BASE_DIR / db_path
    db_path.parent.mkdir(parents=True, exist_ok=True)
    DATABASE_PATH = str(db_path)


@contextmanager
def get_db():
    """Create, use and safely close a database connection."""

    connection = sqlite3.connect(
        DATABASE_PATH,
        timeout=10
    )

    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    connection.execute("PRAGMA busy_timeout = 10000")

    try:
        yield connection
        connection.commit()

    except Exception:
        connection.rollback()
        raise

    finally:
        connection.close()


def init_db():
    """Initialize all application database tables."""

    with get_db() as db:

        db.executescript("""

            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL COLLATE NOCASE UNIQUE,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL DEFAULT 'user'
                    CHECK(role IN ('user', 'admin')),
                created_at INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS records (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                title TEXT NOT NULL,
                body TEXT NOT NULL,
                created_at INTEGER NOT NULL,

                FOREIGN KEY(user_id)
                    REFERENCES users(id)
                    ON DELETE CASCADE
            );

            CREATE INDEX IF NOT EXISTS idx_records_user_id
            ON records(user_id);

            CREATE TABLE IF NOT EXISTS sessions (
                token_hash TEXT PRIMARY KEY,
                user_id INTEGER NOT NULL,
                created_at INTEGER NOT NULL,
                expires_at INTEGER NOT NULL,

                FOREIGN KEY(user_id)
                    REFERENCES users(id)
                    ON DELETE CASCADE
            );

            CREATE INDEX IF NOT EXISTS idx_sessions_user_id
            ON sessions(user_id);

            CREATE INDEX IF NOT EXISTS idx_sessions_expires_at
            ON sessions(expires_at);

            CREATE TABLE IF NOT EXISTS login_attempts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL COLLATE NOCASE,
                attempted_at INTEGER NOT NULL,
                success INTEGER NOT NULL
                    CHECK(success IN (0, 1))
            );

            CREATE INDEX IF NOT EXISTS idx_login_attempts_username
            ON login_attempts(username);

            CREATE TABLE IF NOT EXISTS account_locks (
                username TEXT PRIMARY KEY COLLATE NOCASE,
                failed_attempts INTEGER NOT NULL DEFAULT 0,
                locked_until INTEGER
            );

        """)


def check_database():
    """Verify that the database is accessible."""

    with get_db() as db:
        result = db.execute("SELECT 1").fetchone()
        return result[0] == 1
