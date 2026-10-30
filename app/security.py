
import hashlib
import secrets

from argon2 import PasswordHasher, Type
from argon2.exceptions import (
    VerifyMismatchError,
    VerificationError,
    InvalidHashError
)

# Argon2id password hashing configuration
password_hasher = PasswordHasher(
    time_cost=3,
    memory_cost=65536,  # 64 MiB
    parallelism=4,
    hash_len=32,
    salt_len=16,
    type=Type.ID
)


def hash_password(password: str) -> str:
    """
    Hash a password using Argon2id.

    Argon2 automatically generates a unique random salt
    for every password.
    """

    return password_hasher.hash(password)


def verify_password(password: str, stored_hash: str) -> bool:
    """Verify a password against its stored Argon2 hash."""

    try:
        return password_hasher.verify(stored_hash, password)

    except (
        VerifyMismatchError,
        VerificationError,
        InvalidHashError
    ):
        return False


def password_needs_rehash(stored_hash: str) -> bool:
    """Check whether a password hash needs updated parameters."""

    try:
        return password_hasher.check_needs_rehash(stored_hash)

    except (VerificationError, InvalidHashError):
        return False


def generate_session_token() -> str:
    """
    Generate a cryptographically secure opaque session token.

    32 random bytes provide 256 bits of randomness.
    """

    return secrets.token_urlsafe(32)


def hash_session_token(token: str) -> str:
    """
    Hash the session token before storing it in SQLite.

    SHA-256 is appropriate here because session tokens
    are already cryptographically random, unlike passwords.
    """

    return hashlib.sha256(
        token.encode("utf-8")
    ).hexdigest()
