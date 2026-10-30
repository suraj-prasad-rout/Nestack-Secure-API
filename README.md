# Nestack — Secure Records API

**Technical Assessment: Cybersecurity Intern / Engineer**

A secure, multi-tenant Records API built using Python, FastAPI and SQLite. The application implements custom authentication, server-side session management, role-based authorization and object-level access control.

## 1. Technology Stack

- Python 3.14
- FastAPI
- SQLite
- Argon2id (`argon2-cffi`)
- Pydantic
- Pytest
- HTTPX

## 2. Features

- User registration and login.
- Argon2id password hashing with unique salts.
- Cryptographically secure opaque session tokens.
- SHA-256 hashing of session tokens before database storage.
- Server-side session verification on protected requests.
- Session expiration and revocation.
- User-owned record creation and retrieval.
- Admin access to records across users.
- Object-level authorization to prevent IDOR.
- Input validation and length restrictions.
- Parameterized SQL queries.
- Account-level failed-login tracking and temporary lockout.

## 3. Project Structure

```text
Nestack_Submission/
│
├── app/
│   ├── __init__.py
│   ├── main.py
│   ├── database.py
│   ├── auth.py
│   ├── security.py
│   ├── records.py
│   └── validators.py
│
├── tests/
│   ├── conftest.py
│   ├── test_auth.py
│   ├── test_records.py
│   ├── test_idor.py
│   ├── test_admin.py
│   ├── test_lockout.py
│   ├── test_validation.py
│   └── test_security_hardening.py
│
├── .env.example
├── .gitignore
├── requirements.txt
└── README.md
```

## 4. Installation and Execution

### Prerequisites

- Python 3.12 or newer.
- pip.
- Windows, Linux or macOS.

### Clone the repository

```bash
git clone <YOUR_PRIVATE_REPOSITORY_URL>
cd Nestack_Submission
```

### Create a virtual environment

Windows PowerShell:

```powershell
python -m venv venv
.\venv\Scripts\Activate.ps1
```

### Install dependencies

```bash
pip install -r requirements.txt
```

### Configure environment variables

Create a `.env` file in the project root:

```env
APP_ENV=development
DATABASE_PATH=./nestack.db
SESSION_TTL_HOURS=12
LOCKOUT_MINUTES=15
MAX_LOGIN_FAILURES=5
```

### Start the API

```bash
python -m uvicorn app.main:app --reload
```

API address:

```text
http://127.0.0.1:8000
```

Interactive API documentation:

```text
http://127.0.0.1:8000/docs
```

## 5. API Endpoints

| Method | Endpoint               | Description                   |
| ------ | ---------------------- | ----------------------------- |
| GET    | `/`                    | API information               |
| GET    | `/health`              | Health check                  |
| POST   | `/register`            | Register a user               |
| POST   | `/login`               | Authenticate a user           |
| GET    | `/me`                  | Verify current session        |
| POST   | `/logout`              | Revoke current session        |
| POST   | `/records`             | Create a record               |
| GET    | `/records/{record_id}` | Retrieve an authorized record |

### Registration example

```json
{
	"username": "suraj",
	"password": "SecurePassword@123"
}
```

### Login example

```json
{
	"username": "suraj",
	"password": "SecurePassword@123"
}
```

Successful login returns an opaque bearer token. Include it in the Authorization header for protected endpoints.

```text
Authorization: Bearer <SESSION_TOKEN>
```

### Record creation example

```json
{
	"title": "Security Report",
	"body": "Confidential security assessment."
}
```

## 6. Security Architecture and Threat Model

### 6.1 Password Storage

Passwords are hashed using Argon2id, a memory-hard password hashing algorithm.

Configuration:

- Time cost: 3
- Memory cost: 65536 KiB
- Parallelism: 4
- Hash length: 32 bytes
- Salt length: 16 bytes

A unique random salt is automatically generated for every password.

Passwords are never stored in plaintext.

**Why Argon2id?**

Argon2id makes offline password guessing more expensive by requiring significant memory and computational resources. Its unique salts also prevent identical passwords from producing identical stored hashes.

### 6.2 Session Management

The application uses opaque, server-side sessions instead of JWTs.

Session creation:

1. Generate a cryptographically random token using Python's `secrets` module.
2. Hash the token using SHA-256.
3. Store only the hash in the sessions table.
4. Return the original token to the authenticated client.

On each protected request:

1. Extract the bearer token.
2. Calculate its SHA-256 hash.
3. Search the sessions table for the hash.
4. Verify session expiration.
5. Retrieve the associated user and role.
6. Permit access only after successful verification.

Sessions can also be revoked by deleting their database entries.

### 6.3 Broken Access Control and IDOR Prevention

Every record belongs to a specific user through its `user_id` field.

Record retrieval applies an ownership condition directly in the SQL query:

```sql
SELECT id, user_id, title, body, created_at
FROM records
WHERE id = ?
AND (
    user_id = ?
    OR ? = 'admin'
);
```

The authenticated user ID and role come from the verified server-side session.

A normal user cannot retrieve another user's record, even if they discover or guess its record ID.

Unauthorized and nonexistent records both return HTTP 404.

### 6.4 Privilege Escalation Prevention

New accounts always receive the `user` role from server-side registration logic.

The registration model rejects unexpected fields using Pydantic's `extra="forbid"` configuration.

The application does not provide a public endpoint for changing user roles.

Admin privileges must be assigned through a trusted server-side administrative process.

### 6.5 SQL Injection Prevention

Database operations use parameterized SQLite queries.

Example:

```python
db.execute(
    "SELECT * FROM users WHERE username = ?",
    (username,)
)
```

Untrusted input is passed as a parameter rather than concatenated into SQL statements.

### 6.6 Input Validation

Pydantic validates incoming requests.

Implemented restrictions include:

- Username: 3–32 characters.
- Password: 12–128 characters for registration.
- Record title: 1–150 characters.
- Record body: 1–10,000 characters.
- Unexpected request fields are rejected.

Invalid requests receive HTTP 422 from FastAPI/Pydantic validation.

### 6.7 Brute-Force Protection

Failed login attempts are tracked by account username.

The application:

- Records unsuccessful login attempts.
- Applies a temporary lock after five consecutive failures.
- Uses a 15-minute lockout period.
- Returns HTTP 429 during an active lockout.
- Resets the failure counter after successful authentication.

## 7. Database Leak Threat Analysis

If an attacker obtains a copy of the users table:

**What the attacker could obtain:**

- User IDs.
- Usernames.
- Argon2id password hashes.
- Assigned roles.
- Account creation timestamps.

**What the attacker could not directly obtain:**

- Plaintext passwords.
- Original passwords from the stored hashes without successfully guessing them.
- Original session tokens from their SHA-256 hashes.

Argon2id makes offline password cracking more expensive, but weak passwords may still be guessed. SHA-256 session hashes protect stored bearer tokens because the original tokens are generated with high cryptographic randomness.

A database leak may also expose records, metadata and other stored application information if those tables are included in the stolen database. Password hashing does not encrypt the records themselves.

Therefore, database access restrictions, backups, encryption at rest and incident response remain important security controls.

## 8. Automated Security Testing

Run the test suite:

```bash
python -m pytest -v
```

The current development test suite contains 24 automated tests.

Tested security properties include:

- Registration and duplicate-account rejection.
- Password verification.
- Invalid session rejection.
- Session revocation.
- Session expiration.
- Record creation and retrieval.
- IDOR prevention.
- Admin authorization.
- Privilege escalation prevention.
- Brute-force account lockout.
- SQL injection resistance.
- Input validation.
- Password hash storage.
- Session token hash storage.
- Record ownership enforcement.

**Latest development test result: 24 passed.**

## 9. Configuration and Deployment Notes

- Environment variables are used for application configuration.
- `.env` must not be committed.
- Local SQLite databases must not be committed.
- Production deployments should use HTTPS.
- Production secrets must be securely managed.
- Database files must have restricted filesystem permissions.
- Administrative privileges must be provisioned through a trusted process.
- Production deployment requires additional concurrency, rate-limiting and operational security review.

## 10. Security Scope and Limitations

This project is a technical assessment implementation, not a fully audited production authentication platform.

The current implementation demonstrates password hashing, server-side sessions, role-based access control and record ownership checks. Additional production work should include robust concurrent login-lockout handling, account recovery, monitoring, deployment hardening and secure administrator provisioning.

## 11. Author

**Project:** Nestack Secure Records API  
**Language:** Python  
**Framework:** FastAPI  
**Database:** SQLite  
**Security:** Argon2id, SHA-256 session hashing, RBAC and IDOR prevention

Developed as part of the Nestack Cybersecurity Technical Assessment.
