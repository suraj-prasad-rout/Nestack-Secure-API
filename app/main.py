from app.records import create_record, get_record
from app.validators import RecordRequest
from contextlib import asynccontextmanager

from fastapi import FastAPI, Depends
from fastapi.responses import JSONResponse

from app.database import init_db
from app.auth import (
    register_user,
    authenticate_user,
    get_current_user,
    revoke_session,
    bearer_scheme
)
from app.validators import RegisterRequest, LoginRequest


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    yield


app = FastAPI(
    title="Nestack Secure Records API",
    description="Secure multi-tenant records management API",
    version="1.0.0",
    lifespan=lifespan
)


@app.get("/")
def root():
    return {
        "message": "Nestack Secure Records API is running",
        "status": "healthy"
    }


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/register", status_code=201)
def register(data: RegisterRequest):

    user = register_user(
        username=data.username,
        password=data.password
    )

    return {
        "message": "Account registered successfully",
        "user": user
    }


@app.post("/login")
def login(data: LoginRequest):

    return authenticate_user(
        username=data.username,
        password=data.password
    )


@app.get("/me")
def get_profile(
    current_user: dict = Depends(get_current_user)
):
    return {
        "message": "Authentication successful",
        "user": current_user
    }


@app.post("/logout")
def logout(
    credentials=Depends(bearer_scheme)
):

    result = revoke_session(credentials)

    return result


@app.post("/records", status_code=201)
def create_new_record(
    data: RecordRequest,
    current_user: dict = Depends(get_current_user)
):
    record = create_record(
        user_id=current_user["id"],
        title=data.title,
        body=data.body
    )

    return {
        "message": "Record created successfully",
        "record": record
    }


@app.get("/records/{record_id}")
def read_record(
    record_id: int,
    current_user: dict = Depends(get_current_user)
):
    if record_id <= 0:
        from fastapi import HTTPException
        raise HTTPException(
            status_code=400,
            detail="Invalid record ID"
        )

    record = get_record(
        record_id=record_id,
        current_user=current_user
    )

    return {
        "record": record
    }
