
from pydantic import BaseModel, Field, ConfigDict, field_validator


class RegisterRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    username: str = Field(min_length=3, max_length=32)
    password: str = Field(min_length=12, max_length=128)

    @field_validator("username")
    @classmethod
    def validate_username(cls, value):
        if not value.strip():
            raise ValueError("Username cannot be empty")

        if not all(c.isalnum() or c in "_-" for c in value):
            raise ValueError("Invalid username characters")

        return value.strip()


class LoginRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    username: str = Field(min_length=3, max_length=32)
    password: str = Field(min_length=1, max_length=128)


class RecordRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    title: str = Field(min_length=1, max_length=150)
    body: str = Field(min_length=1, max_length=10000)
