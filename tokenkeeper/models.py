from datetime import datetime

from pydantic import BaseModel, constr


class TokenCreate(BaseModel):
    name: constr(max_length=100)  # type: ignore
    expires_at: datetime | None = None


class TokenResponse(BaseModel):
    token: str


class TokenRevoke(BaseModel):
    name: str


class TokenRead(BaseModel):
    name: str
    created_at: datetime
    last_used: datetime | None = None
    expires_at: datetime | None = None


class VerifyResponse(BaseModel):
    valid: bool
    user: str


class RevokeResponse(BaseModel):
    revoked: bool


class ReadyResponse(BaseModel):
    status: str


class HealthResponse(BaseModel):
    status: str
