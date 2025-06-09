from datetime import datetime

from pydantic import BaseModel, constr


class TokenCreate(BaseModel):
    name: constr(max_length=100)  # type: ignore
    expires_at: datetime | None = None


class TokenResponse(BaseModel):
    token: str


class TokenVerify(BaseModel):
    token: str


class TokenRevoke(BaseModel):
    name: str


class TokenRead(BaseModel):
    name: str
    created_at: datetime
    last_used: datetime | None = None
    expires_at: datetime | None = None
