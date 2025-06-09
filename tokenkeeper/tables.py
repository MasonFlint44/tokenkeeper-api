from datetime import datetime

from sqlalchemy import Boolean, DateTime, ForeignKey, Index, String, func
from sqlalchemy.orm import Mapped, mapped_column

from .db import Base


class User(Base):
    __tablename__ = "users"
    username: Mapped[str] = mapped_column(String(128), primary_key=True)


class Token(Base):
    __tablename__ = "tokens"
    __table_args__ = (
        Index("ix_token_user_active", "user", "revoked", "expires_at"),
        Index("ix_token_user_name_active", "user", "name", "revoked", "expires_at"),
        Index("ix_token_prefix_active", "prefix", "revoked", "expires_at"),
    )
    prefix: Mapped[str] = mapped_column(String(32), primary_key=True)
    name: Mapped[str] = mapped_column(String(100), nullable=False)
    user: Mapped[str] = mapped_column(
        String(128), ForeignKey("users.username"), nullable=False
    )
    hashed_token: Mapped[str] = mapped_column(String(255), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    last_used: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=True)
    revoked: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=True)
