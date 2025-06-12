from datetime import UTC, datetime
from typing import Iterable

from fastapi import Depends
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from ..db import get_session
from ..tables import Token


class TokensDataAccess:
    def __init__(self, session: AsyncSession = Depends(get_session)):
        self.session = session

    async def list_active_tokens(self, username: str) -> Iterable[Token]:
        now = datetime.now(UTC)
        result = await self.session.scalars(
            select(Token).where(
                Token.user == username,
                Token.revoked == False,
                (Token.expires_at.is_(None) | (Token.expires_at > now)),
            )
        )
        return result.all()

    async def get_active_token_by_name(self, username: str, name: str) -> Token | None:
        now = datetime.now(UTC)
        result = await self.session.execute(
            select(Token)
            .where(
                Token.user == username,
                Token.name == name,
                Token.revoked == False,
                (Token.expires_at.is_(None) | (Token.expires_at > now)),
            )
            .limit(1)
        )
        return result.scalar_one_or_none()

    async def create_token(self, token: Token) -> bool:
        self.session.add(token)
        try:
            await self.session.commit()
            return True
        except IntegrityError:
            await self.session.rollback()
            return False

    async def get_active_token_by_prefix(self, prefix: str) -> Token | None:
        now = datetime.now(UTC)
        result = await self.session.execute(
            select(Token)
            .where(
                Token.prefix == prefix,
                Token.revoked == False,
                (Token.expires_at.is_(None) | (Token.expires_at > now)),
            )
            .limit(1)
        )
        return result.scalar_one_or_none()

    async def revoke_token_by_name(self, username: str, name: str) -> bool:
        now = datetime.now(UTC)
        result = await self.session.execute(
            select(Token)
            .where(
                Token.user == username,
                Token.name == name,
                Token.revoked == False,
                (Token.expires_at.is_(None) | (Token.expires_at > now)),
            )
            .limit(1)
        )
        token = result.scalar_one_or_none()
        if not token:
            return False

        token.revoked = True
        await self.session.commit()
        return True

    async def touch_token(self, token: Token) -> None:
        token.last_used = datetime.now(UTC)
        await self.session.commit()
